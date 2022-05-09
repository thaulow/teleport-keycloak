/*
Copyright 2021-2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/tool/tbot/config"
	"github.com/gravitational/teleport/tool/tbot/identity"
	"github.com/gravitational/trace"
	"github.com/kr/pretty"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentTBot,
})

const (
	authServerEnvVar = "TELEPORT_AUTH_SERVER"
	tokenEnvVar      = "TELEPORT_BOT_TOKEN"
)

func main() {
	if err := Run(os.Args[1:]); err != nil {
		utils.FatalError(err)
		trace.DebugReport(err)
	}
}

func Run(args []string) error {
	var cf config.CLIConf
	utils.InitLogger(utils.LoggingForDaemon, logrus.InfoLevel)

	app := utils.InitCLIParser("tbot", "tbot: Teleport Machine ID").Interspersed(false)
	app.Flag("debug", "Verbose logging to stdout").Short('d').BoolVar(&cf.Debug)
	app.Flag("config", "Path to a configuration file. Defaults to `/etc/tbot.yaml` if unspecified.").Short('c').StringVar(&cf.ConfigPath)
	app.HelpFlag.Short('h')

	versionCmd := app.Command("version", "Print the version")

	startCmd := app.Command("start", "Starts the renewal bot, writing certificates to the data dir at a set interval.")
	startCmd.Flag("auth-server", "Address of the Teleport Auth Server (On-Prem installs) or Proxy Server (Cloud installs).").Short('a').Envar(authServerEnvVar).StringVar(&cf.AuthServer)
	startCmd.Flag("token", "A bot join token, if attempting to onboard a new bot; used on first connect.").Envar(tokenEnvVar).StringVar(&cf.Token)
	startCmd.Flag("ca-pin", "CA pin to validate the Teleport Auth Server; used on first connect.").StringsVar(&cf.CAPins)
	startCmd.Flag("data-dir", "Directory to store internal bot data. Access to this directory should be limited.").StringVar(&cf.DataDir)
	startCmd.Flag("destination-dir", "Directory to write short-lived machine certificates.").StringVar(&cf.DestinationDir)
	startCmd.Flag("certificate-ttl", "TTL of short-lived machine certificates.").Default("60m").DurationVar(&cf.CertificateTTL)
	startCmd.Flag("renewal-interval", "Interval at which short-lived certificates are renewed; must be less than the certificate TTL.").DurationVar(&cf.RenewalInterval)
	startCmd.Flag("join-method", "Method to use to join the cluster, can be \"token\" or \"iam\".").Default(config.DefaultJoinMethod).EnumVar(&cf.JoinMethod, "token", "iam")
	startCmd.Flag("oneshot", "If set, quit after the first renewal.").BoolVar(&cf.Oneshot)

	initCmd := app.Command("init", "Initialize a certificate destination directory for writes from a separate bot user.")
	initCmd.Flag("destination-dir", "Directory to write short-lived machine certificates to.").StringVar(&cf.DestinationDir)
	initCmd.Flag("owner", "Defines Linux \"user:group\" owner of \"--destination-dir\". Defaults to the Linux user running tbot if unspecified.").StringVar(&cf.Owner)
	initCmd.Flag("bot-user", "Enables POSIX ACLs and defines Linux user that can read/write short-lived certificates to \"--destination-dir\".").StringVar(&cf.BotUser)
	initCmd.Flag("reader-user", "Enables POSIX ACLs and defines Linux user that will read short-lived certificates from \"--destination-dir\".").StringVar(&cf.ReaderUser)
	initCmd.Flag("init-dir", "If using a config file and multiple destinations are configured, controls which destination dir to configure.").StringVar(&cf.InitDir)
	initCmd.Flag("clean", "If set, remove unexpected files and directories from the destination.").BoolVar(&cf.Clean)

	configCmd := app.Command("config", "Parse and dump a config file").Hidden()

	watchCmd := app.Command("watch", "Watch a destination directory for changes.").Hidden()

	utils.UpdateAppUsageTemplate(app, args)
	command, err := app.Parse(args)
	if err != nil {
		app.Usage(args)
		return trace.Wrap(err)
	}

	// While in debug mode, send logs to stdout.
	if cf.Debug {
		utils.InitLogger(utils.LoggingForDaemon, logrus.DebugLevel)
	}

	botConfig, err := config.FromCLIConf(&cf)
	if err != nil {
		return trace.Wrap(err)
	}

	switch command {
	case versionCmd.FullCommand():
		err = onVersion()
	case startCmd.FullCommand():
		err = onStart(botConfig)
	case configCmd.FullCommand():
		err = onConfig(botConfig)
	case initCmd.FullCommand():
		err = onInit(botConfig, &cf)
	case watchCmd.FullCommand():
		err = onWatch(botConfig)
	default:
		// This should only happen when there's a missing switch case above.
		err = trace.BadParameter("command %q not configured", command)
	}

	return err
}

func onVersion() error {
	utils.PrintVersion()
	return nil
}

func onConfig(botConfig *config.BotConfig) error {
	pretty.Println(botConfig)

	return nil
}

func onWatch(botConfig *config.BotConfig) error {
	return trace.NotImplemented("watch not yet implemented")
}

func onStart(botConfig *config.BotConfig) error {
	if botConfig.AuthServer == "" {
		return trace.BadParameter("an auth or proxy server must be set via --auth-server or configuration")
	}

	// First, try to make sure all destinations are usable.
	if err := checkDestinations(botConfig); err != nil {
		return trace.Wrap(err)
	}

	// Start by loading the bot's primary destination.
	dest, err := botConfig.Storage.GetDestination()
	if err != nil {
		return trace.Wrap(err, "could not read bot storage destination from config")
	}

	reloadChan := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go handleSignals(reloadChan, cancel)

	configTokenHashBytes := []byte{}
	if botConfig.Onboarding != nil && botConfig.Onboarding.Token != "" {
		sha := sha256.Sum256([]byte(botConfig.Onboarding.Token))
		configTokenHashBytes = []byte(hex.EncodeToString(sha[:]))
	}

	var authClient auth.ClientI

	// First, attempt to load an identity from storage.
	ident, err := identity.LoadIdentity(dest, identity.BotKinds()...)
	if err == nil && !hasTokenChanged(ident.TokenHashBytes, configTokenHashBytes) {
		identStr, err := describeTLSIdentity(ident)
		if err != nil {
			return trace.Wrap(err)
		}

		log.Infof("Successfully loaded bot identity, %s", identStr)

		if err := checkIdentity(ident); err != nil {
			return trace.Wrap(err)
		}

		if botConfig.Onboarding != nil {
			log.Warn("Note: onboarding config ignored as identity was loaded from persistent storage")
		}

		authClient, err = authenticatedUserClientFromIdentity(ctx, ident, botConfig.AuthServer)
		if err != nil {
			return trace.Wrap(err)
		}
	} else {
		// If the identity can't be loaded, assume we're starting fresh and
		// need to generate our initial identity from a token

		if ident != nil {
			// If ident is set here, we detected a token change above.
			log.Warnf("Detected a token change, will attempt to fetch a new identity.")
		} else if trace.IsNotFound(err) {
			// This is _probably_ a fresh start, so we'll log the true error
			// and try to fetch a fresh identity.
			log.Debugf("Identity %s is not found or empty and could not be loaded, will start from scratch: %+v", dest, err)
		} else {
			return trace.Wrap(err)
		}

		// Verify we can write to the destination.
		if err := identity.VerifyWrite(dest); err != nil {
			return trace.Wrap(err, "Could not write to destination %s, aborting.", dest)
		}

		// Get first identity
		ident, err = getIdentityFromToken(botConfig)
		if err != nil {
			return trace.Wrap(err)
		}

		log.Debug("Attempting first connection using initial auth client")
		authClient, err = authenticatedUserClientFromIdentity(ctx, ident, botConfig.AuthServer)
		if err != nil {
			return trace.Wrap(err)
		}

		// Attempt a request to make sure our client works.
		if _, err := authClient.Ping(ctx); err != nil {
			return trace.Wrap(err, "unable to communicate with auth server")
		}

		identStr, err := describeTLSIdentity(ident)
		if err != nil {
			return trace.Wrap(err)
		}
		log.Infof("Successfully generated new bot identity, %s", identStr)

		log.Debugf("Storing new bot identity to %s", dest)
		if err := identity.SaveIdentity(ident, dest, identity.BotKinds()...); err != nil {
			return trace.Wrap(err, "unable to save generated identity back to destination")
		}
	}

	watcher, err := authClient.NewWatcher(ctx, types.Watch{
		Kinds: []types.WatchKind{{
			Kind: types.KindCertAuthority,
		}},
	})
	if err != nil {
		return trace.Wrap(err)
	}

	go watchCARotations(watcher)

	defer watcher.Close()

	return renewLoop(ctx, botConfig, authClient, ident, reloadChan)
}

func hasTokenChanged(configTokenBytes, identityBytes []byte) bool {
	if len(configTokenBytes) == 0 || len(identityBytes) == 0 {
		return false
	}

	return !bytes.Equal(identityBytes, configTokenBytes)
}

// checkDestinations checks all destinations and tries to create any that
// don't already exist.
func checkDestinations(cfg *config.BotConfig) error {
	// Note: This is vaguely problematic as we don't recommend that users
	// store renewable certs under the same user as end-user certs. That said,
	//  - if the destination was properly created via tbot init this is a no-op
	//  - if users intend to follow that advice but miss a step, it should fail
	//    due to lack of permissions
	storage, err := cfg.Storage.GetDestination()
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO: consider warning if ownership of all destintions is not expected.

	// Note: no subdirs to init for bot's internal storage.
	if err := storage.Init([]string{}); err != nil {
		return trace.Wrap(err)
	}

	for _, dest := range cfg.Destinations {
		destImpl, err := dest.GetDestination()
		if err != nil {
			return trace.Wrap(err)
		}

		subdirs, err := dest.ListSubdirectories()
		if err != nil {
			return trace.Wrap(err)
		}

		if err := destImpl.Init(subdirs); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// checkIdentity performs basic startup checks on an identity and loudly warns
// end users if it is unlikely to work.
func checkIdentity(ident *identity.Identity) error {
	var validAfter time.Time
	var validBefore time.Time

	if ident.X509Cert != nil {
		validAfter = ident.X509Cert.NotBefore
		validBefore = ident.X509Cert.NotAfter
	} else if ident.SSHCert != nil {
		validAfter = time.Unix(int64(ident.SSHCert.ValidAfter), 0)
		validBefore = time.Unix(int64(ident.SSHCert.ValidBefore), 0)
	} else {
		return trace.BadParameter("identity is invalid and contains no certificates")
	}

	now := time.Now().UTC()
	if now.After(validBefore) {
		log.Errorf(
			"Identity has expired. The renewal is likely to fail. (expires: %s, current time: %s)",
			validBefore.Format(time.RFC3339),
			now.Format(time.RFC3339),
		)
	} else if now.Before(validAfter) {
		log.Warnf(
			"Identity is not yet valid. Confirm that the system time is correct. (valid after: %s, current time: %s)",
			validAfter.Format(time.RFC3339),
			now.Format(time.RFC3339),
		)
	}

	return nil
}

// handleSignals handles incoming Unix signals.
func handleSignals(reload chan struct{}, cancel context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1)

	for signal := range signals {
		switch signal {
		case syscall.SIGINT:
			log.Info("Received interrupt, cancelling...")
			cancel()
			return
		case syscall.SIGHUP, syscall.SIGUSR1:
			log.Info("Received reload signal, reloading...")
			reload <- struct{}{}
		}
	}
}

func watchCARotations(watcher types.Watcher) {
	for {
		select {
		case event := <-watcher.Events():
			log.Debugf("CA event: %+v", event)
			// TODO: handle CA rotations
		case <-watcher.Done():
			if err := watcher.Error(); err != nil {
				log.WithError(err).Warnf("error watching for CA rotations")
			}
			return
		}
	}
}
