/*
Copyright 2021 Gravitational, Inc.

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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/utils/keypaths"
	libclient "github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/db/dbcmd"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	alpncommon "github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/utils"
)

// onProxyCommandSSH creates a local ssh proxy.
// In cases of TLS Routing the connection is established to the WebProxy with teleport-proxy-ssh ALPN protocol.
// and all ssh traffic is forwarded through the local ssh proxy.
//
// If proxy doesn't support TLS Routing the onProxyCommandSSH is used as ProxyCommand to remove proxy/site prefixes
// from destination node address to support multiple platform where 'cut -d' command is not provided.
// For more details please look at: Generate Windows-compatible OpenSSH config https://github.com/gravitational/teleport/pull/7848
func onProxyCommandSSH(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}

	targetHost, targetPort, err := net.SplitHostPort(tc.Host)
	if err != nil {
		return trace.Wrap(err)
	}
	targetHost = cleanTargetHost(targetHost, tc.WebProxyHost(), tc.SiteName)

	if tc.TLSRoutingEnabled {
		return trace.Wrap(sshProxyWithTLSRouting(cf, tc, targetHost, targetPort))
	}

	return trace.Wrap(sshProxy(cf, tc, targetHost, targetPort))
}

// cleanTargetHost cleans the targetHost and remote site and proxy suffixes.
// Before the `cut -d` command was used for this purpose but to support multi-platform OpenSSH clients the logic
// it was moved tsh proxy ssh command.
// For more details please look at: Generate Windows-compatible OpenSSH config https://github.com/gravitational/teleport/pull/7848
func cleanTargetHost(targetHost, proxyHost, siteName string) string {
	targetHost = strings.TrimSuffix(targetHost, "."+proxyHost)
	targetHost = strings.TrimSuffix(targetHost, "."+siteName)
	return targetHost
}

func sshProxyWithTLSRouting(cf *CLIConf, tc *libclient.TeleportClient, targetHost, targetPort string) error {
	address, err := utils.ParseAddr(tc.WebProxyAddr)
	if err != nil {
		return trace.Wrap(err)
	}

	pool, err := tc.LocalAgent().ClientCertPool(tc.SiteName)
	if err != nil {
		return trace.Wrap(err)
	}
	tlsConfig := &tls.Config{
		RootCAs: pool,
	}

	lp, err := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		RemoteProxyAddr:    tc.WebProxyAddr,
		Protocol:           alpncommon.ProtocolProxySSH,
		InsecureSkipVerify: cf.InsecureSkipVerify,
		ParentContext:      cf.Context,
		SNI:                address.Host(),
		SSHUser:            tc.HostLogin,
		SSHUserHost:        fmt.Sprintf("%s:%s", targetHost, targetPort),
		SSHHostKeyCallback: tc.HostKeyCallback,
		SSHTrustedCluster:  cf.SiteName,
		ClientTLSConfig:    tlsConfig,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer lp.Close()
	if err := lp.SSHProxy(tc.LocalAgent()); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func sshProxy(cf *CLIConf, tc *libclient.TeleportClient, targetHost, targetPort string) error {
	sshPath, err := getSSHPath()
	if err != nil {
		return trace.Wrap(err)
	}
	keysDir := profile.FullProfilePath(tc.Config.KeysDir)
	knownHostsPath := keypaths.KnownHostsPath(keysDir)

	sshHost, sshPort := tc.SSHProxyHostPort()
	args := []string{
		"-A",
		"-o", fmt.Sprintf("UserKnownHostsFile=%s", knownHostsPath),
		"-p", strconv.Itoa(sshPort),
		sshHost,
		"-s",
		fmt.Sprintf("proxy:%s:%s@%s", targetHost, targetPort, tc.SiteName),
	}

	if tc.HostLogin != "" {
		args = append([]string{"-l", tc.HostLogin}, args...)
	}

	child := exec.Command(sshPath, args...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return trace.Wrap(child.Run())
}

func onProxyCommandDB(cf *CLIConf) error {
	client, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}
	database, err := pickActiveDatabase(cf)
	if err != nil {
		return trace.Wrap(err)
	}
	rootCluster, err := client.RootClusterName()
	if err != nil {
		return trace.Wrap(err)
	}
	profile, err := libclient.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}

	addr := "localhost:0"
	if cf.LocalProxyPort != "" {
		addr = fmt.Sprintf("127.0.0.1:%s", cf.LocalProxyPort)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.WithError(err).Warnf("Failed to close listener.")
		}
	}()

	// If user requested no client auth, open an authenticated tunnel using
	// client cert/key of the database.
	certFile := cf.LocalProxyCertFile
	if certFile == "" && cf.LocalProxyTunnel {
		certFile = profile.DatabaseCertPathForCluster(cf.SiteName, database.ServiceName)
	}
	keyFile := cf.LocalProxyKeyFile
	if keyFile == "" && cf.LocalProxyTunnel {
		keyFile = profile.KeyPath()
	}

	lp, err := mkLocalProxy(cf.Context, localProxyOpts{
		proxyAddr: client.WebProxyAddr,
		protocol:  database.Protocol,
		listener:  listener,
		insecure:  cf.InsecureSkipVerify,
		certFile:  certFile,
		keyFile:   keyFile,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	go func() {
		<-cf.Context.Done()
		lp.Close()
	}()

	if cf.LocalProxyTunnel {
		addr, err := utils.ParseAddr(lp.GetAddr())
		if err != nil {
			return trace.Wrap(err)
		}
		cmd, err := dbcmd.NewCmdBuilder(client, profile, database, cf.SiteName,
			dbcmd.WithLocalProxy("localhost", addr.Port(0), ""),
			dbcmd.WithNoTLS(),
			dbcmd.WithLogger(log),
		).GetConnectCommand()
		if err != nil {
			return trace.Wrap(err)
		}
		err = dbProxyAuthTpl.Execute(os.Stdout, map[string]string{
			"database": database.ServiceName,
			"type":     dbProtocolToText(database.Protocol),
			"cluster":  profile.Cluster,
			"command":  cmd.String(),
			"address":  listener.Addr().String(),
		})
		if err != nil {
			return trace.Wrap(err)
		}
	} else {
		err = dbProxyTpl.Execute(os.Stdout, map[string]string{
			"database": database.ServiceName,
			"address":  listener.Addr().String(),
			"ca":       profile.CACertPathForCluster(rootCluster),
			"cert":     profile.DatabaseCertPathForCluster(cf.SiteName, database.ServiceName),
			"key":      profile.KeyPath(),
		})
		if err != nil {
			return trace.Wrap(err)
		}
	}

	defer lp.Close()
	if err := lp.Start(cf.Context); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

type localProxyOpts struct {
	proxyAddr string
	listener  net.Listener
	protocol  string
	insecure  bool
	certFile  string
	keyFile   string
}

func mkLocalProxy(ctx context.Context, opts localProxyOpts) (*alpnproxy.LocalProxy, error) {
	alpnProtocol, err := alpncommon.ToALPNProtocol(opts.protocol)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	address, err := utils.ParseAddr(opts.proxyAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs, err := mkLocalProxyCerts(opts.certFile, opts.keyFile)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lp, err := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		InsecureSkipVerify: opts.insecure,
		RemoteProxyAddr:    opts.proxyAddr,
		Protocol:           alpnProtocol,
		Listener:           opts.listener,
		ParentContext:      ctx,
		SNI:                address.Host(),
		Certs:              certs,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return lp, nil
}

func mkLocalProxyCerts(certFile, keyFile string) ([]tls.Certificate, error) {
	if certFile == "" && keyFile == "" {
		return []tls.Certificate{}, nil
	}
	if certFile == "" && keyFile != "" || certFile != "" && keyFile == "" {
		return nil, trace.BadParameter("both --cert-file and --key-file are required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return []tls.Certificate{cert}, nil
}

// dbProxyTpl is the message that gets printed to a user when a database proxy is started.
var dbProxyTpl = template.Must(template.New("").Parse(`Started DB proxy on {{.address}}

Use following credentials to connect to the {{.database}} proxy:
  ca_file={{.ca}}
  cert_file={{.cert}}
  key_file={{.key}}
`))

func dbProtocolToText(protocol string) string {
	switch protocol {
	case defaults.ProtocolPostgres:
		return "PostgreSQL"
	case defaults.ProtocolCockroachDB:
		return "CockroachDB"
	case defaults.ProtocolMySQL:
		return "MySQL"
	case defaults.ProtocolMongoDB:
		return "MongoDB"
	case defaults.ProtocolRedis:
		return "Redis"
	case defaults.ProtocolSQLServer:
		return "SQL Server"
	}
	return ""
}

// dbProxyAuthTpl is the message that's printed for an authenticated db proxy.
var dbProxyAuthTpl = template.Must(template.New("").Parse(
	`Started authenticated tunnel for the {{.type}} database "{{.database}}" in cluster "{{.cluster}}" on {{.address}}.

Use the following command to connect to the database:
  $ {{.command}}
`))
