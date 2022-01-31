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
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/utils/keypaths"
	libclient "github.com/gravitational/teleport/lib/client"
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
	lp, err := mkLocalProxy(cf, client.WebProxyAddr, database.Protocol, listener)
	if err != nil {
		return trace.Wrap(err)
	}
	go func() {
		<-cf.Context.Done()
		lp.Close()
	}()

	profile, err := libclient.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return trace.Wrap(err)
	}

	err = dbProxyTpl.Execute(os.Stdout, map[string]string{
		"database": database.ServiceName,
		"address":  listener.Addr().String(),
		"ca":       profile.CACertPath(),
		"cert":     profile.DatabaseCertPathForCluster(cf.SiteName, database.ServiceName),
		"key":      profile.KeyPath(),
	})
	if err != nil {
		return trace.Wrap(err)
	}

	defer lp.Close()
	if err := lp.Start(cf.Context); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// onProxyCommandAWS creates a local AWS proxy.
func onProxyCommandAWS(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}

	tempAWSCred, err := newTempAWSCredentials()
	if err != nil {
		return trace.Wrap(err)
	}
	defer tempAWSCred.cleanup()

	if err = tempAWSCred.createSharedCredentialsFile(); err != nil {
		return trace.Wrap(err)
	}

	localProxy, err := createLocalAWSCLIProxy(cf, tc, tempAWSCred.get(), tempAWSCred.getCert())
	if err != nil {
		return trace.Wrap(err)
	}

	defer localProxy.Close()
	go func() {
		<-cf.Context.Done()
		localProxy.Close()
	}()

	endpointURL := url.URL{Scheme: "https", Host: localProxy.GetAddr()}
	templateData := tempAWSCred.genEnvironmentVariables()
	templateData["credentialsFile"] = tempAWSCred.getSharedCredentialsFilePath()
	templateData["address"] = localProxy.GetAddr()
	templateData["endpointURL"] = endpointURL.String()
	if err = awsProxyTemplate.Execute(os.Stdout, templateData); err != nil {
		return trace.Wrap(err)
	}
	if err := localProxy.StartAWSAccessProxy(cf.Context); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func mkLocalProxy(cf *CLIConf, remoteProxyAddr string, protocol string, listener net.Listener) (*alpnproxy.LocalProxy, error) {
	alpnProtocol, err := toALPNProtocol(protocol)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	address, err := utils.ParseAddr(remoteProxyAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lp, err := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		InsecureSkipVerify: cf.InsecureSkipVerify,
		RemoteProxyAddr:    remoteProxyAddr,
		Protocol:           alpnProtocol,
		Listener:           listener,
		ParentContext:      cf.Context,
		SNI:                address.Host(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return lp, nil
}

func toALPNProtocol(dbProtocol string) (alpncommon.Protocol, error) {
	switch dbProtocol {
	case defaults.ProtocolMySQL:
		return alpncommon.ProtocolMySQL, nil
	case defaults.ProtocolPostgres, defaults.ProtocolCockroachDB:
		return alpncommon.ProtocolPostgres, nil
	case defaults.ProtocolMongoDB:
		return alpncommon.ProtocolMongoDB, nil
	default:
		return "", trace.NotImplemented("%q protocol is not supported", dbProtocol)
	}
}

var (
	// dbProxyTpl is the message that gets printed to a user when a database proxy is started.
	dbProxyTpl = template.Must(template.New("").Parse(`Started DB proxy on {{.address}}

Use the following credentials to connect to the {{.database}} proxy:
  ca_file={{.ca}}
  cert_file={{.cert}}
  key_file={{.key}}
`))

	// awsProxyTemplate is the message that gets printed to a user when an AWS
	// proxy is started.
	awsProxyTemplate = template.Must(template.New("").Parse(`Started AWS proxy on {{.address}}

Use the following AWS credentials file to connect to the proxy:
  AWS_SHARED_CREDENTIALS_FILE={{.credentialsFile}}

Alternatively, use the following credentials to connect to the proxy:
  AWS_ACCESS_KEY_ID={{.AWS_ACCESS_KEY_ID}}
  AWS_SECRET_ACCESS_KEY={{.AWS_SECRET_ACCESS_KEY}}
  AWS_CA_BUNDLE={{.AWS_CA_BUNDLE}}

In addition to the credentials, please use "{{.endpointURL}}" as the endpoint
URL(s) in your AWS client applications.

For example, to get caller identity with AWS CLI:
  AWS_SHARED_CREDENTIALS_FILE={{.credentialsFile}} aws sts get-caller-identity --endpoint-url={{.endpointURL}}

`))
)
