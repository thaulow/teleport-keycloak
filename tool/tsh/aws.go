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
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	alpncommon "github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	awsarn "github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	awsCLIBinaryName = "aws"
)

func onAWS(cf *CLIConf) error {
	awsApp, err := pickActiveAWSApp(cf)
	if err != nil {
		return trace.Wrap(err)
	}

	lp, err := awsApp.createLocalAWSProxy()
	if err != nil {
		return trace.Wrap(err)
	}
	defer lp.Close()
	go func() {
		if err := lp.StartAWSAccessProxy(cf.Context); err != nil {
			log.WithError(err).Errorf("Failed to start local proxy.")
		}
	}()

	url := url.URL{
		Host:   lp.GetAddr(),
		Scheme: "https",
	}
	if err := os.Setenv("HTTPS_PROXY", url.String()); err != nil {
		return trace.Wrap(err)
	}

	cmd := exec.Command(awsCLIBinaryName, cf.AWSCommandArgs...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

type awsApp struct {
	cf      *CLIConf
	profile *client.ProfileStatus
	tc      *client.TeleportClient

	appName     string
	appCert     tls.Certificate
	appCertX509 *x509.Certificate

	localCAKeyPath string
	localCAPath    string
	localCA        tls.Certificate

	credentials *credentials.Credentials
}

func newAWSApp(cf *CLIConf, profile *client.ProfileStatus, appName string) (*awsApp, error) {
	tc, err := makeClient(cf, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &awsApp{
		cf:             cf,
		tc:             tc,
		profile:        profile,
		appName:        appName,
		localCAKeyPath: profile.KeyPath(),
		localCAPath:    profile.AppLocalhostCAPath(appName),
	}, nil
}

// loadSelfSignedCA loads self-signed CA.
func (a *awsApp) loadSelfSignedCA() (err error) {
	if !utils.FileExists(a.localCAPath) {
		return a.generateSelfSignedCA()
	}

	if a.localCA, err = tls.LoadX509KeyPair(a.localCAPath, a.localCAKeyPath); err != nil {
		log.WithError(err).Debugf("Failed to load certificate from %v. Regenerating local self signed CA.", a.localCAPath)
		return a.generateSelfSignedCA()
	}

	return nil
}

// generateSelfSignedCA prepares self-signed CA used for local proxy.
func (a *awsApp) generateSelfSignedCA() (err error) {
	if err = a.loadAppCertificate(); err != nil {
		return trace.Wrap(err)
	}

	if a.localCA, err = newSelfSignedCA(a.localCAPath, a.localCAKeyPath, a.appCertX509.NotAfter); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// genAndSetAWSCredentials generates fake AWS credentials that are used for
// signing an AWS request during AWS API calls and verified on local AWS proxy
// side, and then sets the credentials through environment variables.
func (a *awsApp) genAndSetAWSCredentials() error {
	// There is no specific format or value required for access key and secret,
	// as long as the AWS clients and the local proxy are using the same
	// values. Access key has a length constraint of size between 16 and 128.
	// Here access key and secert are generated based on current profile and
	// app name so same values can be recreated.
	//
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_Credentials.html
	hashData := []byte(fmt.Sprintf("%v-%v-%v", a.profile.Name, a.profile.Username, a.appName))
	md5sum := md5.Sum(hashData)
	sha1sum := sha1.Sum(hashData)
	id := hex.EncodeToString(md5sum[:])[:16]
	secret := hex.EncodeToString(sha1sum[:])

	a.credentials = credentials.NewStaticCredentials(id, secret, "")
	return a.setAWSEnvCredentials()
}

// setAWSEnvCredentials sets AWS credentials through environment variables.
func (a *awsApp) setAWSEnvCredentials() error {
	envVariables, err := a.getAWSEnvCredentials()
	if err != nil {
		return trace.Wrap(err)
	}

	for key, value := range envVariables {
		if err := os.Setenv(key, value); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// getAWSEnvCredentials returns a list of AWS credentials mapped to their
// environment variables.
//
// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
func (a *awsApp) getAWSEnvCredentials() (map[string]string, error) {
	if a.credentials == nil {
		return nil, trace.BadParameter("credentials is missing")
	}

	values, err := a.credentials.Get()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return map[string]string{
		"AWS_ACCESS_KEY_ID":     values.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": values.SecretAccessKey,
		"AWS_CA_BUNDLE":         a.localCAPath,
	}, nil
}

// createLocalAWSProxy creates a local proxy for AWS clients.
func (a *awsApp) createLocalAWSProxy() (*alpnproxy.LocalProxy, error) {
	if err := a.loadAppCertificate(); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := a.loadSelfSignedCA(); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := a.genAndSetAWSCredentials(); err != nil {
		return nil, trace.Wrap(err)
	}

	proxyAddress, err := utils.ParseAddr(a.tc.WebProxyAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	listenAddr := "localhost:0"
	if a.cf.LocalProxyPort != "" {
		listenAddr = fmt.Sprintf("localhost:%s", a.cf.LocalProxyPort)
	}

	listener, err := alpnproxy.NewHTTPSFowardProxyListener(listenAddr, a.localCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	lp, err := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		Listener:           listener,
		RemoteProxyAddr:    a.tc.WebProxyAddr,
		Protocol:           alpncommon.ProtocolHTTP,
		InsecureSkipVerify: a.cf.InsecureSkipVerify,
		ParentContext:      a.cf.Context,
		SNI:                proxyAddress.Host(),
		AWSCredentials:     a.credentials,
		Certs:              []tls.Certificate{a.appCert},
	})
	if err != nil {
		if cerr := listener.Close(); cerr != nil {
			return nil, trace.NewAggregate(err, cerr)
		}
		return nil, trace.Wrap(err)
	}
	return lp, nil
}

// loadAWSAppCertificate loads the certificate for the specified AWS app.
func (a *awsApp) loadAppCertificate() (err error) {
	key, err := a.tc.LocalAgent().GetKey(a.tc.SiteName, client.WithAppCerts{})
	if err != nil {
		return trace.Wrap(err)
	}
	cc, ok := key.AppTLSCerts[a.appName]
	if !ok {
		return trace.NotFound("please login into AWS Console App 'tsh app login' first")
	}

	a.appCert, err = tls.X509KeyPair(cc, key.Priv)
	if err != nil {
		return trace.Wrap(err)
	}

	if len(a.appCert.Certificate) < 1 {
		return trace.NotFound("invalid certificate length")
	}

	a.appCertX509, err = x509.ParseCertificate(a.appCert.Certificate[0])
	if err != nil {
		return trace.Wrap(err)
	}

	if time.Until(a.appCertX509.NotAfter) < 5*time.Second {
		return trace.BadParameter(
			"AWS application %s certificate has expired, please re-login to the app using 'tsh app login'",
			a.appName)
	}
	return nil
}

func printArrayAs(arr []string, columnName string) {
	sort.Strings(arr)
	if len(arr) == 0 {
		return
	}
	t := asciitable.MakeTable([]string{columnName})
	for _, v := range arr {
		t.AddRow([]string{v})
	}
	fmt.Println(t.AsBuffer().String())

}

func getARNFromFlags(cf *CLIConf, profile *client.ProfileStatus) (string, error) {
	if cf.AWSRole == "" {
		printArrayAs(profile.AWSRolesARNs, "Available Role ARNs")
		return "", trace.BadParameter("--aws-role flag is required")
	}
	for _, v := range profile.AWSRolesARNs {
		if v == cf.AWSRole {
			return v, nil
		}
	}

	roleNameToARN := make(map[string]string)
	for _, v := range profile.AWSRolesARNs {
		arn, err := awsarn.Parse(v)
		if err != nil {
			return "", trace.Wrap(err)
		}
		// Example of the ANR Resource: 'role/EC2FullAccess' or 'role/path/to/customrole'
		parts := strings.Split(arn.Resource, "/")
		if len(parts) < 1 || parts[0] != "role" {
			continue
		}
		roleName := strings.Join(parts[1:], "/")

		if val, ok := roleNameToARN[roleName]; ok && cf.AWSRole == roleName {
			return "", trace.BadParameter(
				"provided role name %q is ambiguous between %q and %q ARNs, please specify full role ARN",
				cf.AWSRole, val, arn.String())
		}
		roleNameToARN[roleName] = arn.String()
	}

	roleARN, ok := roleNameToARN[cf.AWSRole]
	if !ok {
		printArrayAs(profile.AWSRolesARNs, "Available Role ARNs")
		printArrayAs(mapKeysToSlice(roleNameToARN), "Available Role Names")
		inputType := "ARN"
		if !awsarn.IsARN(cf.AWSRole) {
			inputType = "name"
		}
		return "", trace.NotFound("failed to find the %q role %s", cf.AWSRole, inputType)
	}
	return roleARN, nil
}

func mapKeysToSlice(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// newSelfSignedCA generates new self signed local cert.
func newSelfSignedCA(caPath, keyPath string, notAfter time.Time) (tls.Certificate, error) {
	keyPem, err := utils.ReadPath(keyPath)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	key, err := utils.ParsePrivateKey(keyPem)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	certPem, err := tlsca.GenerateSelfSignedCAWithConfig(tlsca.GenerateCAConfig{
		Entity: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Teleport"},
		},
		Signer:      key,
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP(defaults.Localhost)},
		TTL:         time.Until(notAfter),
		Clock:       clockwork.NewRealClock(),
	})
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	// WriteFile truncates existing file before writing.
	if err = os.WriteFile(caPath, certPem, 0600); err != nil {
		return tls.Certificate{}, trace.ConvertSystemError(err)
	}
	return cert, nil
}

// pickActiveAWSApp returns the AWS app the current profile is logged into.
func pickActiveAWSApp(cf *CLIConf) (*awsApp, error) {
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(profile.Apps) == 0 {
		return nil, trace.NotFound("Please login to AWS app using 'tsh app login' first")
	}
	name := cf.AppName
	if name != "" {
		app, err := profile.FindApp(name)
		if err != nil {
			if trace.IsNotFound(err) {
				return nil, trace.NotFound("Please login to AWS app using 'tsh app login' first")
			}
			return nil, trace.Wrap(err)
		}
		if app.AWSRoleARN == "" {
			return nil, trace.BadParameter(
				"Selected app %q is not an AWS application", name,
			)
		}
		return newAWSApp(cf, profile, name)
	}

	awsApps := profile.AWSAppNames()
	if len(awsApps) == 0 {
		return nil, trace.NotFound("Please login to AWS App using 'tsh app login' first")
	}
	if len(awsApps) > 1 {
		names := strings.Join(awsApps, ", ")
		return nil, trace.BadParameter(
			"Multiple AWS apps are available (%v), please specify one using --app CLI argument", names,
		)
	}
	return newAWSApp(cf, profile, awsApps[0])
}

// postAWSAppLogin handles an AWS app after its app login.
func postAWSAppLogin(cf *CLIConf, profile *client.ProfileStatus, awsAppName string) error {
	awsApp, err := newAWSApp(cf, profile, awsAppName)
	if err != nil {
		return trace.Wrap(err)
	}

	if err = awsApp.generateSelfSignedCA(); err != nil {
		return trace.Wrap(err)
	}

	return awsCliTpl.Execute(os.Stdout, map[string]string{
		"awsAppName": awsAppName,
		"awsCmd":     "s3 ls",
	})
}

// awsCliTpl is the message that gets printed to a user upon successful aws app login.
var awsCliTpl = template.Must(template.New("").Parse(
	`Logged into AWS app {{.awsAppName}}. Example AWS cli command:

tsh aws {{.awsCmd}}
`))
