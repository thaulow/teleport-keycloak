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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/google/uuid"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	alpncommon "github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	awsarn "github.com/aws/aws-sdk-go/aws/arn"
)

const (
	awsCLIBinaryName = "aws"
)

func onAWS(cf *CLIConf) error {
	tc, err := makeClient(cf, false)
	if err != nil {
		return trace.Wrap(err)
	}

	// Generate temporary AWS credentials and self-signed local cert.
	tempAWSCred, err := newTempAWSCredentials()
	if err != nil {
		return trace.Wrap(err)
	}
	defer tempAWSCred.cleanup()

	// AWS credentials need to be set through environment variables in order to
	// enforce AWS CLI to sign the request and provide Authorization Header
	// where service-name and region-name are encoded.
	if err = tempAWSCred.setEnvironmentVariables(); err != nil {
		return trace.Wrap(err)
	}

	lp, err := createLocalAWSCLIProxy(cf, tc, tempAWSCred.get(), tempAWSCred.getCert())
	if err != nil {
		return trace.Wrap(err)
	}
	defer lp.Close()
	go func() {
		if err := lp.StartAWSAccessProxy(cf.Context); err != nil {
			log.WithError(err).Errorf("Failed to start local proxy.")
		}
	}()

	// Use "--endpoint-url" flag to force AWS CLI to connect to the local proxy.
	// Teleport AWS Signing APP will resolve aws-service and aws-region to the proper Amazon API URL.
	endpointURL := url.URL{Scheme: "https", Host: lp.GetAddr()}
	endpointFlag := fmt.Sprintf("--endpoint-url=%s", endpointURL.String())

	args := append([]string{}, cf.AWSCommandArgs...)
	args = append(args, endpointFlag)
	cmd := exec.Command(awsCLIBinaryName, args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func createLocalAWSCLIProxy(cf *CLIConf, tc *client.TeleportClient, cred *credentials.Credentials, localCerts tls.Certificate) (*alpnproxy.LocalProxy, error) {
	awsApp, err := pickActiveAWSApp(cf)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	appCerts, err := loadAWSAppCertificate(tc, awsApp)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	address, err := utils.ParseAddr(tc.WebProxyAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	localAddr := fmt.Sprintf("%s:0", defaults.Localhost)
	if cf.LocalProxyPort != "" {
		localAddr = fmt.Sprintf("%s:%s", defaults.Localhost, cf.LocalProxyPort)
	}
	listener, err := tls.Listen("tcp", localAddr, &tls.Config{
		Certificates: []tls.Certificate{
			localCerts,
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	lp, err := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		Listener:           listener,
		RemoteProxyAddr:    tc.WebProxyAddr,
		Protocol:           alpncommon.ProtocolHTTP,
		InsecureSkipVerify: cf.InsecureSkipVerify,
		ParentContext:      cf.Context,
		SNI:                address.Host(),
		AWSCredentials:     cred,
		Certs:              []tls.Certificate{appCerts},
	})
	if err != nil {
		if cerr := listener.Close(); cerr != nil {
			return nil, trace.NewAggregate(err, cerr)
		}
		return nil, trace.Wrap(err)
	}
	return lp, nil
}

func loadAWSAppCertificate(tc *client.TeleportClient, appName string) (tls.Certificate, error) {
	key, err := tc.LocalAgent().GetKey(tc.SiteName, client.WithAppCerts{})
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}
	cc, ok := key.AppTLSCerts[appName]
	if !ok {
		return tls.Certificate{}, trace.NotFound("please login into AWS Console App 'tsh app login' first")
	}
	cert, err := tls.X509KeyPair(cc, key.Priv)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}
	if len(cert.Certificate) < 1 {
		return tls.Certificate{}, trace.NotFound("invalid certificate length")
	}
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}
	if time.Until(x509cert.NotAfter) < 5*time.Second {
		return tls.Certificate{}, trace.BadParameter(
			"AWS application %s certificate has expired, please re-login to the app using 'tsh app login'",
			appName)
	}
	return cert, nil
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

// tempAWSCredentials creates fake AWS credentials and self-signed CA certs
// that are used for signing an AWS requests and verified on local AWS proxy
// side.
type tempAWSCredentials struct {
	*tempSelfSignedLocalCert

	accessKeyID     string
	secretAccessKey string
	credentials     *credentials.Credentials

	tempDir                   string
	sharedCredentialsFilePath string
}

// newTempAWSCredentials creates a new tempAWSCredentials.
func newTempAWSCredentials() (*tempAWSCredentials, error) {
	tempDir, err := ioutil.TempDir("", "teleport*")
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	tempCert, err := newTempSelfSignedLocalCert(tempDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	accessKeyID := uuid.NewString()
	secretAccessKey := uuid.NewString()
	return &tempAWSCredentials{
		tempSelfSignedLocalCert: tempCert,
		tempDir:                 tempDir,
		accessKeyID:             accessKeyID,
		secretAccessKey:         secretAccessKey,
		credentials:             credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
	}, nil
}

// genEnvironmentVariables returns a map of environment variables using
// generated credentials.
func (c *tempAWSCredentials) genEnvironmentVariables() map[string]string {
	// AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are used to generate the
	// authorization header by AWS CLI or SDK, and the signature will be
	// verified by the local proxy.
	//
	// AWS_CA_BUNDLE enforce HTTPS protocol communication between AWS clients
	// and the local proxy.
	return map[string]string{
		"AWS_ACCESS_KEY_ID":     c.accessKeyID,
		"AWS_SECRET_ACCESS_KEY": c.secretAccessKey,
		"AWS_CA_BUNDLE":         c.getCAPath(),
	}
}

// setEnvironmentVariables set fake credentials through environment variables for AWS CLI.
func (c *tempAWSCredentials) setEnvironmentVariables() error {
	for key, value := range c.genEnvironmentVariables() {
		if err := os.Setenv(key, value); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// createSharedCredentialsFile create an AWS credentials file using generated
// credentials.
func (c *tempAWSCredentials) createSharedCredentialsFile() error {
	c.sharedCredentialsFilePath = path.Join(c.tempDir, "credentials")
	sharedCredentialsFile, err := os.Create(c.sharedCredentialsFilePath)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	defer sharedCredentialsFile.Close()

	if err = awsSharedCredentialsFileTemplate.Execute(sharedCredentialsFile, c.genEnvironmentVariables()); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// cleanup removes generated files.
func (c *tempAWSCredentials) cleanup() {
	log.Debugf("Removing temporary directory: %v.", c.tempDir)
	if err := os.RemoveAll(c.tempDir); err != nil {
		log.WithError(err).Errorf("Failed to clean temporary directory %q.", c.tempDir)
	}
}

// get returns generated AWS credentials
func (c *tempAWSCredentials) get() *credentials.Credentials {
	return c.credentials
}

// getSharedCredentialsFilePath returns the path to generated AWS shared
// credentials file.
func (c *tempAWSCredentials) getSharedCredentialsFilePath() string {
	return c.sharedCredentialsFilePath
}

type tempSelfSignedLocalCert struct {
	cert   tls.Certificate
	caPath string
}

func newTempSelfSignedLocalCert(dir string) (*tempSelfSignedLocalCert, error) {
	caKey, caCert, err := tlsca.GenerateSelfSignedCAForLocalhost(pkix.Name{
		Organization: []string{"Teleport"},
	}, defaults.CATTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	caFile, err := os.Create(path.Join(dir, "aws_local_proxy.pem"))
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	defer caFile.Close()

	if _, err = caFile.Write(caCert); err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return &tempSelfSignedLocalCert{
		cert:   cert,
		caPath: caFile.Name(),
	}, nil
}

func (t *tempSelfSignedLocalCert) getCAPath() string {
	return t.caPath
}

func (t *tempSelfSignedLocalCert) getCert() tls.Certificate {
	return t.cert
}

func pickActiveAWSApp(cf *CLIConf) (string, error) {
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return "", trace.Wrap(err)
	}
	if len(profile.Apps) == 0 {
		return "", trace.NotFound("Please login to AWS app using 'tsh app login' first")
	}
	name := cf.AppName
	if name != "" {
		app, err := findApp(profile.Apps, name)
		if err != nil {
			if trace.IsNotFound(err) {
				return "", trace.NotFound("Please login to AWS app using 'tsh app login' first")
			}
			return "", trace.Wrap(err)
		}
		if app.AWSRoleARN == "" {
			return "", trace.BadParameter(
				"Selected app %q is not an AWS application", name,
			)
		}
		return name, nil
	}

	awsApps := getAWSAppsName(profile.Apps)
	if len(awsApps) == 0 {
		return "", trace.NotFound("Please login to AWS App using 'tsh app login' first")
	}
	if len(awsApps) > 1 {
		names := strings.Join(awsApps, ", ")
		return "", trace.BadParameter(
			"Multiple AWS apps are available (%v), please specify one using --app CLI argument", names,
		)
	}
	return awsApps[0], nil
}

func findApp(apps []tlsca.RouteToApp, name string) (*tlsca.RouteToApp, error) {
	for _, app := range apps {
		if app.Name == name {
			return &app, nil
		}
	}
	return nil, trace.NotFound("failed to find app with %q name", name)
}

func getAWSAppsName(apps []tlsca.RouteToApp) []string {
	var out []string
	for _, app := range apps {
		if app.AWSRoleARN != "" {
			out = append(out, app.Name)
		}
	}
	return out
}

var awsSharedCredentialsFileTemplate = template.Must(template.New("credentials").Parse(`[default]
aws_access_key_id={{.AWS_ACCESS_KEY_ID}}
aws_secret_access_key={{.AWS_SECRET_ACCESS_KEY}}
ca_bundle={{.AWS_CA_BUNDLE}}
`))
