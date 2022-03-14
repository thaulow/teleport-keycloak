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
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/client"
	awscred "github.com/gravitational/teleport/lib/client/aws"
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
	lp, err := createLocalAWSProxy(cf)
	if err != nil {
		return trace.Wrap(err)
	}
	defer lp.Close()
	go func() {
		if err := lp.StartAWSAccessProxy(cf.Context); err != nil {
			log.WithError(err).Errorf("Failed to start local proxy.")
		}
	}()

	endpointURL := url.URL{Scheme: "https", Host: lp.GetAddr()}
	if err := os.Setenv("https_proxy", endpointURL.String()); err != nil {
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

// createLocalAWSProxy creates a local proxy for AWS clients.
func createLocalAWSProxy(cf *CLIConf) (*alpnproxy.LocalProxy, error) {
	profile, err := client.StatusCurrent(cf.HomePath, cf.Proxy)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	awsAppName, err := pickActiveAWSApp(cf, profile)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tc, err := makeClient(cf, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	appCert, appX509Cert, err := loadAWSAppCertificate(tc, awsAppName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	caCert, err := getSelfSignedLocalCert(profile, awsAppName, appX509Cert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	credProvider, err := getAWSCredentialsProvider(profile, awsAppName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Set credentials through environment variables for AWS CLI.
	if err = credProvider.SetEnvironmentVariables(); err != nil {
		return nil, trace.Wrap(err)
	}

	proxyAddress, err := utils.ParseAddr(tc.WebProxyAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	listenAddr := "localhost:0"
	if cf.LocalProxyPort != "" {
		listenAddr = fmt.Sprintf("localhost:%s", cf.LocalProxyPort)
	}

	listener, err := alpnproxy.NewHTTPSFowardProxyListener(listenAddr, caCert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	lp, err := alpnproxy.NewLocalProxy(alpnproxy.LocalProxyConfig{
		Listener:           listener,
		RemoteProxyAddr:    tc.WebProxyAddr,
		Protocol:           alpncommon.ProtocolHTTP,
		InsecureSkipVerify: cf.InsecureSkipVerify,
		ParentContext:      cf.Context,
		SNI:                proxyAddress.Host(),
		AWSCredentials:     credentials.NewCredentials(credProvider),
		Certs:              []tls.Certificate{appCert},
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
func loadAWSAppCertificate(tc *client.TeleportClient, appName string) (tls.Certificate, *x509.Certificate, error) {
	key, err := tc.LocalAgent().GetKey(tc.SiteName, client.WithAppCerts{})
	if err != nil {
		return tls.Certificate{}, nil, trace.Wrap(err)
	}
	cc, ok := key.AppTLSCerts[appName]
	if !ok {
		return tls.Certificate{}, nil, trace.NotFound("please login into AWS Console App 'tsh app login' first")
	}
	cert, err := tls.X509KeyPair(cc, key.Priv)
	if err != nil {
		return tls.Certificate{}, nil, trace.Wrap(err)
	}
	if len(cert.Certificate) < 1 {
		return tls.Certificate{}, nil, trace.NotFound("invalid certificate length")
	}
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, trace.Wrap(err)
	}
	if time.Until(x509cert.NotAfter) < 5*time.Second {
		return tls.Certificate{}, nil, trace.BadParameter(
			"AWS application %s certificate has expired, please re-login to the app using 'tsh app login'",
			appName)
	}
	return cert, x509cert, nil
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

// getAWSCredentialsProvider returns generated AWS credentials for the
// specified AWS app.
func getAWSCredentialsProvider(profile *client.ProfileStatus, awsAppName string) (*awscred.CredentialsFileProvider, error) {
	credFilePath := profile.AWSCredentialsPath(awsAppName)
	caPath := profile.AppLocalhostCAPath(awsAppName)

	cred, err := awscred.LoadCredentialsFile(credFilePath, awscred.DefaultProfile)
	if err != nil {
		log.WithError(err).Debugf("Failed to load AWS credentials file: %v.", credFilePath)
		// Fallthrough to create new credentials file.
	} else if cred.CustomCABundePath != caPath {
		log.Debugf("CA bundle paths do not match. Expected %v, but got %v.", caPath, cred.CustomCABundePath)
		// Fallthrough to create new credentials file.
	} else {
		return cred, nil
	}

	if utils.FileExists(credFilePath) {
		if err := os.Remove(credFilePath); err != nil {
			return nil, trace.ConvertSystemError(err)
		}
	}

	// There is no specific format or value required for access key and secret,
	// as long as the AWS clients are using these to generate Authentication
	// header which is verified by the local proxy that is using the same
	// values. Access key has a length constraint of size between 16 and 128.
	// Here access key and secert are generated based on current profile and
	// app name so same values can be recreated.
	//
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_Credentials.html
	hashData := []byte(fmt.Sprintf("%v-%v-%v", profile.Name, profile.Username, awsAppName))
	md5sum := md5.Sum(hashData)
	sha1sum := sha1.Sum(hashData)
	config := &awscred.CredentialsConfig{
		AccessKeyID:       hex.EncodeToString(md5sum[:])[:16],
		SecretAccessKey:   hex.EncodeToString(sha1sum[:]),
		CustomCABundePath: caPath,
	}
	return awscred.SaveCredentialsFile(config, credFilePath)
}

func pickActiveAWSApp(cf *CLIConf, profile *client.ProfileStatus) (string, error) {
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

const (
	// AWSCLIModeEndpointURL is mode where --endpoint-url is passed to AWS
	// CLI to forward the request to the local proxy.
	awsCLIModeEndpointURL = "endpoint-url"

	awsCLIModeHTTPSProxy = "https_proxy"
)
