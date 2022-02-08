/*
Copyright 2022 Gravitational, Inc.

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

package aws

import (
	"os"
	"sync"

	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	"github.com/aws/aws-sdk-go/aws/credentials"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
)

// CredentialsConfig is the configuration for Teleport's custom AWS credentials
// providers.
type CredentialsConfig struct {
	// Profile is the profile name
	Profile string

	// AccessKeyID is the AWS access key ID.
	AccessKeyID string

	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string

	// CustomCABundePath is the path to a custom CA bundle.
	CustomCABundePath string

	// Setenv is a function that used to override os.Setenv in tests.
	Setenv func(string, string) error
}

// CheckAndSetDefaults validates the config and sets defaults.
func (c *CredentialsConfig) CheckAndSetDefaults() error {
	if c.Profile == "" {
		c.Profile = defaultProfile
	}

	if c.Setenv == nil {
		c.Setenv = os.Setenv
	}

	if c.AccessKeyID == "" {
		return trace.BadParameter("AccessKeyID is empty")
	}
	if c.SecretAccessKey == "" {
		return trace.BadParameter("SecretAccessKey is empty")
	}
	if c.CustomCABundePath == "" {
		return trace.BadParameter("CustomCABundePath is empty")
	}
	return nil
}

// CredentialsFileProvider is a custom AWS credentials provider that provides
// credentials through a shared credentials file.
//
// One use case of these credentials files is to authenticate AWS clients
// against a local AWS proxy hosted by "tsh". Each credentials file contains a
// AWS profile with a few settings that are supported by most AWS clients and
// SDKs. The "aws_access_key_id" and "aws_secret_access_key" settings are used
// by our proxies to verify the Authorization header signed by SigV4. The
// "ca_bundle" setting specifies a CA bundle that can be used against our
// proxies through TLS connections. The credentials file can usually be loaded
// by AWS clients by specifying environment variable
// "AWS_SHARED_CREDENTIALS_FILE".
//
// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-settings
// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
type CredentialsFileProvider struct {
	*CredentialsConfig

	// readCAOnce is an sync.Once object used to avoid reading CA bundle
	// multiple times.
	readCAOnce sync.Once

	// isExpired is the expiration state of the credentials.
	isExpired bool
}

// LoadCredentialsFile returns our credentials provider by parsing an existing
// credentials file.
func LoadCredentialsFile(path string, profile string) (*CredentialsFileProvider, error) {
	// Currently, "aws-sdk-go" does not expose functions that parse the entire
	// shared config files. "aws-sdk-go-v2" does not support "ca_bundle" for
	// config.SharedConfig. Use "ini" lib to parse until it is supported in AWS
	// SDK.
	iniFile, err := ini.Load(path)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	if profile == "" {
		profile = defaultProfile
	}

	section := iniFile.Section(profile)
	if section == nil {
		return nil, trace.NotFound("profile %v not found in credentials file %v", profile, path)
	}

	config := &CredentialsConfig{
		Profile: profile,
	}
	for keyName, target := range map[string]*string{
		sectionKeyAccessKeyID:     &config.AccessKeyID,
		sectionKeySecretAccessKey: &config.SecretAccessKey,
		sectionKeyCABundle:        &config.CustomCABundePath,
	} {
		key, err := section.GetKey(keyName)
		if err != nil {
			// GetKey error is fmt.Errorf("error when getting key of section %q: key %q not exists", s.name, name)
			return nil, trace.NotFound("failed to parse credentials file %v: %v", path, err)
		}
		*target = key.String()
	}

	if err = config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	return &CredentialsFileProvider{
		CredentialsConfig: config,
	}, nil
}

// SaveCredentialsFile saves the specified credentials in the specified path
// and returns our credentials provider.
func SaveCredentialsFile(config *CredentialsConfig, path string) (*CredentialsFileProvider, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	// LooseLoad will ignore file not found error.
	iniFile, err := ini.LooseLoad(path)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if section := iniFile.Section(config.Profile); section != nil {
		iniFile.DeleteSection(config.Profile)
	}

	section, err := iniFile.NewSection(config.Profile)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for keyName, value := range map[string]string{
		sectionKeyAccessKeyID:     config.AccessKeyID,
		sectionKeySecretAccessKey: config.SecretAccessKey,
		sectionKeyCABundle:        config.CustomCABundePath,
	} {
		if _, err = section.NewKey(keyName, value); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	ini.PrettyFormat = false // Do not align equal signs
	if err = iniFile.SaveTo(path); err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	return &CredentialsFileProvider{
		CredentialsConfig: config,
	}, nil
}

// Retrieve returns credentials values. This function implements
// credentials.Provider of aws-sdk-go.
func (p *CredentialsFileProvider) Retrieve() (credentials.Value, error) {
	return credentials.Value{
		AccessKeyID:     p.AccessKeyID,
		SecretAccessKey: p.SecretAccessKey,
		SessionToken:    "",
		ProviderName:    ProviderName,
	}, nil
}

// IsExpired checks if credentials are expired. This function implements
// credentials.Provider of aws-sdk-go.
func (p *CredentialsFileProvider) IsExpired() bool {
	p.readCAOnce.Do(func() {
		p.isExpired = true

		certsBytes, err := utils.ReadPath(p.CustomCABundePath)
		if err != nil {
			log.WithError(err).Warnf("Failed to read CA file %v.", p.CustomCABundePath)
			return
		}

		certs, err := utils.ReadCertificates(certsBytes)
		if err != nil {
			log.WithError(err).Warnf("Failed to parse certificates from CA file %v.", p.CustomCABundePath)
			return
		}

		// Set expired to false if any cert is not expired.
		for _, cert := range certs {
			if err = utils.VerifyCertificateExpiry(cert, nil); err == nil {
				p.isExpired = false
				return
			}
		}
	})
	return p.isExpired
}

// GetEnvironmentVariables returns a map of environment variables that can be
// used to configure the same settings saved in the credentials file.
func (p *CredentialsFileProvider) GetEnvironmentVariables() map[string]string {
	return map[string]string{
		envVarAccessKeyID:     p.AccessKeyID,
		envVarSecretAccessKey: p.SecretAccessKey,
		envVarCABundle:        p.CustomCABundePath,
	}
}

// SetEnvironmentVariables sets credentials through environment variables for
// AWS clients.
func (p *CredentialsFileProvider) SetEnvironmentVariables() error {
	for key, value := range p.GetEnvironmentVariables() {
		if err := p.Setenv(key, value); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

const (
	// ProviderName is the name of our custom credentials provider.
	ProviderName = "teleport"
)

const (
	// defaultProfile is the default profile name used in the credentials file.
	defaultProfile = "default"

	// sectionKeyAccessKeyID is the section key for the AWS access key.
	sectionKeyAccessKeyID = "aws_access_key_id"
	// sectionKeySecretAccessKey is the section key for the secret key
	// associated with the access key.
	sectionKeySecretAccessKey = "aws_secret_access_key"
	// sectionKeyCABundle is the section key for the custom CA bundle path.
	sectionKeyCABundle = "ca_bundle"

	// envVarAccessKeyID is the environment variable name for the AWS access
	// key.
	envVarAccessKeyID = "AWS_ACCESS_KEY_ID"
	// envVarSecretAccessKey is the environment variable name for the secret
	// key associated with the access key.
	envVarSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	// envVarCABundle is the environment variable name for the custom CA bundle
	// path.
	envVarCABundle = "AWS_CA_BUNDLE"
)
