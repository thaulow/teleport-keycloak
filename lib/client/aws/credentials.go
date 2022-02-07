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

	"github.com/gravitational/teleport/api/utils/tlsutils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	"github.com/aws/aws-sdk-go/aws/credentials"
	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
)

type CredentialsFileConfig struct {
	// Profile is the profile name
	Profile string

	// AccessKeyID is the AWS access key ID.
	AccessKeyID string

	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string

	// CustomCABundePath is the path to a custom CA bundle.
	CustomCABundePath string
}

// CheckAndSetDefaults validates the config and sets defaults.
func (c *CredentialsFileConfig) CheckAndSetDefaults() error {
	if c.Profile == "" {
		c.Profile = defaultProfile
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

type CredentialsFileProvider struct {
	*CredentialsFileConfig

	readCertOnce sync.Once
	expired      bool
}

func LoadCredentialsFile(path string, profile string) (*CredentialsFileProvider, error) {
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

	config := &CredentialsFileConfig{
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
		CredentialsFileConfig: config,
	}, nil
}

func SaveCredentialsFile(config *CredentialsFileConfig, path string) (*CredentialsFileProvider, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

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
		CredentialsFileConfig: config,
	}, nil
}

// Retrieve returns credentials values. This function implements
// credentials.Provider of AWS SDK.
func (p *CredentialsFileProvider) Retrieve() (credentials.Value, error) {
	return credentials.Value{
		AccessKeyID:     p.AccessKeyID,
		SecretAccessKey: p.SecretAccessKey,
		SessionToken:    "",
		ProviderName:    ProviderName,
	}, nil
}

// IsExpired checks if credentials are expired. This function implements
// credentials.Provider of AWS SDK.
func (p *CredentialsFileProvider) IsExpired() bool {
	p.readCertOnce.Do(func() {
		p.expired = true

		certsBytes, err := utils.ReadPath(p.CustomCABundePath)
		if err != nil {
			log.WithError(err).Warnf("Failed to read CA file %v.", p.CustomCABundePath)
			return
		}

		cert, err := tlsutils.ParseCertificatePEM(certsBytes)
		if err != nil {
			log.WithError(err).Warnf("Failed to parse certificates from CA file %v.", p.CustomCABundePath)
			return
		}

		if err = utils.VerifyCertificateExpiry(cert, nil); err == nil {
			p.expired = false
			return
		}
	})
	return p.expired
}

// GetEnvironmentVariables returns a map of environment variables using
// generated credentials.
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
		if err := os.Setenv(key, value); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

const (
	ProviderName = "teleport"
)

const (
	defaultProfile = "default"

	sectionKeyAccessKeyID     = "aws_access_key_id"
	sectionKeySecretAccessKey = "aws_secret_access_key"
	sectionKeyCABundle        = "ca_bundle"

	envVarAccessKeyID     = "AWS_ACCESS_KEY_ID"
	envVarSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	envVarCABundle        = "AWS_CA_BUNDLE"
)
