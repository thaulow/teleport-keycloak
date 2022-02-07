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
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/trace"
)

func TestCredentialsFileProvider(t *testing.T) {
	tempDir := t.TempDir()
	credFilePath := path.Join(tempDir, "credentials")
	caFilePath := path.Join(tempDir, "ca.pem")
	config := &CredentialsFileConfig{
		AccessKeyID:       "access-id",
		SecretAccessKey:   "secret",
		CustomCABundePath: caFilePath,
	}

	entity := pkix.Name{CommonName: "credentials-ut", Organization: []string{"test"}}
	_, certPem, err := tlsca.GenerateSelfSignedCA(entity, []string{"localhost"}, time.Hour)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(caFilePath, certPem, 0600))

	t.Run("SaveCredentialsFile", func(t *testing.T) {
		credProvider, err := SaveCredentialsFile(config, credFilePath)
		require.NoError(t, err)

		credValue, err := credProvider.Retrieve()
		require.NoError(t, err)
		require.Equal(t, credentials.Value{
			AccessKeyID:     "access-id",
			SecretAccessKey: "secret",
			ProviderName:    "teleport",
		}, credValue)
	})

	t.Run("LoadCredentialsFile", func(t *testing.T) {
		credProvider, err := LoadCredentialsFile(credFilePath, defaultProfile)
		require.NoError(t, err)

		require.False(t, credProvider.IsExpired())
		require.Equal(t, config.CustomCABundePath, credProvider.CustomCABundePath)

		credValue, err := credProvider.Retrieve()
		require.NoError(t, err)
		require.Equal(t, credentials.Value{
			AccessKeyID:     "access-id",
			SecretAccessKey: "secret",
			ProviderName:    "teleport",
		}, credValue)

		envVars := credProvider.GetEnvironmentVariables()
		require.Equal(t, map[string]string{
			"AWS_ACCESS_KEY_ID":     "access-id",
			"AWS_SECRET_ACCESS_KEY": "secret",
			"AWS_CA_BUNDLE":         caFilePath,
		}, envVars)
	})

	t.Run("LoadCredentialsFile profile not found", func(t *testing.T) {
		_, err := LoadCredentialsFile(credFilePath, "missing_profile")
		require.True(t, trace.IsNotFound(err))
	})

	t.Run("LoadCredentialsFile path not found", func(t *testing.T) {
		_, err := LoadCredentialsFile("missing_file", defaultProfile)
		require.True(t, trace.IsNotFound(err))
	})

	t.Run("compatible with AWS_SHARED_CREDENTIALS_FILE", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "")
		t.Setenv("AWS_CA_BUNDLE", "")
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credFilePath)
		t.Setenv("AWS_SDK_LOAD_CONFIG", "true")

		session := session.New()

		credValue, err := session.Config.Credentials.Get()
		require.NoError(t, err)
		require.Equal(t, credentials.Value{
			AccessKeyID:     "access-id",
			SecretAccessKey: "secret",
			ProviderName:    fmt.Sprintf("SharedConfigCredentials: %s", credFilePath),
		}, credValue)

		transport, ok := session.Config.HTTPClient.Transport.(*http.Transport)
		require.True(t, ok)

		require.Len(t, transport.TLSClientConfig.RootCAs.Subjects(), 1)
		require.Contains(t, string(transport.TLSClientConfig.RootCAs.Subjects()[0]), entity.CommonName)
	})
}
