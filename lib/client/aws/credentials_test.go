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
	"bytes"
	"context"
	"crypto/x509/pkix"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	sdkv2http "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	sdkv2config "github.com/aws/aws-sdk-go-v2/config"
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
	config := &CredentialsConfig{
		AccessKeyID:       "access-id",
		SecretAccessKey:   "secret",
		CustomCABundePath: caFilePath,
	}
	require.NoError(t, config.CheckAndSetDefaults())

	// Prepare two certs in CA bundle file. One is not expired.
	entity := pkix.Name{CommonName: "credentials-ut", Organization: []string{"test"}}

	_, certPem, err := tlsca.GenerateSelfSignedCA(entity, []string{"localhost"}, time.Hour)
	require.NoError(t, err)
	_, expiredCertPem, err := tlsca.GenerateSelfSignedCA(entity, []string{"localhost"}, -time.Hour)
	require.NoError(t, err)

	pems := bytes.Join([][]byte{expiredCertPem, certPem}, []byte("\n"))
	require.NoError(t, os.WriteFile(caFilePath, pems, 0600))

	// Unset some environment variables.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_CA_BUNDLE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")

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
		t.Run("success", func(t *testing.T) {
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
		})

		t.Run("profile not found", func(t *testing.T) {
			_, err := LoadCredentialsFile(credFilePath, "missing_profile")
			require.True(t, trace.IsNotFound(err))
		})

		t.Run("path not found", func(t *testing.T) {
			_, err := LoadCredentialsFile("missing_file", defaultProfile)
			require.True(t, trace.IsNotFound(err))
		})
	})

	t.Run("AWS environment variables compatible", func(t *testing.T) {
		credProvider, err := LoadCredentialsFile(credFilePath, defaultProfile)
		require.NoError(t, err)

		// Use t.Setenv
		credProvider.Setenv = func(key, value string) error {
			t.Setenv(key, value)
			return nil
		}

		err = credProvider.SetEnvironmentVariables()
		require.NoError(t, err)

		t.Run("aws-sdk-go", func(t *testing.T) {
			compatiableWithAWSSDK(t, config, entity, session.Options{})
		})

		t.Run("aws-sdk-go-v2", func(t *testing.T) {
			compatiableWithAWSSDKV2(t, config, entity)
		})
	})

	t.Run("AWS shared credentials file compatible", func(t *testing.T) {
		t.Run("aws-sdk-go", func(t *testing.T) {
			// Shared credentials file can also be set through environment
			// variable "AWS_SHARED_CREDENTIALS_FILE".
			compatiableWithAWSSDK(t, config, entity, session.Options{
				SharedConfigFiles: []string{credFilePath},
			})
		})

		t.Run("aws-sdk-go-v2", func(t *testing.T) {
			// Shared credentials file can also be set through environment
			// variable "AWS_SHARED_CREDENTIALS_FILE".
			// "ca_bundle" in shared credentials file is not currently
			// supported in aws-sdk-go-v2. Needs to configure custom CA bundle
			// through options or environment variable "AWS_CA_BUNDLE".
			compatiableWithAWSSDKV2(t, config, entity,
				sdkv2config.WithSharedCredentialsFiles([]string{credFilePath}),
				sdkv2config.WithCustomCABundle(bytes.NewReader(pems)),
			)
		})
	})
}

func compatiableWithAWSSDK(t *testing.T, expectedCredentials *CredentialsConfig, certEntity pkix.Name, options session.Options) {
	t.Helper()

	session, err := session.NewSessionWithOptions(options)
	require.NoError(t, err)

	// Verify access key and secret.
	credValue, err := session.Config.Credentials.Get()
	require.NoError(t, err)
	require.Equal(t, expectedCredentials.AccessKeyID, credValue.AccessKeyID)
	require.Equal(t, expectedCredentials.SecretAccessKey, credValue.SecretAccessKey)

	// Verify CA bundle.
	transport, ok := session.Config.HTTPClient.Transport.(*http.Transport)
	require.True(t, ok)

	verifyTransportWithRootCAs(t, transport, certEntity)
}

func compatiableWithAWSSDKV2(t *testing.T, expectedCredentials *CredentialsConfig, certEntity pkix.Name, optFns ...func(*sdkv2config.LoadOptions) error) {
	t.Helper()

	config, err := sdkv2config.LoadDefaultConfig(context.TODO(), optFns...)
	require.NoError(t, err)

	// Verify access key and secret.
	retrievedCredentials, err := config.Credentials.Retrieve(context.TODO())
	require.NoError(t, err)

	require.Equal(t, expectedCredentials.AccessKeyID, retrievedCredentials.AccessKeyID)
	require.Equal(t, expectedCredentials.SecretAccessKey, retrievedCredentials.SecretAccessKey)

	// Verify CA bundle.
	client, ok := config.HTTPClient.(*sdkv2http.BuildableClient)
	require.True(t, ok)
	verifyTransportWithRootCAs(t, client.GetTransport(), certEntity)
}

func verifyTransportWithRootCAs(t *testing.T, transport *http.Transport, certEntity pkix.Name) {
	t.Helper()

	require.NotNil(t, transport)
	require.NotNil(t, transport.TLSClientConfig)
	require.NotNil(t, transport.TLSClientConfig.RootCAs)

	subjects := transport.TLSClientConfig.RootCAs.Subjects()
	require.Greater(t, len(subjects), 0)
	for _, subject := range subjects {
		require.Contains(t, string(subject), certEntity.CommonName)
	}
}
