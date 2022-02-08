/*
Copyright 2015 Gravitational, Inc.

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

package utils

import (
	"bytes"
	"crypto/x509/pkix"
	"io/ioutil"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

func TestCertificateChain(t *testing.T) {
	t.Run("rejects invalid PEMd data", func(t *testing.T) {
		_, err := ReadCertificateChain([]byte("no data"))
		require.True(t, trace.IsNotFound(err))
	})

	t.Run("rejects self-signed certificate", func(t *testing.T) {
		certificateChainBytes, err := ioutil.ReadFile("../../fixtures/certs/ca.pem")
		require.NoError(t, err)

		certificateChain, err := ReadCertificateChain(certificateChainBytes)
		require.NoError(t, err)

		err = VerifyCertificateChain(certificateChain)
		require.Error(t, err)
		require.Equal(t, err.Error(), "x509: certificate signed by unknown authority")
	})
}

func TestReadCertificates(t *testing.T) {
	_, certPem1, err := GenerateSelfSignedSigningCert(pkix.Name{
		CommonName: "cert1",
	}, []string{"localhost"}, time.Hour)
	require.NoError(t, err)

	_, certPem2, err := GenerateSelfSignedSigningCert(pkix.Name{
		CommonName: "cert2",
	}, []string{"localhost"}, time.Hour)
	require.NoError(t, err)

	bundleBytes := bytes.Join([][]byte{certPem1, certPem2}, []byte("\n"))

	x509certs, err := ReadCertificates(bundleBytes)
	require.NoError(t, err)
	require.Len(t, x509certs, 2)
	require.Equal(t, "cert1", x509certs[0].Issuer.CommonName)
	require.Equal(t, "cert2", x509certs[1].Issuer.CommonName)
}
