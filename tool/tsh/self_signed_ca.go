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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"time"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// getSelfSignedLocalCert loads a self-signed local cert for the specified app,
// or creates one if local cert does not exist or is expired.
func getSelfSignedLocalCert(profile *client.ProfileStatus, appName string, notAfter time.time) (tls.Certificate, error) {
	keyPath := profile.KeyPath()
	caPath := profile.AppLocalhostCAPath(appName)

	if utils.FileExists(caPath) {
		cert, err := loadSelfSignedLocalCert(caPath, keyPath, notAfter)
		if err == nil {
			return cert, nil
		}

		// Fallthrough to generate new ones.
		log.WithError(err).Debugf("Failed to load self signed certificates from %v.", caPath)
	}

	return newSelfSignedLocalCert(caPath, keyPath, notAfter)
}

// loadSelfSignedLocalCert loads cert and key pair from specified path and
// verifies its expiry.
func loadSelfSignedLocalCert(caPath, keyPath string, expectedNotAfter time.Time) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(caPath, keyPath)
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

	if x509cert.NotAfter.Sub(expectedNotAfter) {
		return tls.Certificate{}, trace.BadParameter("")
	}
	return cert, nil
}

// newSelfSignedLocalCert generates new self signed local cert.
func newSelfSignedLocalCert(caPath, keyPath string, notAfter time.Time) (tls.Certificate, error) {
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
