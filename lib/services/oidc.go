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

package services

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
)

// ValidateOIDCConnector validates the OIDC connector and sets default values
func ValidateOIDCConnector(oc types.OIDCConnector) error {
	if err := oc.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if _, err := url.Parse(oc.GetIssuerURL()); err != nil {
		return trace.BadParameter("IssuerURL: bad url: '%v'", oc.GetIssuerURL())
	}
	for _, redirectURL := range oc.GetRedirectURLs() {
		if _, err := url.Parse(redirectURL); err != nil {
			return trace.BadParameter("RedirectURL: bad url: '%v'", redirectURL)
		}

	}
	if oc.GetGoogleServiceAccountURI() != "" && oc.GetGoogleServiceAccount() != "" {
		return trace.BadParameter("one of either google_service_account_uri or google_service_account is supported, not both")
	}

	if oc.GetGoogleServiceAccountURI() != "" {
		uri, err := utils.ParseSessionsURI(oc.GetGoogleServiceAccountURI())
		if err != nil {
			return trace.Wrap(err)
		}
		if uri.Scheme != teleport.SchemeFile {
			return trace.BadParameter("only %v:// scheme is supported for google_service_account_uri", teleport.SchemeFile)
		}
		if oc.GetGoogleAdminEmail() == "" {
			return trace.BadParameter("whenever google_service_account_uri is specified, google_admin_email should be set as well, read https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority for more details")
		}
	}
	if oc.GetGoogleServiceAccount() != "" {
		if oc.GetGoogleAdminEmail() == "" {
			return trace.BadParameter("whenever google_service_account is specified, google_admin_email should be set as well, read https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority for more details")
		}
	}
	return nil
}

// GetClaimNames returns a list of claim names from the claim values
func GetClaimNames(claims jose.Claims) []string {
	var out []string
	for claim := range claims {
		out = append(out, claim)
	}
	return out
}

// OIDCClaimsToTraits converts OIDC-style claims into teleport-specific trait format
func OIDCClaimsToTraits(claims jose.Claims) map[string][]string {
	traits := make(map[string][]string)

	for claimName := range claims {
		claimValue, ok, _ := claims.StringClaim(claimName)
		if ok {
			traits[claimName] = []string{claimValue}
		}
		claimValues, ok, _ := claims.StringsClaim(claimName)
		if ok {
			traits[claimName] = claimValues
		}
	}

	return traits
}

// GetOIDCClient creates a new OIDC client for the given OIDC connector and proxy addr.
func GetOIDCClient(ctx context.Context, conn types.OIDCConnector, proxyAddr string) (*oidc.Client, error) {
	client, err := oidc.NewClient(oidc.ClientConfig{
		RedirectURL: GetRedirectURL(conn, proxyAddr),
		Credentials: oidc.ClientCredentials{
			ID:     conn.GetClientID(),
			Secret: conn.GetClientSecret(),
		},
		// open id notifies provider that we are using OIDC scopes
		Scope: apiutils.Deduplicate(append([]string{"openid", "email"}, conn.GetScope()...)),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	doneSyncing := make(chan struct{})
	go func() {
		defer close(doneSyncing)
		client.SyncProviderConfig(conn.GetIssuerURL())
	}()

	select {
	case <-doneSyncing:
	case <-time.After(defaults.WebHeadersTimeout):
		return nil, trace.ConnectionProblem(nil,
			"timed out syncing oidc connector %v, ensure URL %q is valid and accessible and check configuration",
			conn.GetName(), conn.GetIssuerURL())
	case <-ctx.Done():
		return nil, trace.ConnectionProblem(nil, "auth server is shutting down")
	}

	return client, nil
}

// GetRedirectURL gets a redirect URL for the given connector. If the connector
// has a redirect URL which matches the host of the given Proxy address, then
// that one will be returned. Otherwise, the first URL in the list will be returned.
func GetRedirectURL(conn types.OIDCConnector, proxyAddr string) string {
	if len(conn.GetRedirectURLs()) == 0 {
		return ""
	}

	for _, redirectURL := range conn.GetRedirectURLs() {
		if strings.Contains(redirectURL, proxyAddr) {
			return redirectURL
		}
	}

	return conn.GetRedirectURLs()[0]
}

// UnmarshalOIDCConnector unmarshals the OIDCConnector resource from JSON.
func UnmarshalOIDCConnector(bytes []byte, opts ...MarshalOption) (types.OIDCConnector, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var h types.ResourceHeader
	err = utils.FastUnmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	// V2 and V3 have the same layout, the only change is in the behavior
	case types.V2, types.V3:
		var c types.OIDCConnectorV3
		if err := utils.FastUnmarshal(bytes, &c); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
		if err := ValidateOIDCConnector(&c); err != nil {
			return nil, trace.Wrap(err)
		}
		if cfg.ID != 0 {
			c.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			c.SetExpiry(cfg.Expires)
		}
		return &c, nil
	}

	return nil, trace.BadParameter("OIDC connector resource version %v is not supported", h.Version)
}

// MarshalOIDCConnector marshals the OIDCConnector resource to JSON.
func MarshalOIDCConnector(oidcConnector types.OIDCConnector, opts ...MarshalOption) ([]byte, error) {
	if err := ValidateOIDCConnector(oidcConnector); err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch oidcConnector := oidcConnector.(type) {
	case *types.OIDCConnectorV3:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *oidcConnector
			copy.SetResourceID(0)
			oidcConnector = &copy
		}
		return utils.FastMarshal(oidcConnector)
	default:
		return nil, trace.BadParameter("unrecognized OIDC connector version %T", oidcConnector)
	}
}
