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

package config

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/coreos/go-semver/semver"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/tool/tbot/identity"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// TemplateSSHClient contains parameters for the ssh_config config
// template
type TemplateSSHClient struct {
	ProxyPort uint16 `yaml:"proxy_port"`
}

// openSSHVersionRegex is a regex used to parse OpenSSH version strings.
var openSSHVersionRegex = regexp.MustCompile(`^OpenSSH_(?P<major>\d+)\.(?P<minor>\d+)(?:p(?P<patch>\d+))?`)

// openSSHMinVersionForRSAWorkaround is the OpenSSH version after which the
// RSA deprecation workaround should be added to generated ssh_config.
var openSSHMinVersionForRSAWorkaround = semver.New("8.5.0")

const (
	// sshConfigName is the name of the ssh_config file on disk
	sshConfigName = "ssh_config"

	// knownHostsName is the name of the known_hosts file on disk
	knownHostsName = "known_hosts"
)

// parseSSHVersion attempts to parse the local SSH version, used to determine
// certain config template parameters for client version compatibility.
func parseSSHVersion(versionString string) (*semver.Version, error) {
	versionTokens := strings.Split(versionString, " ")
	if len(versionTokens) == 0 {
		return nil, trace.BadParameter("invalid version string: %s", versionString)
	}

	versionID := versionTokens[0]
	matches := openSSHVersionRegex.FindStringSubmatch(versionID)
	if matches == nil {
		return nil, trace.BadParameter("cannot parse version string: %q", versionID)
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, trace.Wrap(err, "invalid major version number: %s", matches[1])
	}

	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil, trace.Wrap(err, "invalid minor version number: %s", matches[2])
	}

	patch := 0
	if matches[3] != "" {
		patch, err = strconv.Atoi(matches[3])
		if err != nil {
			return nil, trace.Wrap(err, "invalid patch version number: %s", matches[3])
		}
	}

	return &semver.Version{
		Major: int64(major),
		Minor: int64(minor),
		Patch: int64(patch),
	}, nil
}

// getSSHVersion attempts to query the system SSH for its current version.
func getSSHVersion() (*semver.Version, error) {
	var out bytes.Buffer

	cmd := exec.Command("ssh", "-V")
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return parseSSHVersion(out.String())
}

func (c *TemplateSSHClient) CheckAndSetDefaults() error {
	if c.ProxyPort == 0 {
		c.ProxyPort = defaults.SSHProxyListenPort
	}
	return nil
}

func (c *TemplateSSHClient) Name() string {
	return TemplateSSHClientName
}

func (c *TemplateSSHClient) Describe() []FileDescription {
	return []FileDescription{
		{
			Name: "ssh_config",
		},
		{
			Name: "known_hosts",
		},
	}
}

func (c *TemplateSSHClient) Render(ctx context.Context, authClient auth.ClientI, currentIdentity *identity.Identity, destination *DestinationConfig) error {
	dest, err := destination.GetDestination()
	if err != nil {
		return trace.Wrap(err)
	}

	clusterName, err := authClient.GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}

	ping, err := authClient.Ping(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	proxyHost, _, err := utils.SplitHostPort(ping.ProxyPublicAddr)
	if err != nil {
		return trace.BadParameter("proxy %+v has no usable public address: %v", ping.ProxyPublicAddr, err)
	}

	// TODO: ideally it'd be nice to fetch this dynamically
	// TODO: eventually we could consider including `tsh proxy`
	// functionality and sidestep this entirely.
	proxyPort := strconv.Itoa(int(c.ProxyPort))

	// Backend note: Prefer to use absolute paths for filesystem backends.
	// If the backend is something else, use "". ssh_config will generate with
	// paths relative to the destination. This doesn't work with ssh in
	// practice so adjusting the config for impossible-to-determine-in-advance
	// destination backends is left as an exercise to the user.
	var dataDir string
	if dir, ok := dest.(*DestinationDirectory); ok {
		dataDir, err = filepath.Abs(dir.Path)
		if err != nil {
			return trace.Wrap(err)
		}
	} else {
		dataDir = ""
	}

	knownHosts, err := fetchKnownHosts(ctx, authClient, clusterName.GetClusterName(), proxyHost)
	if err != nil {
		return trace.Wrap(err)
	}

	knownHostsPath := filepath.Join(dataDir, knownHostsName)
	if err := dest.Write(knownHostsName, []byte(knownHosts)); err != nil {
		return trace.Wrap(err)
	}

	// Default to including the RSA deprecation workaround.
	rsaWorkaround := true
	version, err := getSSHVersion()
	if err != nil {
		log.WithError(err).Debugf("Could not determine SSH version, will include RSA workaround.")
	} else if version.LessThan(*openSSHMinVersionForRSAWorkaround) {
		log.Debugf("OpenSSH version %s does not require workaround for RSA deprecation", version)
		rsaWorkaround = false
	} else {
		log.Debugf("OpenSSH version %s will use workaround for RSA deprecation", version)
	}

	var sshConfigBuilder strings.Builder
	identityFilePath := filepath.Join(dataDir, identity.PrivateKeyKey)
	certificateFilePath := filepath.Join(dataDir, identity.SSHCertKey)
	sshConfigPath := filepath.Join(dataDir, sshConfigName)
	if err := sshConfigTemplate.Execute(&sshConfigBuilder, sshConfigParameters{
		ClusterName:          clusterName.GetClusterName(),
		ProxyHost:            proxyHost,
		ProxyPort:            proxyPort,
		KnownHostsPath:       knownHostsPath,
		IdentityFilePath:     identityFilePath,
		CertificateFilePath:  certificateFilePath,
		SSHConfigPath:        sshConfigPath,
		IncludeRSAWorkaround: rsaWorkaround,
	}); err != nil {
		return trace.Wrap(err)
	}

	if err := dest.Write(sshConfigName, []byte(sshConfigBuilder.String())); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

type sshConfigParameters struct {
	ClusterName         string
	KnownHostsPath      string
	IdentityFilePath    string
	CertificateFilePath string
	ProxyHost           string
	ProxyPort           string
	SSHConfigPath       string

	// IncludeRSAWorkaround controls whether the RSA deprecation workaround is
	// included in the generated configuration. Newer versions of OpenSSH
	// deprecate RSA certificates and, due to a bug in golang's ssh package,
	// Teleport wrongly advertises its unaffected certificates as a
	// now-deprecated certificate type. The workaround includes a config
	// override to re-enable RSA certs for just Teleport hosts, however it is
	// only supported on OpenSSH 8.5 and later.
	IncludeRSAWorkaround bool
}

var sshConfigTemplate = template.Must(template.New("ssh-config").Parse(`
# Begin generated Teleport configuration for {{ .ProxyHost }} from tbot config

# Common flags for all {{ .ClusterName }} hosts
Host *.{{ .ClusterName }} {{ .ProxyHost }}
    UserKnownHostsFile "{{ .KnownHostsPath }}"
    IdentityFile "{{ .IdentityFilePath }}"
    CertificateFile "{{ .CertificateFilePath }}"
    HostKeyAlgorithms ssh-rsa-cert-v01@openssh.com{{- if .IncludeRSAWorkaround }}
    PubkeyAcceptedAlgorithms +ssh-rsa-cert-v01@openssh.com{{- end }}

# Flags for all {{ .ClusterName }} hosts except the proxy
Host *.{{ .ClusterName }} !{{ .ProxyHost }}
    Port 3022
    ProxyCommand ssh -F {{ .SSHConfigPath }} -l %r -p {{ .ProxyPort }} {{ .ProxyHost }} -s proxy:$(echo %h | cut -d '.' -f 1):%p@{{ .ClusterName }}

# End generated Teleport configuration
`))

func fetchKnownHosts(ctx context.Context, client auth.ClientI, clusterName, proxyHosts string) (string, error) {
	ca, err := client.GetCertAuthority(ctx, types.CertAuthID{
		Type:       types.HostCA,
		DomainName: clusterName,
	}, false)
	if err != nil {
		return "", trace.Wrap(err)
	}

	var sb strings.Builder
	for _, auth := range auth.AuthoritiesToTrustedCerts([]types.CertAuthority{ca}) {
		pubKeys, err := auth.SSHCertPublicKeys()
		if err != nil {
			return "", trace.Wrap(err)
		}

		for _, pubKey := range pubKeys {
			bytes := ssh.MarshalAuthorizedKey(pubKey)
			sb.WriteString(fmt.Sprintf(
				"@cert-authority %s,%s,*.%s %s type=host",
				proxyHosts, auth.ClusterName, auth.ClusterName, strings.TrimSpace(string(bytes)),
			))
		}
	}

	return sb.String(), nil
}
