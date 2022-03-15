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

package alpnproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/srv/alpnproxy/common"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/aws"
)

// LocalProxy allows upgrading incoming connection to TLS where custom TLS values are set SNI ALPN and
// updated connection is forwarded to remote ALPN SNI teleport proxy service.
type LocalProxy struct {
	cfg     LocalProxyConfig
	context context.Context
	cancel  context.CancelFunc
}

// LocalProxyConfig is configuration for LocalProxy.
type LocalProxyConfig struct {
	// RemoteProxyAddr is the downstream destination address of remote ALPN proxy service.
	RemoteProxyAddr string
	// Protocol set for the upstream TLS connection.
	Protocol common.Protocol
	// InsecureSkipTLSVerify turns off verification for x509 upstream ALPN proxy service certificate.
	InsecureSkipVerify bool
	// Listener is listener running on local machine.
	Listener net.Listener
	// SNI is a ServerName value set for upstream TLS connection.
	SNI string
	// ParentContext is a parent context, used to signal global closure>
	ParentContext context.Context
	// SSHUser is a SSH user name.
	SSHUser string
	// SSHUserHost is user host requested by ssh subsystem.
	SSHUserHost string
	// SSHHostKeyCallback is the function type used for verifying server keys.
	SSHHostKeyCallback ssh.HostKeyCallback
	// SSHTrustedCluster allows selecting trusted cluster ssh subsystem request.
	SSHTrustedCluster string
	// ClientTLSConfig is a client TLS configuration used during establishing
	// connection to the RemoteProxyAddr.
	ClientTLSConfig *tls.Config
	// Certs are the client certificates used to connect to the remote Teleport Proxy.
	Certs []tls.Certificate
	// AWSCredentials are AWS Credentials used by LocalProxy for request's signature verification.
	AWSCredentials *credentials.Credentials
}

// CheckAndSetDefaults verifies the constraints for LocalProxyConfig.
func (cfg *LocalProxyConfig) CheckAndSetDefaults() error {
	if cfg.RemoteProxyAddr == "" {
		return trace.BadParameter("missing remote proxy address")
	}
	if cfg.Protocol == "" {
		return trace.BadParameter("missing protocol")
	}
	if cfg.ParentContext == nil {
		return trace.BadParameter("missing parent context")
	}
	return nil
}

// NewLocalProxy creates a new instance of LocalProxy.
func NewLocalProxy(cfg LocalProxyConfig) (*LocalProxy, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(cfg.ParentContext)
	return &LocalProxy{
		cfg:     cfg,
		context: ctx,
		cancel:  cancel,
	}, nil
}

// SSHProxy is equivalent of `ssh -o 'ForwardAgent yes' -p port  %r@host -s proxy:%h:%p` but established SSH
// connection to RemoteProxyAddr is wrapped with TLS protocol.
func (l *LocalProxy) SSHProxy(localAgent *client.LocalKeyAgent) error {
	if l.cfg.ClientTLSConfig == nil {
		return trace.BadParameter("client TLS config is missing")
	}

	clientTLSConfig := l.cfg.ClientTLSConfig.Clone()
	clientTLSConfig.NextProtos = []string{string(l.cfg.Protocol)}
	clientTLSConfig.InsecureSkipVerify = l.cfg.InsecureSkipVerify
	clientTLSConfig.ServerName = l.cfg.SNI

	upstreamConn, err := tls.Dial("tcp", l.cfg.RemoteProxyAddr, clientTLSConfig)
	if err != nil {
		return trace.Wrap(err)
	}
	defer upstreamConn.Close()

	client, err := makeSSHClient(upstreamConn, l.cfg.RemoteProxyAddr, &ssh.ClientConfig{
		User: l.cfg.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(localAgent.Signers),
		},
		HostKeyCallback: l.cfg.SSHHostKeyCallback,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return trace.Wrap(err)
	}
	defer sess.Close()

	err = agent.ForwardToAgent(client, localAgent)
	if err != nil {
		return trace.Wrap(err)
	}
	err = agent.RequestAgentForwarding(sess)
	if err != nil {
		return trace.Wrap(err)
	}

	if err = sess.RequestSubsystem(proxySubsystemName(l.cfg.SSHUserHost, l.cfg.SSHTrustedCluster)); err != nil {
		return trace.Wrap(err)
	}
	if err := proxySession(l.context, sess); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func proxySubsystemName(userHost, cluster string) string {
	subsystem := fmt.Sprintf("proxy:%s", userHost)
	if cluster != "" {
		subsystem = fmt.Sprintf("%s@%s", subsystem, cluster)
	}
	return subsystem
}

func makeSSHClient(conn *tls.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	cc, chs, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ssh.NewClient(cc, chs, reqs), nil
}

func proxySession(ctx context.Context, sess *ssh.Session) error {
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	errC := make(chan error)
	go func() {
		defer sess.Close()
		_, err := io.Copy(os.Stdout, stdout)
		errC <- err
	}()
	go func() {
		defer sess.Close()
		_, err := io.Copy(stdin, os.Stdin)
		errC <- err
	}()
	go func() {
		defer sess.Close()
		_, err := io.Copy(os.Stderr, stderr)
		errC <- err
	}()
	var errs []error
	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errC:
			if err != nil && !utils.IsOKNetworkError(err) {
				errs = append(errs, err)
			}
		}
	}
	return trace.NewAggregate(errs...)
}

// Start starts the LocalProxy.
func (l *LocalProxy) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := l.cfg.Listener.Accept()
		if err != nil {
			if utils.IsOKNetworkError(err) {
				return nil
			}
			log.WithError(err).Errorf("Faield to accept client connection.")
			return trace.Wrap(err)
		}
		go func() {
			if err := l.handleDownstreamConnection(ctx, conn, l.cfg.SNI); err != nil {
				if utils.IsOKNetworkError(err) {
					return
				}
				log.WithError(err).Errorf("Failed to handle connection.")
			}
		}()
	}
}

// GetAddr returns the LocalProxy listener address.
func (l *LocalProxy) GetAddr() string {
	return l.cfg.Listener.Addr().String()
}

// handleDownstreamConnection proxies the downstreamConn (connection established to the local proxy) and forward the
// traffic to the upstreamConn (TLS connection to remote host).
func (l *LocalProxy) handleDownstreamConnection(ctx context.Context, downstreamConn net.Conn, serverName string) error {
	defer downstreamConn.Close()
	upstreamConn, err := tls.Dial("tcp", l.cfg.RemoteProxyAddr, &tls.Config{
		NextProtos:         []string{string(l.cfg.Protocol)},
		InsecureSkipVerify: l.cfg.InsecureSkipVerify,
		ServerName:         serverName,
		Certificates:       l.cfg.Certs,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer upstreamConn.Close()

	errC := make(chan error, 2)
	go func() {
		defer downstreamConn.Close()
		defer upstreamConn.Close()
		_, err := io.Copy(downstreamConn, upstreamConn)
		errC <- err
	}()
	go func() {
		defer downstreamConn.Close()
		defer upstreamConn.Close()
		_, err := io.Copy(upstreamConn, downstreamConn)
		errC <- err
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return trace.NewAggregate(append(errs, ctx.Err())...)
		case err := <-errC:
			if err != nil && !utils.IsOKNetworkError(err) {
				errs = append(errs, err)
			}
		}
	}
	return trace.NewAggregate(errs...)
}

func (l *LocalProxy) Close() error {
	l.cancel()
	if l.cfg.Listener != nil {
		if err := l.cfg.Listener.Close(); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// StartAWSAccessProxy starts the local AWS CLI proxy.
func (l *LocalProxy) StartAWSAccessProxy(ctx context.Context) error {
	err := http.Serve(l.cfg.Listener, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method == "CONNECT" {
			l.handleForwardProxy(rw, req)
			return
		}

		l.handleAWSRequest(rw, req)
	}))
	if err != nil && !utils.IsUseOfClosedNetworkError(err) {
		return trace.Wrap(err)
	}
	return nil
}

// handleAWSRequest is a HTTP handler that reverse-proxies an AWS request.
func (l *LocalProxy) handleAWSRequest(rw http.ResponseWriter, req *http.Request) {
	if err := aws.VerifyAWSSignature(req, l.cfg.AWSCredentials); err != nil {
		log.WithError(err).Errorf("AWS signature verification failed.")
		// TODO(greedy52) format a proper AWS XML error.
		rw.Write([]byte(err.Error()))
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos:         []string{string(l.cfg.Protocol)},
			InsecureSkipVerify: l.cfg.InsecureSkipVerify,
			ServerName:         l.cfg.SNI,
			Certificates:       l.cfg.Certs,
		},
	}

	proxy := &httputil.ReverseProxy{
		Director: func(outReq *http.Request) {
			outReq.URL.Scheme = "https"
			outReq.URL.Host = l.cfg.RemoteProxyAddr
		},
		Transport: tr,
	}

	// Note that ReverseProxy automatically adds "X-Forwarded-Host" header.
	proxy.ServeHTTP(rw, req)
}

// handleForwardProxy handles CONNECT tunnel requests from clients.
//
// ┌──────┐1.CONNECT┌─────┐         ┌────────┐
// │      ├────────►│local├────────►│teleport│
// │client│         │     │3.reverse│        │
// │      │   ┌─────┤proxy│  proxy  │ proxy  │
// └──────┘   │     └─────┘         └────────┘
//            │        ▲
//            └────────┘
//            2.forward
//              proxy
//
// The forward proxy process goes like this:
// 1a. Client sends a request (e.g. GET https://s3.us-east-1.amazonaws.com)
//     with HTTPS_PROXY=https://localhost:<local-proxy-port>.
// 1b. Local proxy first recevies a CONNECT request from the client connection.
//     It then prepares a TLS certificate for the requested hostname. Then, the
//     local proxy creates a 2nd connection to itself for tunneling the data.
//     Once ready, the local proxy sends back a 200 to the client to let it
//     know that it can start sending data.
// 2a. Client sends the normal HTTPS request through the 1st connection.
// 2b. Local proxy forwards all data received from the 1st connection to the
//     2nd connection.
// 2c. Local proxy serves the HTTPS request from the 2nd connection using the
//     newly generated certficate.
// 3a. Local proxy adds the hostname (e.g. s3.us-east-1.amazonaws.com) to
//     "X-Forwarded-Host" header then revere proxies the request to the
//     Teleport server.
// 3b. The response traverses through the 2nd connection then to the 1st
//     connection back to the client.
//
// Ideally the 2nd-connection-to-itself is not required if we can decrypt the
// client connection directly. However, many "net/http" functionalities are
// private (e.g. http.conn.serve) for handling a raw connection so it is much
// easier to forward back to itself.
func (l *LocalProxy) handleForwardProxy(rw http.ResponseWriter, req *http.Request) {
	// Hijack client connection.
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		log.Warn("Failed to hijack client connection from HTTP request.")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	clientConn, _, _ := hijacker.Hijack()
	if clientConn == nil {
		log.Warn("Failed to hijack client connection from HTTP request.")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Create a server connection back to our local proxy.
	serverConn, err := net.Dial("tcp", l.cfg.Listener.Addr().String())
	if err != nil {
		log.WithError(err).Warn("Failed to establish connection to local proxy.")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer serverConn.Close()

	// Generate a certificate for the requested host.
	if listener, ok := l.cfg.Listener.(*HTTPSForwardProxyListener); ok {
		listener.AddHost(req.Host)
	}

	// Let client know we are ready for proxying.
	clientConn.Write([]byte(fmt.Sprintf("%v 200 OK\r\n\r\n", req.Proto)))

	// Stream everything from client to local proxy.
	log.Debugf("Forward proxying for %v", req.Host)

	wg := &sync.WaitGroup{}
	wg.Add(2)
	stream := func(reader, writer net.Conn) {
		_, _ = io.Copy(reader, writer)
		if readerConn, ok := reader.(*net.TCPConn); ok {
			readerConn.CloseRead()
		}
		if writerConn, ok := writer.(*net.TCPConn); ok {
			writerConn.CloseWrite()
		}
		wg.Done()
	}
	go stream(clientConn, serverConn)
	go stream(serverConn, clientConn)
	wg.Wait()
}

// HTTPSForwardProxyListener is a TLS listener that can generate certificates
// using provided CA then serve forwarded HTTPS requests, when clients using
// HTTPS_PROXY.
type HTTPSForwardProxyListener struct {
	net.Listener

	ca                 tls.Certificate
	mu                 sync.RWMutex
	certificatesByHost map[string]*tls.Certificate
}

// NewHTTPSFowardProxyListener creates a new HTTPSForwardProxyListener.
func NewHTTPSFowardProxyListener(listenAddr string, ca tls.Certificate) (l *HTTPSForwardProxyListener, err error) {
	l = &HTTPSForwardProxyListener{
		ca:                 ca,
		certificatesByHost: make(map[string]*tls.Certificate),
	}

	tlsConfig := &tls.Config{
		GetCertificate: l.GetCertificate,
	}

	if l.Listener, err = tls.Listen("tcp", listenAddr, tlsConfig); err != nil {
		return nil, trace.Wrap(err)
	}
	return l, nil
}

// GetCertificate return TLS certificate based on SNI. Implements
// GetCertificate of tls.Config.
func (l *HTTPSForwardProxyListener) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if cert, found := l.certificatesByHost[clientHello.ServerName]; found {
		return cert, nil
	}

	return &l.ca, nil
}

// AddHost generates a new certificate for the specified host.
func (l *HTTPSForwardProxyListener) AddHost(host string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Remove port.
	addr, err := utils.ParseAddr(host)
	if err != nil {
		return trace.Wrap(err)
	}
	host = addr.Host()

	if _, found := l.certificatesByHost[host]; found {
		return nil
	}

	cert, err := tlsca.GenerateAndSignCertificateForDomain(host, l.ca)
	if err != nil {
		return trace.Wrap(err)
	}

	log.Debugf("Self-signed certificate generated for %v", host)
	l.certificatesByHost[host] = cert
	return nil
}
