/*
Copyright 2017 Gravitational, Inc.

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
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// NewLoadBalancer returns new load balancer listening on frontend
// and redirecting requests to backends using round robin algo
func NewLoadBalancer(ctx context.Context, frontend NetAddr, backends ...NetAddr) (*LoadBalancer, error) {
	if ctx == nil {
		return nil, trace.BadParameter("missing parameter context")
	}
	waitCtx, waitCancel := context.WithCancel(ctx)
	return &LoadBalancer{
		frontend:     frontend,
		ctx:          ctx,
		backends:     backends,
		currentIndex: -1,
		waitCtx:      waitCtx,
		waitCancel:   waitCancel,
		Entry: log.WithFields(log.Fields{
			trace.Component: "loadbalancer",
			trace.ComponentFields: log.Fields{
				"listen": frontend.String(),
			},
		}),
		connections: make(map[NetAddr]map[int64]net.Conn),
	}, nil
}

// LoadBalancer implements naive round robin TCP load
// balancer used in tests.
type LoadBalancer struct {
	sync.RWMutex
	connID int64
	*log.Entry
	frontend     NetAddr
	backends     []NetAddr
	ctx          context.Context
	currentIndex int
	listener     net.Listener
	connections  map[NetAddr]map[int64]net.Conn
	waitCtx      context.Context
	waitCancel   context.CancelFunc
}

// trackeConnection adds connection to the connection tracker
func (l *LoadBalancer) trackConnection(backend NetAddr, conn net.Conn) int64 {
	l.Lock()
	defer l.Unlock()
	l.connID++
	tracker, ok := l.connections[backend]
	if !ok {
		tracker = make(map[int64]net.Conn)
		l.connections[backend] = tracker
	}
	tracker[l.connID] = conn
	return l.connID
}

// untrackConnection removes connection from connection tracker
func (l *LoadBalancer) untrackConnection(backend NetAddr, id int64) {
	l.Lock()
	defer l.Unlock()
	tracker, ok := l.connections[backend]
	if !ok {
		return
	}
	delete(tracker, id)
}

// dropConnections drops connections associated with backend
func (l *LoadBalancer) dropConnections(backend NetAddr) {
	tracker := l.connections[backend]
	for _, conn := range tracker {
		conn.Close()
	}
	delete(l.connections, backend)
}

// AddBackend adds backend
func (l *LoadBalancer) AddBackend(b NetAddr) {
	l.Lock()
	defer l.Unlock()
	l.backends = append(l.backends, b)
	l.Debugf("Backends %v.", l.backends)
}

// RemoveBackend removes backend
func (l *LoadBalancer) RemoveBackend(b NetAddr) error {
	l.Lock()
	defer l.Unlock()
	l.currentIndex = -1
	for i := range l.backends {
		if l.backends[i] == b {
			l.backends = append(l.backends[:i], l.backends[i+1:]...)
			l.dropConnections(b)
			return nil
		}
	}
	return trace.NotFound("lb has no backend matching: %+v", b)
}

func (l *LoadBalancer) nextBackend() (NetAddr, error) {
	l.Lock()
	defer l.Unlock()
	if len(l.backends) == 0 {
		return NetAddr{}, trace.ConnectionProblem(nil, "no backends")
	}
	l.currentIndex = ((l.currentIndex + 1) % len(l.backends))
	return l.backends[l.currentIndex], nil
}

func (l *LoadBalancer) closeListener() {
	l.Lock()
	defer l.Unlock()
	if l.listener == nil {
		return
	}
	l.listener.Close()
}

func (l *LoadBalancer) Close() error {
	l.closeListener()
	return nil
}

// Listen creates a listener on the frontend addr
func (l *LoadBalancer) Listen() error {
	var err error
	l.listener, err = net.Listen(l.frontend.AddrNetwork, l.frontend.Addr)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	l.Debugf("created listening socket")
	return nil
}

// Addr returns the frontend listener address. Call this after Listen,
// otherwise Addr returns nil.
func (l *LoadBalancer) Addr() net.Addr {
	if l.listener == nil {
		return nil
	}
	return l.listener.Addr()
}

// Serve starts accepting connections
func (l *LoadBalancer) Serve() error {
	defer l.waitCancel()
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if IsUseOfClosedNetworkError(err) {
				return trace.Wrap(err, "listener is closed")
			}
			select {
			case <-l.ctx.Done():
				return trace.Wrap(net.ErrClosed, "context is closing")
			case <-time.After(5. * time.Second):
				l.Debugf("Backoff on network error.")
			}
		} else {
			go l.forwardConnection(conn)
		}
	}
}

func (l *LoadBalancer) forwardConnection(conn net.Conn) {
	err := l.forward(conn)
	if err != nil {
		l.Warningf("Failed to forward connection: %v.", err)
	}
}

// Wait is here to workaround issue https://github.com/golang/go/issues/10527
// in tests
func (l *LoadBalancer) Wait() {
	<-l.waitCtx.Done()
}

func (l *LoadBalancer) forward(conn net.Conn) error {
	defer conn.Close()

	backend, err := l.nextBackend()
	if err != nil {
		return trace.Wrap(err)
	}

	connID := l.trackConnection(backend, conn)
	defer l.untrackConnection(backend, connID)

	backendConn, err := net.Dial(backend.AddrNetwork, backend.Addr)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	defer backendConn.Close()

	backendConnID := l.trackConnection(backend, backendConn)
	defer l.untrackConnection(backend, backendConnID)

	logger := l.WithFields(log.Fields{
		"source": conn.RemoteAddr(),
		"dest":   backendConn.RemoteAddr(),
	})
	logger.Debugf("forward")

	messagesC := make(chan error, 2)

	go func() {
		defer conn.Close()
		defer backendConn.Close()
		_, err := io.Copy(conn, backendConn)
		messagesC <- err
	}()

	go func() {
		defer conn.Close()
		defer backendConn.Close()
		_, err := io.Copy(backendConn, conn)
		messagesC <- err
	}()

	var lastErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-messagesC:
			if err != nil && err != io.EOF {
				logger.Warningf("connection problem: %v %T", trace.DebugReport(err), err)
				lastErr = err
			}
		case <-l.ctx.Done():
			return trace.ConnectionProblem(nil, "context is closing")
		}
	}

	return lastErr
}
