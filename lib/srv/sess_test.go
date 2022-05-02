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

package srv

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/eventstest"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestParseAccessRequestIDs(t *testing.T) {
	testCases := []struct {
		input     string
		comment   string
		result    []string
		assertErr require.ErrorAssertionFunc
	}{
		{
			input:     `{"access_requests":["1a7483e0-575a-4bd1-9faa-022500a49325","30b344f5-d1ba-49fc-b2aa-b04234d0a4ec"]}`,
			comment:   "complete valid input",
			assertErr: require.NoError,
			result:    []string{"1a7483e0-575a-4bd1-9faa-022500a49325", "30b344f5-d1ba-49fc-b2aa-b04234d0a4ec"},
		},
		{
			input:     `{"access_requests":["1a7483e0-575a-4bd1-9faa-022500a49325","30b344f5-d1ba-49fc-b2aa"]}`,
			comment:   "invalid uuid",
			assertErr: require.Error,
			result:    nil,
		},
		{
			input:     `{"access_requests":[nil,"30b344f5-d1ba-49fc-b2aa-b04234d0a4ec"]}`,
			comment:   "invalid value, value in slice is nil",
			assertErr: require.Error,
			result:    nil,
		},
		{
			input:     `{"access_requests":nil}`,
			comment:   "invalid value, whole value is nil",
			assertErr: require.Error,
			result:    nil,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.comment, func(t *testing.T) {
			out, err := parseAccessRequestIDs(tt.input)
			tt.assertErr(t, err)
			require.Equal(t, out, tt.result)
		})
	}

}

func TestSession_newRecorder(t *testing.T) {
	proxyRecording, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{
		Mode: types.RecordAtProxy,
	})
	require.NoError(t, err)

	proxyRecordingSync, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{
		Mode: types.RecordAtProxySync,
	})
	require.NoError(t, err)

	nodeRecording, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{
		Mode: types.RecordAtNode,
	})
	require.NoError(t, err)

	nodeRecordingSync, err := types.NewSessionRecordingConfigFromConfigFile(types.SessionRecordingConfigSpecV2{
		Mode: types.RecordAtNodeSync,
	})
	require.NoError(t, err)

	logger := logrus.WithFields(logrus.Fields{
		trace.Component: teleport.ComponentAuth,
	})

	cases := []struct {
		desc         string
		sess         *session
		sctx         *ServerContext
		errAssertion require.ErrorAssertionFunc
		recAssertion require.ValueAssertionFunc
	}{
		{
			desc: "discard-stream-when-proxy-recording",
			sess: &session{
				id:  "test",
				log: logger,
				registry: &SessionRegistry{
					SessionRegistryConfig: SessionRegistryConfig{
						Srv: &mockServer{
							component: teleport.ComponentNode,
						},
					},
				},
			},
			sctx: &ServerContext{
				SessionRecordingConfig: proxyRecording,
			},
			errAssertion: require.NoError,
			recAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.NotNil(t, i)
				_, ok := i.(*events.DiscardStream)
				require.True(t, ok)
			},
		},
		{
			desc: "discard-stream--when-proxy-sync-recording",
			sess: &session{
				id:  "test",
				log: logger,
				registry: &SessionRegistry{
					SessionRegistryConfig: SessionRegistryConfig{
						Srv: &mockServer{
							component: teleport.ComponentNode,
						},
					},
				},
			},
			sctx: &ServerContext{
				SessionRecordingConfig: proxyRecordingSync,
			},
			errAssertion: require.NoError,
			recAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.NotNil(t, i)
				_, ok := i.(*events.DiscardStream)
				require.True(t, ok)
			},
		},
		{
			desc: "err-new-streamer-fails",
			sess: &session{
				id:  "test",
				log: logger,
				registry: &SessionRegistry{
					SessionRegistryConfig: SessionRegistryConfig{
						Srv: &mockServer{
							component: teleport.ComponentNode,
						},
					},
				},
			},
			sctx: &ServerContext{
				SessionRecordingConfig: nodeRecording,
				srv: &mockServer{
					component: teleport.ComponentNode,
				},
			},
			errAssertion: require.Error,
			recAssertion: require.Nil,
		},
		{
			desc: "err-new-audit-writer-fails",
			sess: &session{
				id:  "test",
				log: logger,
				registry: &SessionRegistry{
					SessionRegistryConfig: SessionRegistryConfig{
						Srv: &mockServer{
							component: teleport.ComponentNode,
						},
					},
				},
			},
			sctx: &ServerContext{
				SessionRecordingConfig: nodeRecordingSync,
				srv: &mockServer{
					component: teleport.ComponentNode,
				},
			},
			errAssertion: require.Error,
			recAssertion: require.Nil,
		},
		{
			desc: "audit-writer",
			sess: &session{
				id:  "test",
				log: logger,
				registry: &SessionRegistry{
					SessionRegistryConfig: SessionRegistryConfig{
						Srv: &mockServer{
							component: teleport.ComponentNode,
						},
					},
				},
			},
			sctx: &ServerContext{
				ClusterName:            "test",
				SessionRecordingConfig: nodeRecordingSync,
				srv: &mockServer{
					MockEmitter: &eventstest.MockEmitter{},
				},
			},
			errAssertion: require.NoError,
			recAssertion: func(t require.TestingT, i interface{}, i2 ...interface{}) {
				require.NotNil(t, i)
				aw, ok := i.(*events.AuditWriter)
				require.True(t, ok)
				require.NoError(t, aw.Close(context.Background()))
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.desc, func(t *testing.T) {
			rec, err := newRecorder(tt.sess, tt.sctx)
			tt.errAssertion(t, err)
			tt.recAssertion(t, rec)
		})
	}
}

// TestInteractiveSession tests interaction session lifecycles.
// Multiple sessions are opened in parallel tests to test for
// deadlocks between session registry, sessions, and parties.
func TestInteractiveSession(t *testing.T) {
	srv := newMockServer(t)
	srv.component = teleport.ComponentNode

	reg, err := NewSessionRegistry(SessionRegistryConfig{
		Srv:                   srv,
		SessionTrackerService: srv.auth,
	})
	require.NoError(t, err)
	t.Cleanup(func() { reg.Close() })

	t.Run("Stop", func(t *testing.T) {
		t.Parallel()
		sess := testOpenSession(t, reg)

		// Stopping the session should trigger the session
		// to end and cleanup in the background
		sess.Stop()

		sessionClosed := func() bool {
			reg.sessionsMux.Lock()
			defer reg.sessionsMux.Unlock()
			_, found := reg.findSessionLocked(sess.id)
			return !found
		}
		require.Eventually(t, sessionClosed, time.Second*5, time.Millisecond*500)
	})

	t.Run("BrokenRecorder", func(t *testing.T) {
		t.Parallel()
		sess := testOpenSession(t, reg)

		// The recorder might be closed in the case of an error downstream.
		// Closing the session recorder should result in the session ending.
		err := sess.recorder.Close(context.Background())
		require.NoError(t, err)
		require.Eventually(t, sess.isStopped, time.Second*5, time.Millisecond*500)
	})
}

// TestParties tests the party mechanisms within an interactive session,
// including party leave, party disconnect, and empty session lingerAndDie.
func TestParties(t *testing.T) {
	srv := newMockServer(t)
	srv.component = teleport.ComponentNode

	// Use a separate clock from srv so we can use BlockUntil.
	regClock := clockwork.NewFakeClock()
	reg, err := NewSessionRegistry(SessionRegistryConfig{
		Srv:                   srv,
		SessionTrackerService: srv.auth,
		clock:                 regClock,
	})
	require.NoError(t, err)
	t.Cleanup(func() { reg.Close() })

	// Create a session with 3 parties
	sess := testOpenSession(t, reg)
	require.Equal(t, 1, len(sess.getParties()))
	testJoinSession(t, reg, sess)
	require.Equal(t, 2, len(sess.getParties()))
	testJoinSession(t, reg, sess)
	require.Equal(t, 3, len(sess.getParties()))

	// If a party leaves, the session should remove the party and continue.
	p := sess.getParties()[0]
	p.Close()

	partyIsRemoved := func() bool {
		return len(sess.getParties()) == 2 && !sess.isStopped()
	}
	require.Eventually(t, partyIsRemoved, time.Second*5, time.Millisecond*500)

	// If a party's session context is closed, the party should leave the session.
	p = sess.getParties()[0]
	err = p.ctx.Close()
	require.NoError(t, err)

	partyIsRemoved = func() bool {
		return len(sess.getParties()) == 1 && !sess.isStopped()
	}
	require.Eventually(t, partyIsRemoved, time.Second*5, time.Millisecond*500)

	p.closeOnce.Do(func() {
		t.Fatalf("party should be closed already")
	})

	// If all parties are gone, the session should linger for a short duration.
	sess.getParties()[0].Close()
	require.False(t, sess.isStopped())

	// Wait for session to linger (time.Sleep)
	regClock.BlockUntil(2)

	// If a party connects to the lingering session, it will continue.
	testJoinSession(t, reg, sess)
	require.Equal(t, 1, len(sess.getParties()))

	regClock.Advance(defaults.SessionIdlePeriod)
	require.False(t, sess.isStopped())

	// If no parties remain it should be closed after the duration.
	sess.getParties()[0].Close()
	require.False(t, sess.isStopped())

	// Wait for session to linger (time.Sleep)
	regClock.BlockUntil(2)

	// Session should close.
	regClock.Advance(defaults.SessionIdlePeriod)
	require.Eventually(t, sess.isStopped, time.Second*5, time.Millisecond*500)
}

func testJoinSession(t *testing.T, reg *SessionRegistry, sess *session) {
	scx := newTestServerContext(t, reg.Srv)
	scx.setSession(sess)

	// Open a new session
	sshChanOpen := newMockSSHChannel()
	go func() {
		// Consume stdout sent to the channel
		io.ReadAll(sshChanOpen)
	}()

	err := reg.OpenSession(sshChanOpen, scx)
	require.NoError(t, err)
}

// TestSessionTracker tests session tracker lifecycle
func TestSessionTracker(t *testing.T) {
	ctx := context.Background()

	srv := newMockServer(t)

	// Use a separate clock from srv so we can use BlockUntil.
	regClock := clockwork.NewFakeClock()
	reg, err := NewSessionRegistry(SessionRegistryConfig{
		Srv:                   srv,
		SessionTrackerService: srv.auth,
		clock:                 regClock,
	})

	require.NoError(t, err)
	t.Cleanup(func() { reg.Close() })

	// Session tracker should be created for a new session
	sess := testOpenSession(t, reg)
	tracker, err := srv.auth.GetSessionTracker(ctx, sess.ID())
	require.NoError(t, err)

	// Session tracker's expiration should be updated on an interval
	// while the session is active.
	regClock.BlockUntil(1)
	regClock.Advance(defaults.SessionTrackerExpirationUpdateInterval)
	srv.clock.Advance(defaults.SessionTrackerExpirationUpdateInterval)

	trackerUpdated := func() bool {
		updatedTracker, err := srv.auth.GetSessionTracker(ctx, sess.ID())
		require.NoError(t, err)
		return updatedTracker.Expiry().Equal(tracker.Expiry().Add(defaults.SessionTrackerExpirationUpdateInterval))
	}
	require.Eventually(t, trackerUpdated, time.Second*5, time.Millisecond*500)

	// Once the sesssion is closed and the last set
	// expiration is up, the tracker should be deleted.
	sess.Close()
	regClock.Advance(defaults.SessionTrackerTTL)
	srv.clock.Advance(defaults.SessionTrackerTTL)

	trackerDeleted := func() bool {
		_, err := srv.auth.GetSessionTracker(ctx, sess.ID())
		if err == nil {
			return false
		}
		require.True(t, trace.IsNotFound(err))
		return true
	}
	require.Eventually(t, trackerDeleted, time.Second*5, time.Millisecond*500)
}

func testOpenSession(t *testing.T, reg *SessionRegistry) *session {
	scx := newTestServerContext(t, reg.Srv)

	// Open a new session
	sshChanOpen := newMockSSHChannel()
	go func() {
		// Consume stdout sent to the channel
		io.ReadAll(sshChanOpen)
	}()

	err := reg.OpenSession(sshChanOpen, scx)
	require.NoError(t, err)

	require.NotNil(t, scx.session)
	return scx.session
}
