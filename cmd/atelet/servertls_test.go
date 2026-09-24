// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/testca"
	"google.golang.org/grpc/credentials"
)

const ateletTestServerName = "atelet.test"

// serverTLSFixture is one atelet server config plus everything a handshake
// against it needs: the trust-bundle path the config reloads from, and the
// roots a test client verifies atelet's serving certificate with.
type serverTLSFixture struct {
	creds      credentials.TransportCredentials
	clientCAs  string
	serverCert *testca.CA
}

func newServerTLSFixture(t *testing.T, initialCA *testca.CA, verify func(tls.ConnectionState) error) serverTLSFixture {
	t.Helper()
	serverCA := testca.New(t, "atelet-serving-ca")
	bundlePath := testca.WriteCredBundle(t, serverCA.Issue(t, testca.LeafOpts{DNSNames: []string{ateletTestServerName}}))

	caPath := filepath.Join(t.TempDir(), "client-ca.pem")
	testca.WriteBundle(t, caPath, initialCA.PEM, time.Now())

	cfg, err := ateletServerTLSConfig(bundlePath, caPath, verify)
	if err != nil {
		t.Fatalf("ateletServerTLSConfig() error = %v", err)
	}
	return serverTLSFixture{creds: credentials.NewTLS(cfg), clientCAs: caPath, serverCert: serverCA}
}

// handshake returns only the error: atelet requires a client certificate, so
// there is no accepted-but-anonymous outcome to distinguish here the way there
// is on ateapi. The assertion below holds that line -- a handshake this server
// accepts always carries an identity.
func (f serverTLSFixture) handshake(t *testing.T, clientCert testca.Leaf) error {
	t.Helper()
	identified, err := testca.Handshake(t, f.creds, f.serverCert.Pool(), ateletTestServerName, clientCert)
	if err == nil && !identified {
		t.Fatal("atelet accepted a handshake with no client certificate, want RequireAndVerifyClientCert")
	}
	return err
}

// TestAteletServerTLSConfigReloadsClientCAs is the regression test for a
// startup-frozen ClientCAs pool. atelet is the only path ateapi has to a node,
// so a config that keeps verifying against the retired CA takes the whole node
// out of the control plane's reach until the process restarts.
func TestAteletServerTLSConfigReloadsClientCAs(t *testing.T) {
	ca1 := testca.New(t, "client-ca-1")
	ca2 := testca.New(t, "client-ca-2")
	f := newServerTLSFixture(t, ca1, nil)

	fromCA1 := ca1.Issue(t, testca.LeafOpts{})
	fromCA2 := ca2.Issue(t, testca.LeafOpts{})

	if err := f.handshake(t, fromCA1); err != nil {
		t.Fatalf("a CA1-signed client was refused before the rotation: %v", err)
	}
	if err := f.handshake(t, fromCA2); err == nil {
		t.Fatal("a CA2-signed client was accepted before the rotation, want a chain failure")
	}

	// Publishing CA2 is the rotation. The mtime bump makes the change visible
	// where the filesystem's timestamp granularity is coarser than the test.
	testca.WriteBundle(t, f.clientCAs, ca2.PEM, time.Now().Add(time.Second))

	if err := f.handshake(t, fromCA2); err != nil {
		t.Fatalf("a CA2-signed client was refused after the rotation: %v", err)
	}
	if err := f.handshake(t, fromCA1); err == nil {
		t.Fatal("a CA1-signed client was accepted after the rotation, want the retired CA to be dropped")
	}
}

// TestAteletServerTLSConfigAppliesVerifyConnection pins the hook to the config
// the handshake actually uses. VerifyConnection assigned to the outer config is
// silently dropped once GetConfigForClient returns one of its own, which is how
// the credential broker's same-node check would stop running while every test
// that only drives a chain check still passed.
func TestAteletServerTLSConfigAppliesVerifyConnection(t *testing.T) {
	ca := testca.New(t, "client-ca")
	refuse := func(tls.ConnectionState) error { return fmt.Errorf("refused by the verify hook") }
	f := newServerTLSFixture(t, ca, refuse)

	if err := f.handshake(t, ca.Issue(t, testca.LeafOpts{})); err == nil {
		t.Fatal("a client with a valid chain was accepted, want the verify hook to refuse it")
	}
}

// TestAteletServerTLSConfigRejectsAnUnreadableClientCA pins the startup read.
// Without it a node with a misprojected trust volume serves happily and refuses
// every caller at handshake time, which reports a mount problem as a fleet-wide
// authentication failure.
func TestAteletServerTLSConfigRejectsAnUnreadableClientCA(t *testing.T) {
	serverCA := testca.New(t, "atelet-serving-ca")
	bundlePath := testca.WriteCredBundle(t, serverCA.Issue(t, testca.LeafOpts{DNSNames: []string{ateletTestServerName}}))

	if _, err := ateletServerTLSConfig(bundlePath, filepath.Join(t.TempDir(), "absent.pem"), nil); err == nil {
		t.Fatal("ateletServerTLSConfig() error = nil for a client CA that does not exist, want a refusal")
	}
}
