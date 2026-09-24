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
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/testca"
	"google.golang.org/grpc/credentials"
)

const ateapiTestServerName = "ateapi.test"

// serverCreds points the package flags buildServerCreds reads at a throwaway
// serving bundle and the given client-CA path, and returns what it built. An
// empty clientCAPath selects the no-pool mode.
func serverCreds(t *testing.T, clientCAPath string) (credentials.TransportCredentials, *testca.CA) {
	t.Helper()
	serverCA := testca.New(t, "ateapi-serving-ca")
	bundlePath := testca.WriteCredBundle(t, serverCA.Issue(t, testca.LeafOpts{DNSNames: []string{ateapiTestServerName}}))

	oldBundle, oldCA := *grpcServerCredBundle, *podIdentityCACerts
	t.Cleanup(func() { *grpcServerCredBundle, *podIdentityCACerts = oldBundle, oldCA })
	*grpcServerCredBundle = bundlePath
	*podIdentityCACerts = clientCAPath

	creds, err := buildServerCreds(context.Background())
	if err != nil {
		t.Fatalf("buildServerCreds() error = %v", err)
	}
	return creds, serverCA
}

// TestBuildServerCredsReloadsClientCAs is the regression test for a
// startup-frozen ClientCAs pool: after a pod-identity CA rotation the old pool
// stops recognising every mTLS caller until ateapi restarts.
//
// The assertion is on the identity the server ended up with, not on the
// handshake error, and the difference is the whole failure mode. Client certs
// are optional here, and the pool is also what the server advertises in the
// CertificateRequest, so a caller holding a certificate from an unadvertised CA
// does not fail the handshake -- it quietly sends nothing and connects as an
// anonymous client. A frozen pool therefore does not break rotated callers
// loudly; it strips their identity and leaves them to be refused later by the
// interceptor, as if they had never presented a certificate at all.
func TestBuildServerCredsReloadsClientCAs(t *testing.T) {
	ca1 := testca.New(t, "client-ca-1")
	ca2 := testca.New(t, "client-ca-2")
	caPath := filepath.Join(t.TempDir(), "pod-identity-ca.pem")
	testca.WriteBundle(t, caPath, ca1.PEM, time.Now())

	creds, serverCA := serverCreds(t, caPath)
	identified := func(leaf testca.Leaf) bool {
		t.Helper()
		identified, err := testca.Handshake(t, creds, serverCA.Pool(), ateapiTestServerName, leaf)
		if err != nil {
			t.Fatalf("handshake failed outright: %v", err)
		}
		return identified
	}

	fromCA1 := ca1.Issue(t, testca.LeafOpts{})
	fromCA2 := ca2.Issue(t, testca.LeafOpts{})

	if !identified(fromCA1) {
		t.Fatal("a CA1-signed client was not recognised before the rotation")
	}
	if identified(fromCA2) {
		t.Fatal("a CA2-signed client was recognised before the rotation, want the unpublished CA to be untrusted")
	}

	// Publishing CA2 is the rotation. The mtime bump makes the change visible
	// where the filesystem's timestamp granularity is coarser than the test.
	testca.WriteBundle(t, caPath, ca2.PEM, time.Now().Add(time.Second))

	if !identified(fromCA2) {
		t.Fatal("a CA2-signed client was not recognised after the rotation")
	}
	if identified(fromCA1) {
		t.Fatal("a CA1-signed client was recognised after the rotation, want the retired CA to be dropped")
	}
}

// TestBuildServerCredsKeepsClientCertsOptional guards the property that makes
// this server's ClientAuth weaker than atelet's on purpose: kubectl-ate holds no
// certificate and authenticates with a Bearer token in the interceptor, so a
// certless handshake has to succeed even while a pool is configured.
func TestBuildServerCredsKeepsClientCertsOptional(t *testing.T) {
	ca := testca.New(t, "client-ca")
	caPath := filepath.Join(t.TempDir(), "pod-identity-ca.pem")
	testca.WriteBundle(t, caPath, ca.PEM, time.Now())

	creds, serverCA := serverCreds(t, caPath)
	identified, err := testca.Handshake(t, creds, serverCA.Pool(), ateapiTestServerName, testca.Leaf{})
	if err != nil {
		t.Fatalf("a certless client was refused: %v", err)
	}
	if identified {
		t.Fatal("a certless client was reported as identified")
	}
}

// TestBuildServerCredsWithNoPoolAsksForNoCertificate covers the mode the flag
// help calls "client-cert verification disabled". It has to ask for no
// certificate rather than leave ClientCAs nil, which does not disable
// verification at all -- it falls back to the host system trust store, so a
// WebPKI-issued certificate would pass the transport check. Connecting with no
// identity at all is the honest shape for a server that has nothing to verify
// against.
func TestBuildServerCredsWithNoPoolAsksForNoCertificate(t *testing.T) {
	creds, serverCA := serverCreds(t, "")
	unrelated := testca.New(t, "unrelated-ca")

	identified, err := testca.Handshake(t, creds, serverCA.Pool(), ateapiTestServerName, unrelated.Issue(t, testca.LeafOpts{}))
	if err != nil {
		t.Fatalf("a client offering an unrelated certificate was refused: %v", err)
	}
	if identified {
		t.Fatal("the server took a client certificate while configured with no pool to verify one against")
	}
}

// TestBuildServerCredsRejectsAnUnreadablePool pins the startup read: without it
// a misprojected trust volume is reported as every caller failing to
// authenticate, long after the pod went ready.
func TestBuildServerCredsRejectsAnUnreadablePool(t *testing.T) {
	serverCA := testca.New(t, "ateapi-serving-ca")
	bundlePath := testca.WriteCredBundle(t, serverCA.Issue(t, testca.LeafOpts{DNSNames: []string{ateapiTestServerName}}))

	oldBundle, oldCA := *grpcServerCredBundle, *podIdentityCACerts
	t.Cleanup(func() { *grpcServerCredBundle, *podIdentityCACerts = oldBundle, oldCA })
	*grpcServerCredBundle = bundlePath
	*podIdentityCACerts = filepath.Join(t.TempDir(), "absent.pem")

	if _, err := buildServerCreds(context.Background()); err == nil {
		t.Fatal("buildServerCreds() error = nil for a pod-identity CA that does not exist, want a refusal")
	}
}
