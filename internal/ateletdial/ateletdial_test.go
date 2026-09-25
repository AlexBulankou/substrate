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

package ateletdial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/substratex509"
	"github.com/agent-substrate/substrate/internal/testca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

const (
	ateletSPIFFEID = "spiffe://cluster.local/ns/ate-system/sa/atelet"
	workerSPIFFEID = "spiffe://cluster.local/ns/ate-demo/sa/ateom"
)

// TestTLSConfigRejectsIncompleteArguments covers the guard that keeps a caller
// from building a config that would verify nothing. Each field is required for
// a different reason, so each gets its own case rather than one table row.
func TestTLSConfigRejectsIncompleteArguments(t *testing.T) {
	env := newWorkerEnv(t)

	for _, tc := range []struct {
		name               string
		credentials, trust string
		spiffeID           string
	}{
		{"no worker credentials", "", env.trustPath, ateletSPIFFEID},
		{"no trust bundle", env.credentialPath, "", ateletSPIFFEID},
		{"no atelet SPIFFE ID", env.credentialPath, env.trustPath, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TLSConfig(tc.credentials, tc.trust, tc.spiffeID)
			if err == nil {
				t.Fatalf("TLSConfig() error = nil, want an error for %s", tc.name)
			}
			if got != nil {
				t.Errorf("TLSConfig() = %v, want nil alongside the error", got)
			}
		})
	}
}

func TestTLSConfigRejectsAnUnusableWorkerIdentity(t *testing.T) {
	env := newWorkerEnv(t)

	t.Run("credential bundle is absent", func(t *testing.T) {
		if _, err := TLSConfig(filepath.Join(t.TempDir(), "absent.pem"), env.trustPath, ateletSPIFFEID); err == nil {
			t.Fatal("TLSConfig() error = nil, want a load error for a missing credential bundle")
		}
	})

	// A certificate that parses but carries no Pod identity extension cannot
	// name the node this worker runs on, so there is nothing to compare atelet
	// against. That must fail at construction rather than at verification time,
	// where a nil local identity would be compared against atelet's and match
	// nothing.
	t.Run("certificate has no Pod identity extension", func(t *testing.T) {
		bare := issuePodCertificate(t, env.ca, nil, workerSPIFFEID, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		path := filepath.Join(t.TempDir(), "bare.pem")
		writeCredentialBundle(t, path, bare)

		if _, err := TLSConfig(path, env.trustPath, ateletSPIFFEID); err == nil {
			t.Fatal("TLSConfig() error = nil, want an error for a certificate with no Pod identity")
		}
	})
}

func TestTLSConfigRejectsAnUnusableTrustBundle(t *testing.T) {
	env := newWorkerEnv(t)

	t.Run("trust bundle is absent", func(t *testing.T) {
		if _, err := TLSConfig(env.credentialPath, filepath.Join(t.TempDir(), "absent.pem"), ateletSPIFFEID); err == nil {
			t.Fatal("TLSConfig() error = nil, want a read error for a missing trust bundle")
		}
	})

	// An empty pool is the dangerous case: it parses, and then rejects every
	// peer forever. Failing at construction is what turns that into a startup
	// error rather than a connection that never works.
	t.Run("trust bundle holds no certificates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.pem")
		if err := os.WriteFile(path, []byte("not a PEM block\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := TLSConfig(env.credentialPath, path, ateletSPIFFEID); err == nil {
			t.Fatal("TLSConfig() error = nil, want an error for a trust bundle with no certificates")
		}
	})
}

// TestTLSConfigPinsTheHandshakeShape guards the three settings that make the
// custom verification safe. InsecureSkipVerify is set on purpose — dropping
// VerifyConnection while leaving it set would accept any peer, so the two are
// asserted together.
func TestTLSConfigPinsTheHandshakeShape(t *testing.T) {
	env := newWorkerEnv(t)

	cfg, err := TLSConfig(env.credentialPath, env.trustPath, ateletSPIFFEID)
	if err != nil {
		t.Fatalf("TLSConfig() error = %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#x, want TLS 1.3 (%#x)", cfg.MinVersion, tls.VersionTLS13)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false; the custom VerifyConnection depends on it being set")
	}
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection = nil, which with InsecureSkipVerify set would accept any peer")
	}
	if cfg.GetClientCertificate == nil {
		t.Error("GetClientCertificate = nil; the worker would present no certificate")
	}
}

// TestVerifyConnectionAcceptsTheAteletOnThisNode is the positive control for
// every rejection case below: the same helper, with nothing wrong with it.
func TestVerifyConnectionAcceptsTheAteletOnThisNode(t *testing.T) {
	env := newWorkerEnv(t)
	verify := env.verifier(t, ateletSPIFFEID)

	if err := verify(env.ateletState(t, env.ca, ateletIdentity("node-a", "node-uid"), ateletSPIFFEID)); err != nil {
		t.Fatalf("VerifyConnection() error = %v, want nil for the atelet on this worker's own node", err)
	}
}

func TestVerifyConnectionRejectsAnUnacceptableAtelet(t *testing.T) {
	env := newWorkerEnv(t)
	verify := env.verifier(t, ateletSPIFFEID)
	otherCA := testca.New(t, "test-ca")

	for _, tc := range []struct {
		name  string
		state tls.ConnectionState
		want  string
	}{
		{
			// A handshake that produced no peer chain must not fall through to
			// the index-0 reads below it.
			name:  "no certificate at all",
			state: tls.ConnectionState{},
			want:  "atelet certificate is required",
		},
		{
			// The whole point of the trust bundle: a well-formed certificate
			// with the right SPIFFE ID and the right node, from a CA we do not
			// trust, is still not atelet.
			name:  "chain does not reach a trusted root",
			state: env.ateletState(t, otherCA, ateletIdentity("node-a", "node-uid"), ateletSPIFFEID),
			want:  "verify atelet certificate",
		},
		{
			// Same trusted CA, so only the SPIFFE ID separates atelet from any
			// other workload the cluster CA signs.
			name:  "trusted peer that is not atelet",
			state: env.ateletState(t, env.ca, ateletIdentity("node-a", "node-uid"), workerSPIFFEID),
			want:  "node-local peer is not atelet",
		},
		{
			// The node check is what makes the socket node-local in fact and
			// not just by convention.
			name:  "atelet on a different node",
			state: env.ateletState(t, env.ca, ateletIdentity("node-b", "other-node-uid"), ateletSPIFFEID),
			want:  "is not on worker node",
		},
		{
			// Name and UID are checked separately, so each needs a case that
			// only it can catch: here the UID matches and only the name differs.
			name:  "different node name, same node UID",
			state: env.ateletState(t, env.ca, ateletIdentity("node-b", "node-uid"), ateletSPIFFEID),
			want:  "is not on worker node",
		},
		{
			// A peer from the right CA with the right SPIFFE ID but no Pod
			// identity extension names no node at all, so there is nothing to
			// compare and it cannot be shown to be node-local.
			name:  "no Pod identity extension",
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{issuePodCertificate(t, env.ca, nil, ateletSPIFFEID, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}).Leaf}},
			want:  "is not on worker node",
		},
		{
			// A node recycled under the same name is a different node. The UID
			// is what distinguishes the incarnations, so it is checked
			// separately from the name.
			name:  "same node name, recycled node UID",
			state: env.ateletState(t, env.ca, ateletIdentity("node-a", "recycled-node-uid"), ateletSPIFFEID),
			want:  "is not on worker node",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(tc.state)
			if err == nil {
				t.Fatalf("VerifyConnection() error = nil, want an error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("VerifyConnection() error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestVerifyConnectionRejectsAServerAuthlessCertificate pins that the extended
// key usage is enforced, which a plain chain-to-root check would not do: a
// client certificate the same CA signed would otherwise be accepted as the
// server side of this connection.
func TestVerifyConnectionRejectsAServerAuthlessCertificate(t *testing.T) {
	env := newWorkerEnv(t)
	verify := env.verifier(t, ateletSPIFFEID)

	state := env.stateFor(t, env.ca, ateletIdentity("node-a", "node-uid"), ateletSPIFFEID,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	err := verify(state)
	if err == nil {
		t.Fatal("VerifyConnection() error = nil, want a rejection of a certificate with no serverAuth usage")
	}
	if !strings.Contains(err.Error(), "verify atelet certificate") {
		t.Errorf("VerifyConnection() error = %q, want the chain-verification error", err)
	}
}

// TestVerifyConnectionFollowsATrustBundleRotation is the regression test for a
// pool frozen at construction. kubelet rewrites the projected
// ClusterTrustBundle in place when the signer rotates, and this is the
// connection a worker renews its own certificate over — so a config that stops
// accepting atelet after a rotation costs the worker its identity until the pod
// restarts, with no way to recover in place.
func TestVerifyConnectionFollowsATrustBundleRotation(t *testing.T) {
	env := newWorkerEnv(t)
	verify := env.verifier(t, ateletSPIFFEID)

	rotatedCA := testca.New(t, "test-ca")
	rotated := env.ateletState(t, rotatedCA, ateletIdentity("node-a", "node-uid"), ateletSPIFFEID)

	// Before the projection is rewritten the new CA is correctly a stranger.
	if err := verify(rotated); err == nil {
		t.Fatal("VerifyConnection() error = nil for a CA not yet in the trust bundle, want a rejection")
	}

	rotateTrustBundle(t, env.trustPath, rotatedCA)

	if err := verify(rotated); err != nil {
		t.Fatalf("VerifyConnection() after the trust bundle rotated: error = %v, want nil", err)
	}
}

// TestVerifyConnectionFailsClosedOnAnUnreadableTrustBundle pins the direction
// of the failure introduced by reading the bundle per handshake: if the
// projection goes away mid-process the connection is refused, never accepted on
// a stale or empty pool.
func TestVerifyConnectionFailsClosedOnAnUnreadableTrustBundle(t *testing.T) {
	env := newWorkerEnv(t)
	verify := env.verifier(t, ateletSPIFFEID)
	state := env.ateletState(t, env.ca, ateletIdentity("node-a", "node-uid"), ateletSPIFFEID)

	if err := verify(state); err != nil {
		t.Fatalf("VerifyConnection() before removing the bundle: error = %v, want nil", err)
	}
	if err := os.Remove(env.trustPath); err != nil {
		t.Fatal(err)
	}
	err := verify(state)
	if err == nil {
		t.Fatal("VerifyConnection() error = nil after the trust bundle disappeared, want a refusal")
	}
	// Asserting the reason, not just the refusal: discarding the load error
	// leaves a nil pool, and a nil Roots means "verify against the system trust
	// store", which also refuses this chain. Both paths reject here, so only
	// the message distinguishes an honest fail-closed from an accidental
	// fallback onto the host's CAs.
	if !strings.Contains(err.Error(), "reload atelet trust bundle") {
		t.Errorf("VerifyConnection() error = %q, want the trust-bundle reload failure rather than a chain-verification error", err)
	}
}

// TestDialTargetsTheSocketRatherThanAnAddress pins the passthrough target and
// the unix dialer together: grpc.NewClient is lazy, so the assertion that
// matters at construction is that no name resolution will be attempted against
// the socket path.
func TestDialTargetsTheSocketRatherThanAnAddress(t *testing.T) {
	env := newWorkerEnv(t)
	cfg, err := TLSConfig(env.credentialPath, env.trustPath, ateletSPIFFEID)
	if err != nil {
		t.Fatalf("TLSConfig() error = %v", err)
	}

	socketPath := filepath.Join(t.TempDir(), "atelet.sock")
	conn, err := Dial(socketPath, cfg)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if got, want := conn.Target(), "passthrough:///atelet"; got != want {
		t.Errorf("conn.Target() = %q, want %q", got, want)
	}
	// The socket path reaches the connection through the context dialer, never
	// through the target, so no resolver ever sees it as a name to look up.
	if strings.Contains(conn.Target(), socketPath) {
		t.Errorf("conn.Target() = %q, want the socket path kept out of the resolved target", conn.Target())
	}
}

// TestDialCompletesAMutuallyAuthenticatedHandshake is the end-to-end check that
// the pieces above are actually wired to each other: the unix context dialer
// reaches the socket, the worker presents its Pod certificate, and the custom
// verification accepts a real atelet chain rather than only a synthesized one.
func TestDialCompletesAMutuallyAuthenticatedHandshake(t *testing.T) {
	env := newWorkerEnv(t)
	socketPath := startAteletOnSocket(t, env, ateletIdentity("node-a", "node-uid"))

	cfg, err := TLSConfig(env.credentialPath, env.trustPath, ateletSPIFFEID)
	if err != nil {
		t.Fatalf("TLSConfig() error = %v", err)
	}
	conn, err := Dial(socketPath, cfg)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn.Connect()
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			return
		}
		if state == connectivity.TransientFailure {
			t.Fatal("connection reached TransientFailure; the handshake was rejected")
		}
		if !conn.WaitForStateChange(ctx, state) {
			t.Fatalf("connection stuck in %v, want Ready", state)
		}
	}
}

// startAteletOnSocket runs a TLS gRPC server on a unix socket that presents the
// given atelet identity and requires a client certificate from the same CA —
// the server side of the connection under test.
func startAteletOnSocket(t *testing.T, env *workerEnv, identity *substratex509.PodIdentity) string {
	t.Helper()
	ateletCert := issuePodCertificate(t, env.ca, identity, ateletSPIFFEID, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(env.ca.CertPEM) {
		t.Fatal("test CA PEM did not parse")
	}
	// t.TempDir() embeds the test name, which overruns the ~104 byte unix
	// socket path limit on darwin, so the socket gets its own short dir.
	socketDir, err := os.MkdirTemp("", "ateletdial")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "atelet.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{ateletCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	})))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	return socketPath
}

// --- helpers ---

type workerEnv struct {
	ca             *testca.CA
	credentialPath string
	trustPath      string
	identity       *substratex509.PodIdentity
}

// newWorkerEnv lays out what a worker Pod sees on disk: its own credential
// bundle and the projected atelet trust bundle.
func newWorkerEnv(t *testing.T) *workerEnv {
	t.Helper()
	ca := testca.New(t, "test-ca")
	identity := &substratex509.PodIdentity{
		Namespace:          "ate-demo",
		ServiceAccountName: "ateom",
		ServiceAccountUID:  "ateom-sa-uid",
		PodName:            "worker",
		PodUID:             "worker-uid",
		NodeName:           "node-a",
		NodeUID:            "node-uid",
	}
	dir := t.TempDir()
	credentialPath := filepath.Join(dir, "worker.pem")
	trustPath := filepath.Join(dir, "trust.pem")
	writeCredentialBundle(t, credentialPath,
		issuePodCertificate(t, ca, identity, workerSPIFFEID, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}))
	writeTrustBundle(t, trustPath, ca)

	return &workerEnv{ca: ca, credentialPath: credentialPath, trustPath: trustPath, identity: identity}
}

// verifier returns the VerifyConnection hook from a config built over this
// environment, which is the only way to reach it: it closes over the worker's
// own identity and the trust bundle loader.
func (e *workerEnv) verifier(t *testing.T, spiffeID string) func(tls.ConnectionState) error {
	t.Helper()
	cfg, err := TLSConfig(e.credentialPath, e.trustPath, spiffeID)
	if err != nil {
		t.Fatalf("TLSConfig() error = %v", err)
	}
	return cfg.VerifyConnection
}

func (e *workerEnv) ateletState(t *testing.T, ca *testca.CA, identity *substratex509.PodIdentity, spiffeID string) tls.ConnectionState {
	t.Helper()
	return e.stateFor(t, ca, identity, spiffeID, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func (e *workerEnv) stateFor(t *testing.T, ca *testca.CA, identity *substratex509.PodIdentity, spiffeID string, usages []x509.ExtKeyUsage) tls.ConnectionState {
	t.Helper()
	cert := issuePodCertificate(t, ca, identity, spiffeID, usages)
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert.Leaf}}
}

func ateletIdentity(nodeName, nodeUID string) *substratex509.PodIdentity {
	return &substratex509.PodIdentity{
		Namespace:          "ate-system",
		ServiceAccountName: "atelet",
		ServiceAccountUID:  "atelet-sa-uid",
		PodName:            "atelet",
		PodUID:             "atelet-uid",
		NodeName:           nodeName,
		NodeUID:            nodeUID,
	}
}

// issuePodCertificate issues a leaf under ca naming spiffeID. A nil identity
// issues one with NO Pod identity extension — the case several tests need,
// where the peer is otherwise well-formed but names no node at all.
func issuePodCertificate(t *testing.T, ca *testca.CA, identity *substratex509.PodIdentity, spiffeID string, usages []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	opts := testca.Opts{URIs: []string{spiffeID}, ExtKeyUsage: usages}
	if identity != nil {
		opts.MutateTemplate = func(template *x509.Certificate) {
			if err := substratex509.AddPodIdentityToCertificate(identity, template); err != nil {
				t.Fatalf("AddPodIdentityToCertificate: %v", err)
			}
		}
	}
	leaf := ca.Issue(t, opts)
	cert, err := x509.ParseCertificate(leaf.CertDER)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.CertDER}, Leaf: cert, PrivateKey: leaf.Key}
}

func writeCredentialBundle(t *testing.T, path string, cert tls.Certificate) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTrustBundle(t *testing.T, path string, ca *testca.CA) {
	t.Helper()
	if err := os.WriteFile(path, ca.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// rotateTrustBundle replaces the projected bundle the way kubelet does, by
// swapping in a different file rather than rewriting the bytes in place.
//
// The distinction is load-bearing for this test rather than incidental
// realism: credbundle's pool cache invalidates on (inode, mtime, size), and
// two single-CA PEMs written microseconds apart differ in none of the three,
// so an in-place rewrite here is reliably invisible to the loader and the test
// flakes. kubelet swaps the ..data symlink, which changes the inode the path
// resolves to, so the rotation this asserts is the one that actually happens.
func rotateTrustBundle(t *testing.T, path string, ca *testca.CA) {
	t.Helper()
	staging := path + ".rotated"
	if err := os.WriteFile(staging, ca.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staging, path); err != nil {
		t.Fatal(err)
	}
}
