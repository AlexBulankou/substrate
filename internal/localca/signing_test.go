//  Copyright 2026 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package localca

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"
)

// CreateCertificate is the signing operation itself: every pod identity and
// service DNS certificate in the cluster comes out of it. The tests here pin
// which CA it signs with, because that choice is the CA rotation mechanism --
// ActiveForSigning is how an operator moves issuance to a new root while the
// old one stays in the trust anchors long enough for existing certificates to
// expire. Signing with the wrong CA is invisible at issuance time and shows up
// later as peers rejecting a certificate they have no anchor for.

// leafTemplate is a minimal version of what the signers build: enough for
// x509.CreateCertificate to produce a leaf, with none of the identity
// encoding, which belongs to the signer packages rather than here.
func leafTemplate(t *testing.T) (*x509.Certificate, crypto.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating subject key: %v", err)
	}
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "subject"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, pub
}

// mustGenerateCA fails the test rather than returning an error: a CA that
// cannot be generated says nothing about the code under test.
func mustGenerateCA(t *testing.T, id string) *CA {
	t.Helper()
	ca, err := GenerateCA(id, KeyTypeED25519, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA(%q): %v", id, err)
	}
	return ca
}

// signedBy reports whether the single-certificate chain was signed by ca.
// CheckSignatureFrom is the precise question here -- x509.Verify would also
// bring in validity windows and key usage, which are the template's business.
func signedBy(t *testing.T, chain [][]byte, ca *CA) bool {
	t.Helper()
	if len(chain) == 0 {
		t.Fatal("chain is empty")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("parsing issued certificate: %v", err)
	}
	return leaf.CheckSignatureFrom(ca.RootCertificate) == nil
}

// TestCreateCertificateSignsWithTheActiveCA is the rotation property. A pool
// holds every CA whose certificates are still valid, but exactly one of them
// is current for signing. Signing with a different member would still produce
// a certificate that verifies against the pool's own trust anchors, so nothing
// local catches it -- the damage appears at a peer that has only been given
// the new root.
func TestCreateCertificateSignsWithTheActiveCA(t *testing.T) {
	outgoing, incoming := mustGenerateCA(t, "outgoing"), mustGenerateCA(t, "incoming")
	pool := &ConcretePool{CAs: []*CA{outgoing, incoming}, ActiveForSigning: "incoming"}

	template, pub := leafTemplate(t)
	chain, err := pool.CreateCertificate(template, pub)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	if !signedBy(t, chain, incoming) {
		t.Error("certificate is not signed by the CA designated ActiveForSigning")
	}
	// The negative half is what makes the first assertion mean something:
	// "incoming" is deliberately not first in the list, so a selection that
	// ignored ActiveForSigning would land on "outgoing".
	if signedBy(t, chain, outgoing) {
		t.Error("certificate is signed by the outgoing CA, want the active one")
	}
}

// TestCreateCertificateRejectsAnUnknownActiveCA covers the fail-closed half of
// the selection. A pool whose ActiveForSigning names a CA that has already
// been pruned from the list is a misconfiguration, and the only safe response
// is to stop issuing: falling back to some other member would silently sign
// with a CA the operator has deliberately moved off.
func TestCreateCertificateRejectsAnUnknownActiveCA(t *testing.T) {
	present := mustGenerateCA(t, "present")
	pool := &ConcretePool{CAs: []*CA{present}, ActiveForSigning: "pruned"}

	template, pub := leafTemplate(t)
	chain, err := pool.CreateCertificate(template, pub)
	if err == nil {
		t.Fatalf("CreateCertificate() error = nil, want a refusal; it signed with %v", chain)
	}
}

// TestCreateCertificateOnAnEmptyPoolRefuses pins that a pool with no CAs
// reports an error rather than panicking on CAs[0]. An empty pool is what a
// state file with an empty CA list deserializes to, and this runs inside the
// signer's reconcile loop: a panic there takes the whole controller down and
// stops issuance for every signer it hosts, not just the misconfigured one.
// The recover is what turns that crash into a statement of which contract
// broke, rather than a stack trace in the middle of an unrelated test run.
func TestCreateCertificateOnAnEmptyPoolRefuses(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CreateCertificate() panicked on a pool with no CAs (%v), want an error return", r)
		}
	}()

	template, pub := leafTemplate(t)
	if _, err := (&ConcretePool{}).CreateCertificate(template, pub); err == nil {
		t.Error("CreateCertificate() error = nil for a pool with no CAs, want a refusal")
	}
}

// TestCreateCertificateFallsBackToTheFirstCA pins the documented
// backwards-compatibility path for pools written before ActiveForSigning
// existed. It is marked for removal in the source; this test is here so that
// removing it is a deliberate change with a failing test attached, rather than
// something that quietly starts erroring on an old dev cluster's state file.
func TestCreateCertificateFallsBackToTheFirstCA(t *testing.T) {
	first, second := mustGenerateCA(t, "first"), mustGenerateCA(t, "second")
	pool := &ConcretePool{CAs: []*CA{first, second}}

	template, pub := leafTemplate(t)
	chain, err := pool.CreateCertificate(template, pub)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v, want the first CA used when none is designated", err)
	}
	if !signedBy(t, chain, first) {
		t.Error("certificate is not signed by the first CA in the list")
	}
	if signedBy(t, chain, second) {
		t.Error("certificate is signed by the second CA, want the first")
	}
}

// TestCreateCertificateReturnsOnlyTheLeaf pins the shape of the chain. The
// signers PEM-encode whatever comes back and hand it straight to the kubelet,
// so a chain that also carried the root would put the CA certificate into
// every workload's certificate file -- where a verifier that trusts its own
// chain would accept a root it was never configured to trust. Distributing
// roots is TrustAnchors' job.
func TestCreateCertificateReturnsOnlyTheLeaf(t *testing.T) {
	ca := mustGenerateCA(t, "only")
	pool := &ConcretePool{CAs: []*CA{ca}, ActiveForSigning: "only"}

	template, pub := leafTemplate(t)
	chain, err := pool.CreateCertificate(template, pub)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("chain has %d certificates, want just the leaf", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("parsing issued certificate: %v", err)
	}
	if leaf.IsCA {
		t.Error("the returned certificate is a CA certificate, want the issued leaf")
	}
}

// TestRefreshingPoolSignsFromTheRotatedFile is the end of the rotation story:
// changing ActiveForSigning on disk has to reach issuance without restarting
// the controller, because the process holding this pool is long-lived and a
// rotation that only takes effect on restart is not a rotation. The refresh is
// time-based, so the test runs in a synctest bubble and steps past the
// interval rather than sleeping for real.
func TestRefreshingPoolSignsFromTheRotatedFile(t *testing.T) {
	before, after := mustGenerateCA(t, "before"), mustGenerateCA(t, "after")

	rotated, err := Marshal(&ConcretePool{CAs: []*CA{before, after}, ActiveForSigning: "after"})
	if err != nil {
		t.Fatalf("marshaling the rotated pool: %v", err)
	}
	initial, err := Marshal(&ConcretePool{CAs: []*CA{before}, ActiveForSigning: "before"})
	if err != nil {
		t.Fatalf("marshaling the initial pool: %v", err)
	}

	synctest.Test(t, func(t *testing.T) {
		poolFile := filepath.Join(t.TempDir(), "pool.json")
		if err := os.WriteFile(poolFile, initial, 0o600); err != nil {
			t.Fatalf("writing the initial pool: %v", err)
		}

		pool, err := NewRefreshingPool(poolFile)
		if err != nil {
			t.Fatalf("NewRefreshingPool() error = %v", err)
		}

		template, pub := leafTemplate(t)
		chain, err := pool.CreateCertificate(template, pub)
		if err != nil {
			t.Fatalf("CreateCertificate() before rotation: %v", err)
		}
		if !signedBy(t, chain, before) {
			t.Fatal("the first certificate is not signed by the CA that was active on disk")
		}

		if err := os.WriteFile(poolFile, rotated, 0o600); err != nil {
			t.Fatalf("writing the rotated pool: %v", err)
		}
		time.Sleep(2 * time.Minute)

		chain, err = pool.CreateCertificate(template, pub)
		if err != nil {
			t.Fatalf("CreateCertificate() after rotation: %v", err)
		}
		if !signedBy(t, chain, after) {
			t.Error("issuance is still using the pre-rotation CA after the refresh interval")
		}
	})
}

// TestRefreshingPoolStopsSigningWhenItsStateGoesAway pins the fail-closed
// direction. The in-memory pool stays perfectly usable when the state file
// becomes unreadable, so the tempting behaviour is to keep signing from it.
// That would mean a CA revoked by deleting its state file carries on issuing
// certificates for as long as the controller happens to stay up; refusing is
// the choice that bounds the damage.
func TestRefreshingPoolStopsSigningWhenItsStateGoesAway(t *testing.T) {
	ca := mustGenerateCA(t, "only")
	state, err := Marshal(&ConcretePool{CAs: []*CA{ca}, ActiveForSigning: "only"})
	if err != nil {
		t.Fatalf("marshaling the pool: %v", err)
	}

	synctest.Test(t, func(t *testing.T) {
		poolFile := filepath.Join(t.TempDir(), "pool.json")
		if err := os.WriteFile(poolFile, state, 0o600); err != nil {
			t.Fatalf("writing the pool: %v", err)
		}

		pool, err := NewRefreshingPool(poolFile)
		if err != nil {
			t.Fatalf("NewRefreshingPool() error = %v", err)
		}
		template, pub := leafTemplate(t)
		if _, err := pool.CreateCertificate(template, pub); err != nil {
			t.Fatalf("CreateCertificate() while the state file exists: %v", err)
		}

		if err := os.Remove(poolFile); err != nil {
			t.Fatalf("removing the pool state: %v", err)
		}
		time.Sleep(2 * time.Minute)

		if _, err := pool.CreateCertificate(template, pub); err == nil {
			t.Error("CreateCertificate() error = nil after the state file went away, want issuance to stop")
		}
	})
}
