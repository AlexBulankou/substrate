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

package localjwtauthority

// Tests for the signing half of the pool.
//
// TestRefreshingPool covers reloading the pool from disk; the signing path it
// wraps had no coverage at all, which for a package whose entire job is minting
// actor identities is the wrong half to leave untested. A signer that emits the
// wrong algorithm in its header, or picks the wrong authority, or crashes on an
// operator's hand-edited pool file, all look identical to a caller that only
// checks for a nil error -- so these verify the produced JWT against the
// public key rather than asserting that signing returned something.

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/agent-substrate/substrate/internal/actoridjwt"
)

// testRSAKey is generated once: a 2048-bit RSA keygen costs more than every
// other assertion in this file combined, and none of these tests care which
// key they got.
var testRSAKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}()

func testClaims() *actoridjwt.Claims {
	now := time.Now().Truncate(time.Second)
	return &actoridjwt.Claims{
		Issuer:     "https://ate.example",
		Subject:    "actor:default:example",
		Audiences:  []string{"ateapi"},
		Expiration: now.Add(time.Hour),
		NotBefore:  now,
		IssuedAt:   now,
		JTI:        "test-jti",
	}
}

// splitJWT returns the decoded header and payload and the raw signing input,
// failing the test on anything that is not three base64url segments.
func splitJWT(t *testing.T, jwt string) (wireHeader, map[string]any, string, []byte) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d segments, want 3: %q", len(parts), jwt)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header wireHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	return header, payload, parts[0] + "." + parts[1], sig
}

// bigFromBytes reads one half of an ES256 signature. RFC 7518 3.4 fixes each
// of r and s at 32 bytes, left-padded -- unlike the ASN.1 form crypto/ecdsa
// produces by default -- so the halves are split by offset, not parsed.
func bigFromBytes(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// TestSignJWTVerifiesUnderTheAdvertisedKey is the assertion that matters for a
// signer: a relying party that fetches the pool's verification keys, picks the
// one named by `kid`, and checks the signature with the algorithm named by
// `alg` must succeed. Anything less -- "signing returned no error", or even
// "the segments decode" -- passes just as well for a JWT nobody can verify.
func TestSignJWTVerifiesUnderTheAdvertisedKey(t *testing.T) {
	t.Parallel()

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	for _, tc := range []struct {
		algorithm string
		key       crypto.Signer
		hash      crypto.Hash
	}{
		{algorithm: "ES256", key: ecdsaKey, hash: crypto.SHA256},
		{algorithm: "RS256", key: testRSAKey, hash: crypto.SHA256},
		{algorithm: "RS384", key: testRSAKey, hash: crypto.SHA384},
		{algorithm: "RS512", key: testRSAKey, hash: crypto.SHA512},
	} {
		t.Run(tc.algorithm, func(t *testing.T) {
			t.Parallel()
			pool := &ConcretePool{
				Authorities:      []*Authority{{ID: "primary", Algorithm: tc.algorithm, SigningKey: tc.key}},
				ActiveForSigning: "primary",
			}

			jwt, err := pool.SignJWT(testClaims())
			if err != nil {
				t.Fatalf("SignJWT: %v", err)
			}

			header, payload, signingInput, sig := splitJWT(t, jwt)
			if header.Algorithm != tc.algorithm {
				t.Errorf("header alg = %q, want %q", header.Algorithm, tc.algorithm)
			}
			// The kid is how a relying party selects among the pool's
			// verification keys, so a signer that omits it produces a token
			// that verifies only by trying every key in turn.
			if header.KeyID != "primary" {
				t.Errorf("header kid = %q, want %q", header.KeyID, "primary")
			}
			if got := payload["sub"]; got != "actor:default:example" {
				t.Errorf("payload sub = %v, want %q", got, "actor:default:example")
			}

			digest := hashBytes(tc.hash.New(), []byte(signingInput))
			switch pub := tc.key.Public().(type) {
			case *ecdsa.PublicKey:
				if len(sig) != 64 {
					t.Fatalf("ES256 signature is %d bytes, want the fixed 64 of RFC 7518 3.4", len(sig))
				}
				if !ecdsa.Verify(pub, digest, bigFromBytes(sig[:32]), bigFromBytes(sig[32:])) {
					t.Error("ECDSA signature does not verify under the advertised key")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig); err != nil {
					t.Errorf("RSA signature does not verify under the advertised key: %v", err)
				}
			default:
				t.Fatalf("unexpected public key type %T", pub)
			}
		})
	}
}

// TestSignJWTRejectsAlgorithmKeyMismatch is the regression test for a panic.
// Nothing validates that an authority's Algorithm matches its key type: the
// two arrive independently through Unmarshal, one as a string and one as
// PKCS#8. Before the checked assertions in sign, a pool naming RS256 over an
// ECDSA key took down the process on the first request that tried to use it --
// and RefreshingPool re-reads the pool file on a timer, so a single bad rotation
// crash-looped every replica rather than failing one request.
func TestSignJWTRejectsAlgorithmKeyMismatch(t *testing.T) {
	t.Parallel()

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	for _, tc := range []struct {
		name       string
		algorithm  string
		key        crypto.Signer
		wantSubstr string
	}{
		{name: "RS256 over an ECDSA key", algorithm: "RS256", key: ecdsaKey, wantSubstr: "requires an RSA key"},
		{name: "RS384 over an ECDSA key", algorithm: "RS384", key: ecdsaKey, wantSubstr: "requires an RSA key"},
		{name: "RS512 over an ECDSA key", algorithm: "RS512", key: ecdsaKey, wantSubstr: "requires an RSA key"},
		{name: "ES256 over an RSA key", algorithm: "ES256", key: testRSAKey, wantSubstr: "requires an ECDSA key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pool := &ConcretePool{
				Authorities:      []*Authority{{ID: "primary", Algorithm: tc.algorithm, SigningKey: tc.key}},
				ActiveForSigning: "primary",
			}

			jwt, err := pool.SignJWT(testClaims())
			if err == nil {
				t.Fatalf("SignJWT accepted a mismatched key and returned %q", jwt)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q does not say which key type was needed", err)
			}
		})
	}
}

// TestSignJWTRejectsNonP256ES256 pins the curve check. ES256 is defined over
// P-256 only; signing with a P-384 key produces a signature whose r and s do
// not fit the fixed 64-byte encoding, so a verifier either rejects it or, worse,
// reads a truncated one.
func TestSignJWTRejectsNonP256ES256(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	pool := &ConcretePool{
		Authorities:      []*Authority{{ID: "primary", Algorithm: "ES256", SigningKey: key}},
		ActiveForSigning: "primary",
	}

	if jwt, err := pool.SignJWT(testClaims()); err == nil {
		t.Fatalf("SignJWT accepted a P-384 key for ES256 and returned %q", jwt)
	}
}

// TestSignJWTRejectsUnknownAlgorithm covers the default branch, including
// "none" -- the algorithm a relying party must never accept and that this
// signer must never emit.
func TestSignJWTRejectsUnknownAlgorithm(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []string{"", "none", "HS256", "ES384", "PS256"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			pool := &ConcretePool{
				Authorities:      []*Authority{{ID: "primary", Algorithm: algorithm, SigningKey: testRSAKey}},
				ActiveForSigning: "primary",
			}
			jwt, err := pool.SignJWT(testClaims())
			if err == nil {
				t.Fatalf("SignJWT accepted algorithm %q and returned %q", algorithm, jwt)
			}
			if !strings.Contains(err.Error(), "unimplemented algorithm") {
				t.Errorf("error %q does not name the unimplemented algorithm", err)
			}
		})
	}
}

// TestSignJWTSelectsTheActiveAuthority covers the selection logic, which is
// what makes rotation work. Signing with the wrong authority of a multi-key
// pool still produces a verifiable token -- every authority in the pool is
// published as a verification key -- so this failure is invisible until the
// outgoing key is finally removed and previously-issued tokens stop verifying.
func TestSignJWTSelectsTheActiveAuthority(t *testing.T) {
	t.Parallel()

	outgoing, err := GenerateECDSAP256Authority("outgoing")
	if err != nil {
		t.Fatalf("generate outgoing authority: %v", err)
	}
	incoming, err := GenerateECDSAP256Authority("incoming")
	if err != nil {
		t.Fatalf("generate incoming authority: %v", err)
	}

	for _, tc := range []struct {
		name    string
		pool    *ConcretePool
		wantKID string
		wantErr string
	}{
		{
			name:    "active is honored over pool order",
			pool:    &ConcretePool{Authorities: []*Authority{outgoing, incoming}, ActiveForSigning: "incoming"},
			wantKID: "incoming",
		},
		{
			// The documented backwards-compatibility fallback for dev clusters
			// whose pool files predate ActiveForSigning.
			name:    "empty active falls back to the first authority",
			pool:    &ConcretePool{Authorities: []*Authority{outgoing, incoming}},
			wantKID: "outgoing",
		},
		{
			name:    "active naming an absent authority is an error",
			pool:    &ConcretePool{Authorities: []*Authority{outgoing}, ActiveForSigning: "retired"},
			wantErr: "not present",
		},
		{
			name:    "empty pool is an error",
			pool:    &ConcretePool{},
			wantErr: "no authorities",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jwt, err := tc.pool.SignJWT(testClaims())
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("SignJWT returned %q, want an error", jwt)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("SignJWT: %v", err)
			}
			header, _, _, _ := splitJWT(t, jwt)
			if header.KeyID != tc.wantKID {
				t.Errorf("signed with kid %q, want %q", header.KeyID, tc.wantKID)
			}
		})
	}
}

// TestVerificationKeysPublishesEveryAuthority pins that the inactive
// authorities are published too. That is the whole point of the pool: during a
// rotation the outgoing key must stay verifiable, or every token issued before
// the flip is rejected the moment it happens.
func TestVerificationKeysPublishesEveryAuthority(t *testing.T) {
	t.Parallel()

	outgoing, err := GenerateECDSAP256Authority("outgoing")
	if err != nil {
		t.Fatalf("generate outgoing authority: %v", err)
	}
	incoming, err := GenerateECDSAP256Authority("incoming")
	if err != nil {
		t.Fatalf("generate incoming authority: %v", err)
	}
	pool := &ConcretePool{Authorities: []*Authority{outgoing, incoming}, ActiveForSigning: "incoming"}

	keys, err := pool.VerificationKeys()
	if err != nil {
		t.Fatalf("VerificationKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("published %d keys, want 2", len(keys))
	}
	for i, want := range []*Authority{outgoing, incoming} {
		if keys[i].KeyID != want.ID {
			t.Errorf("key %d has kid %q, want %q", i, keys[i].KeyID, want.ID)
		}
		// A published key must be the public half. Publishing the private key
		// would hand every consumer the ability to mint actor identities.
		if _, isPrivate := keys[i].PublicKey.(*ecdsa.PrivateKey); isPrivate {
			t.Errorf("key %d published a private key", i)
		}
		pub, ok := keys[i].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("key %d has type %T, want *ecdsa.PublicKey", i, keys[i].PublicKey)
		}
		if !pub.Equal(want.SigningKey.Public()) {
			t.Errorf("key %d does not match the authority it names", i)
		}
	}
}

// TestUnmarshalRejectsANonSigningKey is the second panic regression. The code
// assumed every key type x509.ParsePKCS8PrivateKey returns implements
// crypto.Signer; an X25519 key parses to *ecdh.PrivateKey, which is a
// key-agreement key and does not. Since RefreshingPool re-reads the pool file
// on a timer, an unchecked assertion here turns one wrong key into a crash loop
// across every replica.
func TestUnmarshalRejectsANonSigningKey(t *testing.T) {
	t.Parallel()

	agreementKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(agreementKey)
	if err != nil {
		t.Fatalf("marshal X25519 key: %v", err)
	}
	wire, err := json.Marshal(&serializedPool{
		ActiveForSigning: "primary",
		Authorities: []*serializedAuthority{
			{ID: "primary", Algorithm: "ES256", SigningKeyPKCS8: pkcs8},
		},
	})
	if err != nil {
		t.Fatalf("marshal pool: %v", err)
	}

	pool, err := Unmarshal(wire)
	if err == nil {
		t.Fatalf("Unmarshal accepted a key-agreement key and returned %+v", pool)
	}
	if !strings.Contains(err.Error(), "cannot sign") {
		t.Errorf("error %q does not say the key cannot sign", err)
	}
}

// TestMarshalUnmarshalPreservesSigning is the round trip that matters: a pool
// written to disk and read back must still sign under the same authority. An
// id or algorithm dropped in serialization produces a pool that signs with a
// kid no verifier recognizes.
func TestMarshalUnmarshalPreservesSigning(t *testing.T) {
	t.Parallel()

	outgoing, err := GenerateECDSAP256Authority("outgoing")
	if err != nil {
		t.Fatalf("generate outgoing authority: %v", err)
	}
	incoming, err := GenerateECDSAP256Authority("incoming")
	if err != nil {
		t.Fatalf("generate incoming authority: %v", err)
	}
	original := &ConcretePool{Authorities: []*Authority{outgoing, incoming}, ActiveForSigning: "incoming"}

	wire, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	restored, err := Unmarshal(wire)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if restored.ActiveForSigning != "incoming" {
		t.Errorf("ActiveForSigning = %q, want %q", restored.ActiveForSigning, "incoming")
	}
	jwt, err := restored.SignJWT(testClaims())
	if err != nil {
		t.Fatalf("SignJWT on the restored pool: %v", err)
	}
	header, _, signingInput, sig := splitJWT(t, jwt)
	if header.KeyID != "incoming" {
		t.Errorf("restored pool signed with kid %q, want %q", header.KeyID, "incoming")
	}
	if header.Algorithm != "ES256" {
		t.Errorf("restored pool signed with alg %q, want %q", header.Algorithm, "ES256")
	}
	// Verified against the ORIGINAL key, so a round trip that silently
	// substituted a key would fail here rather than round-trip consistently.
	pub, ok := incoming.SigningKey.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("original key is %T, want *ecdsa.PublicKey", incoming.SigningKey.Public())
	}
	digest := hashBytes(crypto.SHA256.New(), []byte(signingInput))
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig))
	}
	if !ecdsa.Verify(pub, digest, bigFromBytes(sig[:32]), bigFromBytes(sig[32:])) {
		t.Error("restored pool's signature does not verify under the original key")
	}
}

// TestRefreshingPoolSignJWTFollowsTheFileOnlyAfterTheCacheExpires covers the
// wrapper every real caller actually holds -- ateapi constructs a
// RefreshingPool, never a ConcretePool -- and pins the two things its doc
// comment's promise of signing that "continues working seamlessly" as an
// administrator rotates the pool does not say out loud:
//
//   - the rotation is not instant. refreshIfNecessary caches for a minute, so
//     for up to a minute after the new pool lands on disk, tokens are still
//     minted by the outgoing authority. That is fine -- the outgoing key stays
//     published as a verification key -- but only if an operator knows to wait
//     out the window before deleting it.
//   - a pool file that goes bad stops signing rather than falling back to the
//     last good in-memory pool. That is the safe direction, and it is the
//     opposite of "seamlessly", so it is pinned rather than assumed.
//
// Uses synctest, as TestRefreshingPool does, so the minute costs no wall time.
func TestRefreshingPoolSignJWTFollowsTheFileOnlyAfterTheCacheExpires(t *testing.T) {
	outgoing, err := GenerateECDSAP256Authority("outgoing")
	if err != nil {
		t.Fatalf("generate outgoing authority: %v", err)
	}
	incoming, err := GenerateECDSAP256Authority("incoming")
	if err != nil {
		t.Fatalf("generate incoming authority: %v", err)
	}
	before, err := Marshal(&ConcretePool{Authorities: []*Authority{outgoing}, ActiveForSigning: "outgoing"})
	if err != nil {
		t.Fatalf("marshal pool before rotation: %v", err)
	}
	after, err := Marshal(&ConcretePool{
		Authorities:      []*Authority{outgoing, incoming},
		ActiveForSigning: "incoming",
	})
	if err != nil {
		t.Fatalf("marshal pool after rotation: %v", err)
	}

	synctest.Test(t, func(t *testing.T) {
		poolFile := filepath.Join(t.TempDir(), "pool.json")
		if err := os.WriteFile(poolFile, before, 0o600); err != nil {
			t.Fatalf("write pool before rotation: %v", err)
		}
		pool, err := NewRefreshingPool(poolFile)
		if err != nil {
			t.Fatalf("NewRefreshingPool: %v", err)
		}

		signedKID := func(t *testing.T, when string) string {
			t.Helper()
			jwt, err := pool.SignJWT(testClaims())
			if err != nil {
				t.Fatalf("SignJWT %s: %v", when, err)
			}
			header, _, _, _ := splitJWT(t, jwt)
			return header.KeyID
		}

		if got := signedKID(t, "before rotation"); got != "outgoing" {
			t.Errorf("signed with kid %q before rotation, want %q", got, "outgoing")
		}

		if err := os.WriteFile(poolFile, after, 0o600); err != nil {
			t.Fatalf("write pool after rotation: %v", err)
		}
		// Asserted, not tolerated: a wrapper that re-read the file on every
		// call would pass a "follows the file" test and quietly turn every
		// signature into a disk read.
		if got := signedKID(t, "immediately after rotation"); got != "outgoing" {
			t.Errorf("signed with kid %q inside the cache window, want the outgoing %q", got, "outgoing")
		}

		time.Sleep(time.Minute)
		if got := signedKID(t, "after the cache window"); got != "incoming" {
			t.Errorf("signed with kid %q after the cache window, want the rotated-in %q", got, "incoming")
		}

		// A truncated or half-written pool file fails the signing call rather
		// than silently reusing the pool already in memory.
		if err := os.WriteFile(poolFile, []byte("{"), 0o600); err != nil {
			t.Fatalf("write corrupt pool: %v", err)
		}
		time.Sleep(time.Minute)
		if jwt, err := pool.SignJWT(testClaims()); err == nil {
			t.Errorf("SignJWT over a corrupt pool file returned %q, want an error", jwt)
		}
	})
}

// TestUnmarshalRejectsAnUnparseableKey covers the other Unmarshal error path.
func TestUnmarshalRejectsAnUnparseableKey(t *testing.T) {
	t.Parallel()

	wire, err := json.Marshal(&serializedPool{
		Authorities: []*serializedAuthority{{ID: "primary", Algorithm: "ES256", SigningKeyPKCS8: []byte("not pkcs8")}},
	})
	if err != nil {
		t.Fatalf("marshal pool: %v", err)
	}
	if pool, err := Unmarshal(wire); err == nil {
		t.Fatalf("Unmarshal accepted a non-PKCS#8 key and returned %+v", pool)
	}
}
