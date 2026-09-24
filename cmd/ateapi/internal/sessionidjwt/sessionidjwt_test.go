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

package sessionidjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The assertions here are deliberately on "does the signature VERIFY against
// the public key", not on "did Sign return a non-empty string". A token that is
// well-formed but unverifiable is the failure mode that matters: it passes any
// shape-based test and is rejected by every real relying party.
//
// Six statements are deliberately left uncovered, because reaching them needs a
// hand-built invalid value rather than a realistic input. Recorded here so the
// next reader does not re-derive it:
//
//   - the json.Marshal error in ClaimsToWire, and the one for wireHeader in
//     Sign: both marshal a []string / an all-string struct, neither of which
//     encoding/json can fail on.
//   - the three rsa.SignPKCS1v15 error returns: PKCS1v15 only fails when the
//     digest does not fit the modulus, and the smallest key this module can
//     produce is 1024 bits (128 bytes) -- crypto/rsa refuses to generate
//     anything smaller under go 1.26. A SHA-512 PKCS1v15 block is 94 bytes, so
//     it fits every permitted key and the branch cannot be reached.
//   - the ecdsa.Sign error return, which a valid P-256 key does not produce.
//
// The payload-marshal error in Sign IS reachable -- Audiences is a
// json.RawMessage -- and is covered below.

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	// 2048 is the smallest size that is both realistic and fast enough here;
	// SHA-512 digests do not fit a smaller modulus under PKCS1v15.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func testECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	return key
}

func testClaims() *Claims {
	// Truncated to whole seconds because the wire format is a Unix timestamp;
	// sub-second precision is discarded by design and comparing against an
	// untruncated value would fail for the wrong reason.
	now := time.Now().Truncate(time.Second)
	return &Claims{
		Issuer:     "https://ate.example",
		Subject:    "session-subject",
		Audiences:  []string{"ateapi", "atelet"},
		Expiration: now.Add(time.Hour),
		NotBefore:  now,
		IssuedAt:   now,
		JTI:        "jti-1",
		Substrate: SubstrateClaims{
			AppID:     "app-1",
			UserID:    "user-1",
			SessionID: "session-1",
		},
	}
}

// splitToken returns the signing input and the decoded signature.
func splitToken(t *testing.T, token string) (signingInput string, sig []byte) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	return parts[0] + "." + parts[1], sig
}

func decodeSegment(t *testing.T, seg string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
}

func TestClaimsToWire(t *testing.T) {
	claims := testClaims()

	wire, err := ClaimsToWire(claims)
	if err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}

	if wire.Issuer != claims.Issuer || wire.Subject != claims.Subject || wire.JTI != claims.JTI {
		t.Errorf("scalar claims not carried: %+v", wire)
	}
	// Audiences is json.RawMessage, so the check is that it round-trips as a
	// JSON array rather than as the Go slice's default rendering.
	var auds []string
	if err := json.Unmarshal(wire.Audiences, &auds); err != nil {
		t.Fatalf("audiences are not valid JSON: %v", err)
	}
	if len(auds) != 2 || auds[0] != "ateapi" || auds[1] != "atelet" {
		t.Errorf("audiences = %v, want [ateapi atelet]", auds)
	}
	if int64(wire.Expiration) != claims.Expiration.Unix() {
		t.Errorf("exp = %v, want %d", wire.Expiration, claims.Expiration.Unix())
	}
	if int64(wire.NotBefore) != claims.NotBefore.Unix() {
		t.Errorf("nbf = %v, want %d", wire.NotBefore, claims.NotBefore.Unix())
	}
	if int64(wire.IssuedAt) != claims.IssuedAt.Unix() {
		t.Errorf("iat = %v, want %d", wire.IssuedAt, claims.IssuedAt.Unix())
	}
	if wire.Substrate.AppID != "app-1" || wire.Substrate.UserID != "user-1" || wire.Substrate.SessionID != "session-1" {
		t.Errorf("substrate claims not carried: %+v", wire.Substrate)
	}
}

// TestSignRSAVerifies covers RS256/RS384/RS512 by verifying each signature
// against the public key with the digest the algorithm name promises. A test
// that only checked "three segments, no error" would pass even if every
// variant signed a SHA-256 digest.
func TestSignRSAVerifies(t *testing.T) {
	key := testRSAKey(t)
	wire, err := ClaimsToWire(testClaims())
	if err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}

	for _, tc := range []struct {
		alg  string
		hash crypto.Hash
	}{
		{"RS256", crypto.SHA256},
		{"RS384", crypto.SHA384},
		{"RS512", crypto.SHA512},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			token, err := Sign(wire, key, tc.alg, "key-1")
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			signingInput, sig := splitToken(t, token)
			h := tc.hash.New()
			h.Write([]byte(signingInput))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, tc.hash, h.Sum(nil), sig); err != nil {
				t.Errorf("signature does not verify under %s: %v", tc.alg, err)
			}

			var hdr wireHeader
			decodeSegment(t, strings.Split(token, ".")[0], &hdr)
			if hdr.Algorithm != tc.alg {
				t.Errorf("header alg = %q, want %q", hdr.Algorithm, tc.alg)
			}
			if hdr.KeyID != "key-1" {
				t.Errorf("header kid = %q, want key-1", hdr.KeyID)
			}
		})
	}
}

// TestSignES256Verifies checks the raw R||S encoding RFC 7518 §3.4 requires.
// Go's ecdsa package speaks ASN.1 by default, so this is hand-rolled in Sign
// and is exactly the kind of code that silently produces a signature no
// standard library will accept.
func TestSignES256Verifies(t *testing.T) {
	key := testECDSAKey(t, elliptic.P256())
	wire, err := ClaimsToWire(testClaims())
	if err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}

	token, err := Sign(wire, key, "ES256", "key-1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	signingInput, sig := splitToken(t, token)
	if len(sig) != 64 {
		t.Fatalf("ES256 signature is %d bytes, want 64 (fixed-width R||S)", len(sig))
	}
	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, h.Sum(nil), r, s) {
		t.Error("ES256 signature does not verify")
	}
}

// TestSignES256RejectsNonP256Key pins the explicit curve guard. ES256 names
// P-256; signing with P-384 under that label produces a token a relying party
// cannot verify, so it has to fail at mint time rather than at use time.
func TestSignES256RejectsNonP256Key(t *testing.T) {
	key := testECDSAKey(t, elliptic.P384())
	wire, err := ClaimsToWire(testClaims())
	if err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}

	if _, err := Sign(wire, key, "ES256", "key-1"); err == nil {
		t.Fatal("ES256 accepted a P-384 key; it must reject any non-P256 curve")
	}
}

func TestSignRejectsUnknownAlgorithm(t *testing.T) {
	wire, err := ClaimsToWire(testClaims())
	if err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}

	// "none" is the canonical JWT downgrade attack: if it were ever accepted,
	// an unsigned token would be mintable.
	for _, alg := range []string{"none", "HS256", ""} {
		if _, err := Sign(wire, testRSAKey(t), alg, "key-1"); err == nil {
			t.Errorf("Sign accepted unsupported algorithm %q", alg)
		}
	}
}

// TestClaimsToWireNilAudiencesBecomesJSONNull pins current behaviour, which is
// not what the `omitempty` tag on WireClaims.Audiences suggests: a nil slice
// marshals to the four bytes "null", which is non-empty, so the claim is
// emitted as `"aud":null` rather than omitted. A relying party that treats a
// present-but-null audience differently from an absent one will see the
// difference, so it is worth having pinned.
func TestClaimsToWireNilAudiencesBecomesJSONNull(t *testing.T) {
	claims := testClaims()
	claims.Audiences = nil

	wire, err := ClaimsToWire(claims)
	if err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}
	if string(wire.Audiences) != "null" {
		t.Errorf("aud = %q, want %q", wire.Audiences, "null")
	}

	token, err := Sign(wire, testRSAKey(t), "RS256", "key-1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var payload map[string]any
	decodeSegment(t, strings.Split(token, ".")[1], &payload)
	aud, present := payload["aud"]
	if !present {
		t.Error("aud is absent from the payload; it is emitted as null today")
	}
	if aud != nil {
		t.Errorf("aud = %v, want null", aud)
	}
}

// TestClaimsToWireZeroTimesFailClosed checks the direction the mistake falls
// in. time.Time{}.Unix() is not 0, it is -62135596800, so a caller that forgets
// to set Expiration does NOT get exp omitted (which many verifiers read as
// "never expires") -- it gets a token that expired in year 1. That is the safe
// direction, and it is worth a test precisely because the omitempty tag makes
// the unsafe reading look plausible.
func TestClaimsToWireZeroTimesFailClosed(t *testing.T) {
	wire, err := ClaimsToWire(&Claims{Issuer: "https://ate.example"})
	if err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}

	wantZero := time.Time{}.Unix()
	if wire.Expiration >= 0 {
		t.Errorf("exp = %v for a zero Expiration; want a far-past value so the token fails closed", wire.Expiration)
	}
	if int64(wire.Expiration) != wantZero {
		t.Errorf("exp = %v, want %d", wire.Expiration, wantZero)
	}
}

// TestSignPropagatesPayloadMarshalError is the one marshal-error path in Sign
// that a caller can actually reach: Audiences is a json.RawMessage, so it is
// emitted verbatim and an invalid value fails at Marshal time rather than at
// ClaimsToWire time. Callers that build a WireClaims by hand (rather than via
// ClaimsToWire) can hit this, and the failure must be an error -- a swallowed
// one would mint a token with a truncated payload.
func TestSignPropagatesPayloadMarshalError(t *testing.T) {
	wire := &WireClaims{
		Issuer:    "https://ate.example",
		Audiences: json.RawMessage(`{"not":`), // truncated: invalid JSON
	}

	token, err := Sign(wire, testRSAKey(t), "RS256", "key-1")
	if err == nil {
		t.Fatal("Sign accepted an invalid raw audience; the marshal error must be surfaced")
	}
	if token != "" {
		t.Errorf("Sign returned token %q alongside an error; it must return the empty string", token)
	}
}

// TestSignPanicsOnKeyTypeMismatch documents CURRENT behaviour rather than
// desired behaviour, and is written to fail loudly if that behaviour changes.
//
// Sign type-asserts signingKey.(*rsa.PrivateKey) without the comma-ok form, so
// an RS* algorithm paired with an ECDSA key panics instead of returning an
// error. Every caller today passes a matched pair, so this is not reachable in
// production -- but it is a caller-supplied pair, and the failure mode of a
// panic in a token-minting path is worse than an error. Flagged rather than
// changed here: fixing it is a behaviour change, not test coverage.
func TestSignPanicsOnKeyTypeMismatch(t *testing.T) {
	wire, err := ClaimsToWire(testClaims())
	if err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Error("Sign no longer panics on an RS256/ECDSA mismatch -- if it now " +
				"returns an error, that is an improvement: update this test to assert it")
		}
	}()
	_, _ = Sign(wire, testECDSAKey(t, elliptic.P256()), "RS256", "key-1")
}
