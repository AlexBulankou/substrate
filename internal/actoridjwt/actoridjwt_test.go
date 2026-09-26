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

// Tests for the actor-JWT wire encoding.
//
// ClaimsToWire is the only translation between the internal claim struct and
// the JSON that gets signed into an actor's identity token: localjwtauthority
// calls it and marshals the result straight into the JWT payload, and nothing
// ever parses WireClaims back. That makes this the single chokepoint where a
// mistake becomes an authentication defect rather than a bug, and it makes the
// struct tags load-bearing in a way that reads as cosmetic.
//
// The assertions below are written against the marshalled JSON rather than
// against the WireClaims fields, because the tags are exactly the part that
// can be wrong while every field holds the right value.
package actoridjwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// validClaims is a claim set shaped like the one controlapi mints: bound to an
// audience, valid for fifteen minutes, backdated five to tolerate clock skew.
func validClaims() *Claims {
	now := time.Unix(1_700_000_000, 0)
	return &Claims{
		Issuer:     "https://api.ate-system.svc",
		Subject:    "atespaces:demo:actors:actor-1",
		Audiences:  []string{"api.ate-system.svc"},
		Expiration: now.Add(15 * time.Minute),
		NotBefore:  now.Add(-5 * time.Minute),
		IssuedAt:   now,
		JTI:        "jti-1",
		Substrate: SubstrateClaims{
			Atespace:  "demo",
			ActorName: "actor-1",
			ActorUID:  "uid-1",
		},
	}
}

// wireJSON runs the encoding the signer runs and hands back the parsed object,
// so a test can ask whether a claim is present rather than merely zero.
func wireJSON(t *testing.T, claims *Claims) map[string]any {
	t.Helper()
	wire, err := ClaimsToWire(claims)
	if err != nil {
		t.Fatalf("ClaimsToWire(%+v) = error %v", claims, err)
	}
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshalling wire claims: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshalling the payload we just produced: %v", err)
	}
	return got
}

// TestClaimsToWireProducesTheRegisteredClaimNames pins the JSON names against
// RFC 7519. A renamed field still compiles, still round-trips through this
// package, and produces a token every relying party rejects -- or worse,
// accepts while ignoring the claim it could not find.
func TestClaimsToWireProducesTheRegisteredClaimNames(t *testing.T) {
	got := wireJSON(t, validClaims())

	for name, want := range map[string]any{
		"iss": "https://api.ate-system.svc",
		"sub": "atespaces:demo:actors:actor-1",
		"exp": float64(1_700_000_900),
		"nbf": float64(1_699_999_700),
		"iat": float64(1_700_000_000),
		"jti": "jti-1",
	} {
		if got[name] != want {
			t.Errorf("payload[%q] = %v, want %v", name, got[name], want)
		}
	}
}

// TestClaimsToWireNestsSubstrateClaimsUnderTheNamespacedKey pins both the
// container name and the keys inside it. A private claim collides with any
// other issuer's claim of the same name unless it stays namespaced, which is
// the entire reason the key is "ate.dev" rather than "substrate".
func TestClaimsToWireNestsSubstrateClaimsUnderTheNamespacedKey(t *testing.T) {
	got := wireJSON(t, validClaims())

	nested, ok := got["ate.dev"].(map[string]any)
	if !ok {
		t.Fatalf("payload[\"ate.dev\"] = %v (%T), want a nested object", got["ate.dev"], got["ate.dev"])
	}
	for name, want := range map[string]any{
		"atespace":  "demo",
		"actorName": "actor-1",
		"actorUID":  "uid-1",
	} {
		if nested[name] != want {
			t.Errorf("payload[\"ate.dev\"][%q] = %v, want %v", name, nested[name], want)
		}
	}
}

// TestClaimsToWireAlwaysEmitsAnExpiration is the reason the time claims carry
// no omitempty, and it is the one case in this package where a wrong answer is
// a security defect rather than a malformed token.
//
// A float64 tagged omitempty disappears at zero, and zero is a real instant
// here: the Unix epoch. The resulting payload has no exp claim at all, and a
// relying party reads a missing exp as "this token does not expire" -- so the
// value most likely to arrive from an uninitialised or misconverted timestamp
// produces an eternal actor credential. Emitting exp:0 instead fails closed,
// because a token that expired in 1970 is rejected everywhere.
func TestClaimsToWireAlwaysEmitsAnExpiration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expiration time.Time
		want       float64
	}{
		{"the unix epoch", time.Unix(0, 0), 0},
		{"the zero time", time.Time{}, -62135596800},
		{"a normal expiry", time.Unix(1_700_000_900, 0), 1_700_000_900},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			claims.Expiration = tc.expiration

			got := wireJSON(t, claims)

			exp, present := got["exp"]
			if !present {
				t.Fatal("payload has no exp claim: a token with no expiry is valid forever")
			}
			if exp != tc.want {
				t.Errorf("exp = %v, want %v", exp, tc.want)
			}
		})
	}
}

// TestClaimsToWireRefusesClaimsWithNoAudience covers the other unbound-token
// path. A nil audience marshals to `aud:null` and an empty one to `aud:[]`;
// neither is malformed enough for a relying party to reject, and the usual
// reading is that the token is not audience-restricted -- valid anywhere it is
// presented. Refusing to encode is the fail-closed answer, and it belongs
// here because this is the only place every caller passes through.
func TestClaimsToWireRefusesClaimsWithNoAudience(t *testing.T) {
	for _, tc := range []struct {
		name      string
		audiences []string
	}{
		{"nil", nil},
		{"empty", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			claims.Audiences = tc.audiences

			wire, err := ClaimsToWire(claims)
			if err == nil {
				b, _ := json.Marshal(wire)
				t.Fatalf("ClaimsToWire = no error for a token with no audience; it produced %s", b)
			}
			if !strings.Contains(err.Error(), "audience") {
				t.Errorf("error %q does not mention the audience; the caller cannot tell what was wrong", err)
			}
		})
	}
}

// TestClaimsToWireKeepsTheAudienceAList pins the shape rather than just the
// contents. RFC 7519 allows aud to be a string or an array of strings, and
// collapsing a single-element list to a bare string is a tempting
// simplification that changes how strict verifiers match it.
func TestClaimsToWireKeepsTheAudienceAList(t *testing.T) {
	for _, tc := range []struct {
		name      string
		audiences []string
		want      []any
	}{
		{"one audience", []string{"api.ate-system.svc"}, []any{"api.ate-system.svc"}},
		{"several audiences", []string{"a", "b", "c"}, []any{"a", "b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := validClaims()
			claims.Audiences = tc.audiences

			got, ok := wireJSON(t, claims)["aud"].([]any)
			if !ok {
				t.Fatalf("aud is not a JSON array; a verifier matching on array membership would miss it")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("aud = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("aud[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestClaimsToWireTruncatesSubSecondTimes documents that the encoding is
// whole-second, so a caller cannot smuggle a sub-second expiry past a verifier
// that compares integers. Unix() truncates toward the past for positive times,
// which shortens the window rather than extending it.
func TestClaimsToWireTruncatesSubSecondTimes(t *testing.T) {
	claims := validClaims()
	claims.Expiration = time.Unix(1_700_000_900, 999_999_999)

	if got := wireJSON(t, claims)["exp"]; got != float64(1_700_000_900) {
		t.Errorf("exp = %v, want the second truncated toward the past (1700000900)", got)
	}
}

// TestClaimsToWireDoesNotMutateItsInput guards a property callers rely on
// implicitly: controlapi builds one Claims and hands it to a pool that may
// sign against more than one authority.
func TestClaimsToWireDoesNotMutateItsInput(t *testing.T) {
	claims := validClaims()
	before := *claims

	if _, err := ClaimsToWire(claims); err != nil {
		t.Fatalf("ClaimsToWire: %v", err)
	}

	if claims.Issuer != before.Issuer || claims.Subject != before.Subject ||
		!claims.Expiration.Equal(before.Expiration) || claims.Substrate != before.Substrate {
		t.Error("ClaimsToWire mutated the claims it was given")
	}
	if len(claims.Audiences) != 1 || claims.Audiences[0] != "api.ate-system.svc" {
		t.Errorf("Audiences = %v, want the caller's slice untouched", claims.Audiences)
	}
}
