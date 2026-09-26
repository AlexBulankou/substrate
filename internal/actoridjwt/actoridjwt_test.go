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

package actoridjwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClaimsToWire_ClaimNamePerKind(t *testing.T) {
	base := Claims{
		Issuer:     "https://idp.ate-system.svc",
		Subject:    "x",
		Audiences:  []string{"a"},
		Expiration: time.Unix(1_800_000_000, 0),
		Substrate:  SubstrateClaims{Atespace: "team-a", ActorName: "my-actor", ActorUID: "3b9f1e77-2c4d-4a80-91be-6d5c8f0a7e21"},
	}
	for _, tc := range []struct {
		kind       Kind
		wantClaim  string
		otherClaim string
	}{
		{KindActor, "actor.ate.dev", "worker-for-actor.ate.dev"},
		{KindWorkerForActor, "worker-for-actor.ate.dev", "actor.ate.dev"},
	} {
		claims := base
		claims.Kind = tc.kind
		wire, err := ClaimsToWire(&claims)
		if err != nil {
			t.Fatalf("ClaimsToWire(%v) failed: %v", tc.kind, err)
		}
		payload, err := json.Marshal(wire)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(payload, &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := raw[tc.wantClaim]; !ok {
			t.Errorf("kind %v: claim %q missing from %s", tc.kind, tc.wantClaim, payload)
		}
		for _, absent := range []string{tc.otherClaim, "ate.dev"} {
			if _, ok := raw[absent]; ok {
				t.Errorf("kind %v: unexpected claim %q in %s", tc.kind, absent, payload)
			}
		}
		var sub WireSubstrateClaims
		if err := json.Unmarshal(raw[tc.wantClaim], &sub); err != nil {
			t.Fatalf("kind %v: decode %q: %v", tc.kind, tc.wantClaim, err)
		}
		if want := (WireSubstrateClaims{Atespace: "team-a", ActorName: "my-actor", ActorUID: "3b9f1e77-2c4d-4a80-91be-6d5c8f0a7e21"}); sub != want {
			t.Errorf("kind %v: %q = %+v, want %+v", tc.kind, tc.wantClaim, sub, want)
		}
	}
}

func TestClaimsToWire_NodeOnWorkerTokensOnly(t *testing.T) {
	claims := Claims{
		Kind:      KindWorkerForActor,
		Subject:   "x",
		Audiences: []string{"a"},
		Substrate: SubstrateClaims{Atespace: "team-a", ActorName: "my-actor", ActorUID: "u", Node: "node-1"},
	}
	wire, err := ClaimsToWire(&claims)
	if err != nil {
		t.Fatal(err)
	}
	if got := wire.WorkerForActor.Node; got != "node-1" {
		t.Errorf("worker-for-actor node = %q, want node-1", got)
	}
	claims.Kind = KindActor
	if _, err := ClaimsToWire(&claims); err == nil {
		t.Error("ClaimsToWire accepted a node on an actor's own token")
	}
}

func TestClaimsToWire_RejectsUnspecifiedKind(t *testing.T) {
	for _, kind := range []Kind{KindUnspecified, Kind(99)} {
		if _, err := ClaimsToWire(&Claims{Kind: kind, Subject: "x", Audiences: []string{"a"}}); err == nil {
			t.Errorf("ClaimsToWire(kind %v) succeeded, want error", kind)
		}
	}
}

func TestWireClaims_Substrate(t *testing.T) {
	actor := &WireSubstrateClaims{Atespace: "a", ActorName: "n", ActorUID: "u"}
	worker := &WireSubstrateClaims{Atespace: "a2", ActorName: "n2", ActorUID: "u2"}
	for _, tc := range []struct {
		name       string
		wire       WireClaims
		wantOK     bool
		wantKind   Kind
		wantClaims *WireSubstrateClaims
	}{
		{name: "neither claim", wire: WireClaims{}},
		{name: "both claims", wire: WireClaims{Actor: actor, WorkerForActor: worker}},
		{name: "actor", wire: WireClaims{Actor: actor}, wantOK: true, wantKind: KindActor, wantClaims: actor},
		{name: "worker-for-actor", wire: WireClaims{WorkerForActor: worker}, wantOK: true, wantKind: KindWorkerForActor, wantClaims: worker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, claims, ok := tc.wire.Substrate()
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if kind != tc.wantKind {
				t.Errorf("kind = %v, want %v", kind, tc.wantKind)
			}
			if claims != tc.wantClaims {
				t.Errorf("claims = %+v, want %+v", claims, tc.wantClaims)
			}
		})
	}
}

func TestKind_Names(t *testing.T) {
	for _, tc := range []struct {
		kind          Kind
		prefix, claim string
	}{
		{KindUnspecified, "", ""},
		{KindActor, "actor", "actor.ate.dev"},
		{KindWorkerForActor, "worker-for-actor", "worker-for-actor.ate.dev"},
	} {
		if got := tc.kind.SubjectPrefix(); got != tc.prefix {
			t.Errorf("Kind(%d).SubjectPrefix() = %q, want %q", tc.kind, got, tc.prefix)
		}
		if got := tc.kind.ClaimName(); got != tc.claim {
			t.Errorf("Kind(%d).ClaimName() = %q, want %q", tc.kind, got, tc.claim)
		}
	}
}

// The tests below cover the wire encoding itself rather than the claim-name
// routing above.
//
// ClaimsToWire is the only translation between the internal claim struct and
// the JSON that gets signed into an actor's identity token: localjwtauthority
// calls it and marshals the result straight into the JWT payload. That makes
// it the single chokepoint where a mistake becomes an authentication defect
// rather than a bug, and it makes the struct tags load-bearing in a way that
// reads as cosmetic.
//
// The assertions are written against the marshalled JSON rather than against
// the WireClaims fields, because the tags are exactly the part that can be
// wrong while every field holds the right value.

// validClaims is a claim set shaped like the one controlapi mints: bound to an
// audience, valid for fifteen minutes, backdated five to tolerate clock skew.
func validClaims() *Claims {
	now := time.Unix(1_700_000_000, 0)
	return &Claims{
		Kind:       KindActor,
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

	if claims.Kind != before.Kind || claims.Issuer != before.Issuer || claims.Subject != before.Subject ||
		!claims.Expiration.Equal(before.Expiration) || claims.Substrate != before.Substrate {
		t.Error("ClaimsToWire mutated the claims it was given")
	}
	if len(claims.Audiences) != 1 || claims.Audiences[0] != "api.ate-system.svc" {
		t.Errorf("Audiences = %v, want the caller's slice untouched", claims.Audiences)
	}
}
