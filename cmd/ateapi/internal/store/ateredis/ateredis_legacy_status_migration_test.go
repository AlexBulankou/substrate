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

// Poison-seeded regression lane for the ancient flat-string Actor.status
// migrate-on-read shim (issue #7264). The standing valkey store holds pre-fork
// actor records whose `status` field is a bare enum STRING
// ("status":"STATUS_SUSPENDED") rather than the current nested ActorStatus
// message; protojson dies parsing the flat string, which is what bricks
// ListActors on the redis default lane (#2921). Because every fresh/throwaway
// rig boots a store containing only current-schema records
// (fresh-rig-masks-migration-defects), the ONLY way to regression-test the
// migration is to manufacture the pre-migration schema on purpose — which is
// exactly what these tests do. They are the durable regression guard once the
// standing store is eventually healed.
package ateredis

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// legacyActorJSON builds a faithful ancient-schema record: a valid protojson
// Actor whose `status` has been rewritten from the nested {"state": ...} object
// back to the bare enum string the pre-fork schema stored. The ancient record
// only ever carried the bare enum, so no other ActorStatus sub-field is present
// — this reconstruction matches what actually sits in the standing store.
func legacyActorJSON(t *testing.T, name, atespace, flatStatus string) []byte {
	t.Helper()
	current := &ateapipb.Actor{
		Metadata:               &ateapipb.ResourceMetadata{Name: name, Atespace: atespace, Version: 1},
		ActorTemplateNamespace: "default",
		ActorTemplateName:      "test-template",
		Status:                 &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_SUSPENDED},
	}
	nested, err := protojson.Marshal(current)
	if err != nil {
		t.Fatalf("protojson.Marshal seed actor: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(nested, &obj); err != nil {
		t.Fatalf("unmarshal seed actor to map: %v", err)
	}
	flatRaw, err := json.Marshal(flatStatus)
	if err != nil {
		t.Fatalf("marshal flat status: %v", err)
	}
	obj["status"] = flatRaw
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("re-marshal ancient actor: %v", err)
	}
	return out
}

// TestLegacyStatusToActorState covers the pure enum-name transform: every
// STATUS_<X> token maps to the defined ACTOR_STATE_<X>, and any token that is
// unprefixed or whose transform is not a defined ActorState fails closed.
func TestLegacyStatusToActorState(t *testing.T) {
	ok := map[string]string{
		"STATUS_UNSPECIFIED": "ACTOR_STATE_UNSPECIFIED",
		"STATUS_RESUMING":    "ACTOR_STATE_RESUMING",
		"STATUS_RUNNING":     "ACTOR_STATE_RUNNING",
		"STATUS_SUSPENDING":  "ACTOR_STATE_SUSPENDING",
		"STATUS_SUSPENDED":   "ACTOR_STATE_SUSPENDED",
		"STATUS_PAUSING":     "ACTOR_STATE_PAUSING",
		"STATUS_PAUSED":      "ACTOR_STATE_PAUSED",
		"STATUS_CRASHED":     "ACTOR_STATE_CRASHED",
		"STATUS_DELETING":    "ACTOR_STATE_DELETING",
	}
	for in, want := range ok {
		got, mapped := legacyStatusToActorState(in)
		if !mapped || got != want {
			t.Errorf("legacyStatusToActorState(%q) = (%q, %v), want (%q, true)", in, got, mapped, want)
		}
	}

	// Fail-closed: unprefixed, unknown suffix (would transform to an undefined
	// ActorState), the ExternalVolume.Status tokens that share the STATUS_
	// prefix but are NOT actor states, and empty.
	for _, bad := range []string{
		"ACTOR_STATE_RUNNING", // already-nested-style token, no STATUS_ prefix
		"STATUS_BOGUS",        // maps to undefined ACTOR_STATE_BOGUS
		"STATUS_PENDING",      // ExternalVolume.Status, not an ActorState
		"STATUS_CREATED",      // ExternalVolume.Status, not an ActorState
		"RUNNING",             // no prefix
		"",                    // empty
	} {
		if got, mapped := legacyStatusToActorState(bad); mapped {
			t.Errorf("legacyStatusToActorState(%q) = (%q, true), want fail-closed (_, false)", bad, got)
		}
	}
}

// TestMigrateLegacyResidentJSON_MatchesFlatStatus asserts the record-level
// rewrite turns a flat-string status into the nested shape and leaves an
// already-nested record (idempotent) and non-Actor messages untouched.
func TestMigrateLegacyResidentJSON_MatchesFlatStatus(t *testing.T) {
	legacy := legacyActorJSON(t, "session-1", "ns1", "STATUS_CRASHED")
	migrated, ok := migrateLegacyResidentJSON(legacy, &ateapipb.Actor{})
	if !ok {
		t.Fatalf("migrateLegacyResidentJSON did not match a flat-string record")
	}
	got := &ateapipb.Actor{}
	if err := protojson.Unmarshal(migrated, got); err != nil {
		t.Fatalf("migrated payload does not parse as protojson: %v", err)
	}
	if got.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_CRASHED {
		t.Errorf("migrated state = %v, want ACTOR_STATE_CRASHED", got.GetStatus().GetState())
	}

	// Already-nested current record must not match (idempotent — leaves the
	// caller's binary-then-protojson path to handle it).
	current, err := protojson.Marshal(&ateapipb.Actor{
		Metadata: &ateapipb.ResourceMetadata{Name: "n", Atespace: "ns1"},
		Status:   &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_RUNNING},
	})
	if err != nil {
		t.Fatalf("marshal current actor: %v", err)
	}
	if _, ok := migrateLegacyResidentJSON(current, &ateapipb.Actor{}); ok {
		t.Errorf("migrateLegacyResidentJSON matched an already-nested record, want no-match")
	}

	// Non-Actor message must never match.
	if _, ok := migrateLegacyResidentJSON(legacy, &ateapipb.Worker{}); ok {
		t.Errorf("migrateLegacyResidentJSON matched a non-Actor message, want no-match")
	}

	// Unmappable flat token fails closed (no migration, caller keeps its error).
	bogus := legacyActorJSON(t, "session-2", "ns1", "STATUS_BOGUS")
	if _, ok := migrateLegacyResidentJSON(bogus, &ateapipb.Actor{}); ok {
		t.Errorf("migrateLegacyResidentJSON matched an unmappable token, want fail-closed no-match")
	}
}

// TestUnmarshalResident_MigratesLegacyFlatStatus exercises the read-path entry
// point directly: a flat-string record decodes via the third migration tier,
// binary and current-nested records still decode, and an unmappable flat token
// propagates a loud error naming all three failed tiers.
func TestUnmarshalResident_MigratesLegacyFlatStatus(t *testing.T) {
	legacy := legacyActorJSON(t, "session-1", "ns1", "STATUS_SUSPENDED")
	got := &ateapipb.Actor{}
	if err := unmarshalResident(legacy, got); err != nil {
		t.Fatalf("unmarshalResident on legacy flat-status record: %v", err)
	}
	if got.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("decoded state = %v, want ACTOR_STATE_SUSPENDED", got.GetStatus().GetState())
	}

	// Unmappable flat token: no tier succeeds, loud error.
	bogus := legacyActorJSON(t, "session-2", "ns1", "STATUS_BOGUS")
	if err := unmarshalResident(bogus, &ateapipb.Actor{}); err == nil {
		t.Errorf("expected unmarshalResident to fail closed on an unmappable flat token, got nil")
	}
}

// TestGetActor_MigratesLegacyFlatStatus is the end-to-end proof through the real
// single-record read path: seed the ancient flat-string record raw under its
// actor key (exactly as it sits in the standing store) and assert GetActor
// returns the migrated actor rather than crashing on the protojson parse.
func TestGetActor_MigratesLegacyFlatStatus(t *testing.T) {
	_, s, ctx := setupTest(t)

	ref := resources.ActorRef{Atespace: "ns1", Name: "session-legacy"}
	raw := legacyActorJSON(t, ref.Name, ref.Atespace, "STATUS_SUSPENDED")
	if err := s.rdb.Set(ctx, actorDBKey(ref), raw, 0).Err(); err != nil {
		t.Fatalf("seeding legacy actor failed: %v", err)
	}

	actor, err := s.GetActor(ctx, ref)
	if err != nil {
		t.Fatalf("GetActor on legacy flat-status record: %v", err)
	}
	if actor.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("GetActor state = %v, want ACTOR_STATE_SUSPENDED", actor.GetStatus().GetState())
	}
}

// TestListActors_MigratesLegacyFlatStatus is the end-to-end proof through the
// list read path — the exact surface that bricks on the redis default lane
// (#2921). A legacy flat-status record must be returned, not dropped or crashed.
func TestListActors_MigratesLegacyFlatStatus(t *testing.T) {
	_, s, ctx := setupTest(t)

	ref := resources.ActorRef{Atespace: "ns1", Name: "session-legacy"}
	raw := legacyActorJSON(t, ref.Name, ref.Atespace, "STATUS_CRASHED")
	if err := s.rdb.Set(ctx, actorDBKey(ref), raw, 0).Err(); err != nil {
		t.Fatalf("seeding legacy actor failed: %v", err)
	}

	resp, err := s.ListActors(ctx, "ns1", store.ListOptions{PageSize: 1000})
	if err != nil {
		t.Fatalf("ListActors with a legacy flat-status record: %v", err)
	}
	var found *ateapipb.Actor
	for _, a := range resp.Items {
		if a.GetMetadata().GetName() == ref.Name {
			found = a
			break
		}
	}
	if found == nil {
		t.Fatalf("ListActors omitted the legacy actor %q (silent under-report — the skip-on-read failure mode)", ref.Name)
	}
	if found.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_CRASHED {
		t.Errorf("ListActors state = %v, want ACTOR_STATE_CRASHED", found.GetStatus().GetState())
	}
}
