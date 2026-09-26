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

// Hermetic tests for the authorization model and the comparison that decides
// whether to write it.
//
// server_test.go covers the same package end-to-end, but it stands up
// PostgreSQL through testcontainers and skips outright when Docker is not
// reachable -- which is the normal case in CI and in an agent pod.  Everything
// here runs with no daemon, no network and no container, so the parts of the
// authz bootstrap that do not need a datastore stay covered in the
// environments that actually run the suite.
//
// The load-bearing subject is modelsEqual.  It is the whole of the decision
// "is the authorization model already current, or must a new one be written",
// and both of its wrong answers are bad in ways that are quiet: a false
// negative rewrites the model on every startup, a false positive leaves the
// cluster enforcing a stale model after a deploy that was supposed to change
// it.  Neither shows up as an error.
package authz

import (
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/protobuf/proto"
)

// embeddedModel compiles the embedded model.fga the way ensureStoreAndModel
// does.  Failing here means the shipped model does not parse at all.
func embeddedModel(t *testing.T) *openfgav1.AuthorizationModel {
	t.Helper()
	m, err := transformer.TransformDSLToProto(modelDSL)
	if err != nil {
		t.Fatalf("transform embedded model.fga: %v", err)
	}
	return m
}

// TestEmbeddedModelCompiles is the cheapest guard on the shipped artifact: a
// syntactically broken model.fga is a build-time-invisible, startup-fatal
// defect, because the embed succeeds and only TransformDSLToProto fails.
func TestEmbeddedModelCompiles(t *testing.T) {
	m := embeddedModel(t)

	if got := m.GetSchemaVersion(); got != "1.1" {
		t.Errorf("schema version = %q, want %q", got, "1.1")
	}
	if len(m.GetTypeDefinitions()) == 0 {
		t.Fatal("model has no type definitions")
	}
}

// TestEmbeddedModelDefinesTheTypesTheServerGrantsOn pins the type set by name.
// The model compiles fine with a type missing --- the DSL has no notion of a
// required type --- so a deletion would land silently and only surface as
// Check calls failing against an object type the server no longer knows.
func TestEmbeddedModelDefinesTheTypesTheServerGrantsOn(t *testing.T) {
	m := embeddedModel(t)

	got := map[string]bool{}
	for _, td := range m.GetTypeDefinitions() {
		got[td.GetType()] = true
	}

	for _, want := range []string{
		"user",
		"node",
		"worker",
		"global",
		"atespace",
		"actor_template",
		"actor",
	} {
		if !got[want] {
			t.Errorf("model does not define type %q", want)
		}
	}
}

// TestEmbeddedModelRelationsAreNamedByConvention enforces the naming rule the
// model file states in its own header comment: a relation that is evaluated as
// a runtime permission check starts with can_, and everything else is a noun
// describing a graph edge.  The rule is load-bearing rather than cosmetic ---
// callers pick the relation to Check by that prefix --- and nothing else
// enforces it, so a relation added as "get" instead of "can_get" would be
// unreachable from the call site that expects the prefix.
func TestEmbeddedModelRelationsAreNamedByConvention(t *testing.T) {
	m := embeddedModel(t)

	// Nouns the model uses as graph edges rather than as permission checks.
	edges := map[string]bool{
		"owner":            true,
		"editor":           true,
		"viewer":           true,
		"parent_global":    true,
		"parent_atespace":  true,
		"host_node":        true,
		"scheduled_worker": true,
	}

	for _, td := range m.GetTypeDefinitions() {
		for relation := range td.GetRelations() {
			if edges[relation] {
				continue
			}
			if len(relation) < 4 || relation[:4] != "can_" {
				t.Errorf("type %q relation %q is neither a known graph edge nor can_-prefixed", td.GetType(), relation)
			}
		}
	}
}

// TestModelsEqualIgnoresTheModelID is the case the implementation exists for.
// A model read back from the server carries a server-assigned Id; the desired
// model compiled from the DSL does not.  modelsEqual rebuilds both sides
// without the Id precisely so the comparison does not see that difference ---
// remove the rebuild and proto.Equal compares the Ids, returns false forever,
// and the controller writes a redundant authorization model on every single
// startup.
func TestModelsEqualIgnoresTheModelID(t *testing.T) {
	desired := embeddedModel(t)

	existing := proto.Clone(desired).(*openfgav1.AuthorizationModel)
	existing.Id = "01HQ000000000000000000000"

	if !modelsEqual(existing, desired) {
		t.Error("modelsEqual = false for two models differing only in Id, want true")
	}
}

// TestModelsEqualMatchesTheEmbeddedModelAgainstItself is the steady state: on
// a restart with no model change, the model read back must compare equal to
// the one just compiled, or the bootstrap is not idempotent.
func TestModelsEqualMatchesTheEmbeddedModelAgainstItself(t *testing.T) {
	if a, b := embeddedModel(t), embeddedModel(t); !modelsEqual(a, b) {
		t.Error("modelsEqual = false for the embedded model against itself, want true")
	}
}

// TestModelsEqualSeparatesModelsThatDiffer covers the other direction, one
// field at a time.  Each of these is a real change an author could make to
// model.fga, and each must be detected --- a missed difference leaves the
// cluster authorizing against the previous model with no signal.
func TestModelsEqualSeparatesModelsThatDiffer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(m *openfgav1.AuthorizationModel)
	}{
		{
			// Note: modelsEqual's leading schema-version check is a redundant
			// fast path, not a separate behaviour --- both rebuilt messages
			// carry SchemaVersion, so proto.Equal rejects the mismatch on its
			// own.  Deleting that early return is an equivalent mutation and
			// no test can kill it.  This case pins the observable answer,
			// which is what callers depend on either way.
			name: "schema version",
			mutate: func(m *openfgav1.AuthorizationModel) {
				m.SchemaVersion = "1.0"
			},
		},
		{
			name: "a type is removed",
			mutate: func(m *openfgav1.AuthorizationModel) {
				m.TypeDefinitions = m.GetTypeDefinitions()[1:]
			},
		},
		{
			name: "a type is renamed",
			mutate: func(m *openfgav1.AuthorizationModel) {
				m.GetTypeDefinitions()[0].Type = "renamed"
			},
		},
		{
			name: "a relation is added to a type",
			mutate: func(m *openfgav1.AuthorizationModel) {
				for _, td := range m.GetTypeDefinitions() {
					if len(td.GetRelations()) == 0 {
						continue
					}
					var existing *openfgav1.Userset
					for _, u := range td.GetRelations() {
						existing = u
						break
					}
					td.GetRelations()["can_do_something_new"] = existing
					return
				}
			},
		},
		{
			name: "a condition is added",
			mutate: func(m *openfgav1.AuthorizationModel) {
				if m.Conditions == nil {
					m.Conditions = map[string]*openfgav1.Condition{}
				}
				m.Conditions["never"] = &openfgav1.Condition{
					Name:       "never",
					Expression: "false",
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := embeddedModel(t)
			desired := embeddedModel(t)
			tc.mutate(desired)

			// Guard against a mutate that silently did nothing: the case
			// would then pass for the wrong reason.
			if proto.Equal(existing, desired) {
				t.Fatal("the mutation did not change the model; this case proves nothing")
			}

			if modelsEqual(existing, desired) {
				t.Error("modelsEqual = true for models that differ, want false")
			}
		})
	}
}

// TestModelsEqualIsSymmetric guards an asymmetry that would make the result
// depend on which side happened to be read from the server.
func TestModelsEqualIsSymmetric(t *testing.T) {
	existing := embeddedModel(t)
	desired := embeddedModel(t)
	desired.SchemaVersion = "1.0"

	if modelsEqual(existing, desired) != modelsEqual(desired, existing) {
		t.Error("modelsEqual disagrees with itself when the arguments are swapped")
	}
}
