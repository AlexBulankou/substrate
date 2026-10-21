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

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// fakeActorClient serves GetActor from a stored actor and records the
// update it is asked to make.
type fakeActorClient struct {
	actor     *ateapipb.Actor
	getErr    error
	updateReq *ateapipb.UpdateActorRequest
}

func (f *fakeActorClient) GetActor(_ context.Context, _ *ateapipb.GetActorRequest, _ ...grpc.CallOption) (*ateapipb.Actor, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return proto.Clone(f.actor).(*ateapipb.Actor), nil
}

func (f *fakeActorClient) UpdateActor(_ context.Context, in *ateapipb.UpdateActorRequest, _ ...grpc.CallOption) (*ateapipb.Actor, error) {
	f.updateReq = in
	return proto.Clone(in.GetActor()).(*ateapipb.Actor), nil
}

// TestUpdateActorRepointsTemplate checks the read-modify-write: the new
// template is written against the uid and version that were just read, and
// nothing else on the actor changes.
func TestUpdateActorRepointsTemplate(t *testing.T) {
	client := &fakeActorClient{actor: &ateapipb.Actor{
		Metadata: &ateapipb.ResourceMetadata{
			Atespace: "space-1",
			Name:     "actor-1",
			Uid:      "0b5d7c1e-6a43-4f6e-8d2a-3c9f1e7a2b10",
			Version:  7,
		},
		ActorTemplate: &ateapipb.ObjectRef{Atespace: "space-1", Name: "tmpl-old"},
		SourceTag:     &ateapipb.ObjectRef{Atespace: "space-1", Name: "tag-1"},
	}}
	newRef, err := parseAtespacedName("tmpl-new", "space-1")
	if err != nil {
		t.Fatal(err)
	}
	ref := &ateapipb.ObjectRef{Atespace: "space-1", Name: "actor-1"}
	if _, err := updateActor(context.Background(), client, ref, func(a *ateapipb.Actor) { a.ActorTemplate = newRef }); err != nil {
		t.Fatalf("updateActor: %v", err)
	}

	got := client.updateReq.GetActor()
	if got.GetActorTemplate().GetName() != "tmpl-new" || got.GetActorTemplate().GetAtespace() != "space-1" {
		t.Errorf("template = %v, want space-1/tmpl-new", got.GetActorTemplate())
	}
	if got.GetMetadata().GetUid() != client.actor.GetMetadata().GetUid() || got.GetMetadata().GetVersion() != 7 {
		t.Errorf("preconditions = uid %q version %d, want the fetched uid and version 7", got.GetMetadata().GetUid(), got.GetMetadata().GetVersion())
	}
	if !proto.Equal(got.GetSourceTag(), client.actor.GetSourceTag()) {
		t.Errorf("source tag changed: %v", got.GetSourceTag())
	}
}

// TestUpdateActorGetFailure checks that a failed read never sends an update.
func TestUpdateActorGetFailure(t *testing.T) {
	client := &fakeActorClient{getErr: errors.New("not found")}
	ref := &ateapipb.ObjectRef{Atespace: "space-1", Name: "actor-1"}
	if _, err := updateActor(context.Background(), client, ref, func(*ateapipb.Actor) {}); err == nil {
		t.Fatal("updateActor succeeded on a failed GetActor")
	}
	if client.updateReq != nil {
		t.Error("UpdateActor was called after GetActor failed")
	}
}
