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

// Tests for the parts of this package that need no database.
//
// Every other test file here calls requirePool, which skips when Docker is
// unreachable -- so on a machine without a container runtime the package's
// ~2800 lines of tests assert nothing.  The logic below is pure: page-token
// encoding, the pgx error classifiers, the resource-metadata builders and the
// outbox wire format.  None of it needs Postgres to be wrong, so none of it
// should need Postgres to be tested.
//
// Two of these guard invariants that no database test would catch either,
// because they are about compatibility across time rather than behaviour at
// one point in it: the outbox tag byte's numeric values, and page tokens being
// rejected when replayed against a different scope.
package atepg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// --- outbox wire format ---------------------------------------------------

// TestWorkerEventTypeWireValuesArePinned pins the numeric values of the event
// types, because marshalWorkerEvent writes one of them as the payload's first
// byte and other replicas read that byte during a rolling deploy.  The
// constants are declared with iota, so inserting a new one in the middle
// renumbers every value after it.  Old and new replicas would then disagree
// about what a given tag means -- an update read as a delete -- with no error
// on either side.  Append only; never insert.
func TestWorkerEventTypeWireValuesArePinned(t *testing.T) {
	for _, tc := range []struct {
		eventType store.WorkerEventType
		want      int
	}{
		{store.WorkerEventCreated, 0},
		{store.WorkerEventUpdated, 1},
		{store.WorkerEventDeleted, 2},
	} {
		if got := int(tc.eventType); got != tc.want {
			t.Errorf("wire value = %d, want %d: the outbox tag byte is not free to change", got, tc.want)
		}
		// The tag is written as a single byte, so a value past 255 would be
		// truncated silently and alias an existing type.
		if tc.want > 255 {
			t.Errorf("wire value %d does not fit the one-byte tag", tc.want)
		}
	}
}

func TestMarshalWorkerEventRoundTrips(t *testing.T) {
	for _, eventType := range []store.WorkerEventType{
		store.WorkerEventCreated,
		store.WorkerEventUpdated,
		store.WorkerEventDeleted,
	} {
		worker := &ateapipb.Worker{
			Metadata: &ateapipb.ResourceMetadata{Atespace: "space-1", Name: "worker-1", Uid: "uid-1", Version: 3},
		}

		payload, err := marshalWorkerEvent(eventType, worker)
		if err != nil {
			t.Fatalf("marshalWorkerEvent(%d): %v", eventType, err)
		}
		if got := store.WorkerEventType(payload[0]); got != eventType {
			t.Errorf("tag byte = %d, want %d", got, eventType)
		}

		event, err := unmarshalWorkerEvent(payload)
		if err != nil {
			t.Fatalf("unmarshalWorkerEvent: %v", err)
		}
		if event.Type != eventType {
			t.Errorf("round-tripped type = %d, want %d", event.Type, eventType)
		}
		if !proto.Equal(event.Worker, worker) {
			t.Errorf("round-tripped worker = %v, want %v", event.Worker, worker)
		}
	}
}

// TestUnmarshalWorkerEventRejectsCorruptPayloads pins the loud-failure
// contract the function documents: a payload it cannot make sense of must
// error, so the caller resyncs, rather than decode to a zero event that
// downstream treats as a no-op.
func TestUnmarshalWorkerEventRejectsCorruptPayloads(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"empty payload", nil},
		{"unknown event type", []byte{0xff}},
		{"known type, unparseable proto", []byte{byte(store.WorkerEventCreated), 0xff, 0xff, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := unmarshalWorkerEvent(tc.payload); err == nil {
				t.Error("unmarshalWorkerEvent accepted a payload it cannot honour, want an error")
			}
		})
	}
}

// --- page tokens ----------------------------------------------------------

// TestDecodePageTokenRejectsAReplayFromAnotherScope is the one that matters
// most here.  Scope carries the atespace a scoped listing was issued for, so
// accepting a token from a different scope would resume one tenant's scan
// inside another's -- the token is opaque base64, so a caller could pass one
// along without ever knowing it was for a different atespace.
func TestDecodePageTokenRejectsAReplayFromAnotherScope(t *testing.T) {
	token := encodePageToken(kindActor, "space-a", []string{"actor-7"})

	got, err := decodePageToken(token, kindActor, "space-b", 1)
	if err == nil {
		t.Fatalf("decodePageToken accepted a token issued for another atespace, returning %+v", got)
	}
	if !errors.Is(err, store.ErrInvalidPageToken) {
		t.Errorf("error = %v, want it to wrap ErrInvalidPageToken so the API maps it to InvalidArgument", err)
	}
}

// TestDecodePageTokenRejectsAReplayFromAnotherMethod covers the sibling guard:
// the ordering columns differ per List method, so resuming one method's scan
// from another's token would read the key parts as columns they are not.
func TestDecodePageTokenRejectsAReplayFromAnotherMethod(t *testing.T) {
	token := encodePageToken(kindWorker, "", []string{"worker-3"})

	if _, err := decodePageToken(token, kindTag, "", 1); err == nil {
		t.Fatal("decodePageToken accepted a worker token presented to the tag listing")
	} else if !errors.Is(err, store.ErrInvalidPageToken) {
		t.Errorf("error = %v, want it to wrap ErrInvalidPageToken", err)
	}
}

func TestDecodePageTokenRejectsMalformedTokens(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"not base64", "!!!not-base64!!!"},
		{"base64 of something that is not JSON", "bm90IGpzb24="},
		{"unsupported version", encodeRawPageToken(t, pageToken{Version: pageTokenVersion + 1, Kind: kindActor, Last: []string{"a"}})},
		{"version zero, as an omitted field would decode", encodeRawPageToken(t, pageToken{Kind: kindActor, Last: []string{"a"}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodePageToken(tc.token, kindActor, "", 1); err == nil {
				t.Error("decodePageToken accepted a malformed token, want an error")
			} else if !errors.Is(err, store.ErrInvalidPageToken) {
				t.Errorf("error = %v, want it to wrap ErrInvalidPageToken", err)
			}
		})
	}
}

// TestDecodePageTokenEmptyMeansStartOfList pins the caller contract: a first
// page arrives with no token at all, and must not be treated as malformed.
func TestDecodePageTokenEmptyMeansStartOfList(t *testing.T) {
	token, err := decodePageToken("", kindAtespace, "", 1)
	if err != nil {
		t.Fatalf("decodePageToken(\"\"): %v", err)
	}
	if len(token.Last) != 0 {
		t.Errorf("Last = %v, want empty: an absent token cannot resume anywhere", token.Last)
	}
	if token.Kind != kindAtespace {
		t.Errorf("Kind = %q, want %q", token.Kind, kindAtespace)
	}
}

func TestPageTokenRoundTripsItsKeyParts(t *testing.T) {
	want := []string{"space-a", "actor-7"}

	token, err := decodePageToken(encodePageToken(kindActor, "space-a", want), kindActor, "space-a", len(want))
	if err != nil {
		t.Fatalf("decodePageToken: %v", err)
	}
	if strings.Join(token.Last, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("Last = %v, want %v", token.Last, want)
	}
}

// encodeRawPageToken encodes a token struct verbatim.  encodePageToken always
// stamps the current version, so the decoder's version guard is unreachable
// through it and needs a token built by hand to have anything to reject.
func encodeRawPageToken(t *testing.T, token pageToken) string {
	t.Helper()
	b, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("marshalling a raw page token: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// --- pgx error classification ---------------------------------------------

// TestPgErrCodeUnwraps pins that the classifiers see through wrapping.  Every
// call site wraps the driver error with %w before these run, so a classifier
// that only matched a bare *pgconn.PgError would report "not a unique
// violation" for every real unique violation and the store would surface
// Internal where it owes AlreadyExists.
func TestPgErrCodeUnwraps(t *testing.T) {
	bare := &pgconn.PgError{Code: "23505", ConstraintName: "actors_pkey"}
	wrapped := fmt.Errorf("inserting the actor row: %w", fmt.Errorf("in pool.Exec: %w", bare))

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"bare", bare},
		{"wrapped twice", wrapped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pgErrCode(tc.err); got != "23505" {
				t.Errorf("pgErrCode = %q, want %q", got, "23505")
			}
			if got := pgErrConstraint(tc.err); got != "actors_pkey" {
				t.Errorf("pgErrConstraint = %q, want %q", got, "actors_pkey")
			}
		})
	}
}

func TestPgErrCodeOnANonDriverError(t *testing.T) {
	err := errors.New("context deadline exceeded")

	if got := pgErrCode(err); got != "" {
		t.Errorf("pgErrCode = %q, want empty for a non-driver error", got)
	}
	if got := pgErrConstraint(err); got != "" {
		t.Errorf("pgErrConstraint = %q, want empty for a non-driver error", got)
	}
	if isUniqueViolation(err) {
		t.Error("isUniqueViolation = true for a non-driver error")
	}
	if isForeignKeyViolation(err) {
		t.Error("isForeignKeyViolation = true for a non-driver error")
	}
}

func TestIsUniqueViolation(t *testing.T) {
	if !isUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Error("isUniqueViolation = false for 23505")
	}
	if isUniqueViolation(&pgconn.PgError{Code: "23503"}) {
		t.Error("isUniqueViolation = true for a foreign-key violation")
	}
}

// TestIsForeignKeyViolationMatchesBothCodes pins the version-straddling
// behaviour the implementation comment describes: PostgreSQL 18 split
// ON DELETE RESTRICT out into 23001, while older servers report 23503 for
// both.  Dropping either code silently breaks the store against one server
// generation, and a container-backed test only ever exercises whichever
// version the image pins.
func TestIsForeignKeyViolationMatchesBothCodes(t *testing.T) {
	for _, code := range []string{"23503", "23001"} {
		if !isForeignKeyViolation(&pgconn.PgError{Code: code}) {
			t.Errorf("isForeignKeyViolation = false for %s", code)
		}
	}
	if isForeignKeyViolation(&pgconn.PgError{Code: "23505"}) {
		t.Error("isForeignKeyViolation = true for a unique violation")
	}
}

// --- delete error mapping -------------------------------------------------

// TestMapDeleteError walks the branches that decide what a caller sees when a
// guarded delete matches no row.  The distinction is the whole point: "it was
// never there" and "someone else changed it under you" are different answers
// and the client retries only one of them.
func TestMapDeleteError(t *testing.T) {
	const (
		uid     = "uid-1"
		version = int64(4)
	)

	for _, tc := range []struct {
		name         string
		err          error
		precondition store.DeletePreconditions
		want         error
	}{
		{
			name: "the row is gone",
			err:  pgx.ErrNoRows,
			want: store.ErrNotFound,
		},
		{
			name:         "the row is there and still matches, so it moved between the two statements",
			precondition: store.DeletePreconditions{UID: uid, Version: version},
			want:         store.ErrVersionConflict,
		},
		{
			name:         "a different incarnation holds the name",
			precondition: store.DeletePreconditions{UID: "uid-2"},
			want:         store.ErrUIDConflict,
		},
		{
			name:         "the same object moved on",
			precondition: store.DeletePreconditions{UID: uid, Version: 9},
			want:         store.ErrVersionConflict,
		},
		{
			name:         "an unguarded delete that matched nothing",
			precondition: store.DeletePreconditions{},
			want:         store.ErrVersionConflict,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapDeleteError(tc.err, uid, version, tc.precondition)
			if !errors.Is(got, tc.want) {
				t.Errorf("mapDeleteError = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMapDeleteErrorPropagatesAnUnexpectedReadFailure keeps a real failure
// from being laundered into a precondition verdict: if the follow-up read
// itself failed, the store does not know whether the row exists and must not
// claim it does.
func TestMapDeleteErrorPropagatesAnUnexpectedReadFailure(t *testing.T) {
	cause := errors.New("connection reset by peer")

	got := mapDeleteError(cause, "uid-1", 1, store.DeletePreconditions{})

	if !errors.Is(got, cause) {
		t.Errorf("mapDeleteError = %v, want it to wrap the underlying read failure", got)
	}
	for _, sentinel := range []error{store.ErrNotFound, store.ErrVersionConflict, store.ErrUIDConflict} {
		if errors.Is(got, sentinel) {
			t.Errorf("mapDeleteError reported %v for a read that failed outright", sentinel)
		}
	}
}

// --- resource metadata ----------------------------------------------------

func TestSetCreateMetadata(t *testing.T) {
	metadata := &ateapipb.ResourceMetadata{Atespace: "space-1", Name: "actor-1"}

	setCreateMetadata(metadata)

	if metadata.GetUid() == "" {
		t.Error("Uid is empty after setCreateMetadata")
	}
	if got := metadata.GetVersion(); got != 1 {
		t.Errorf("Version = %d, want 1 for a freshly created resource", got)
	}
	if !metadata.GetCreateTime().AsTime().Equal(metadata.GetUpdateTime().AsTime()) {
		t.Error("CreateTime and UpdateTime differ on a resource that has never been updated")
	}
	if metadata.GetAtespace() != "space-1" || metadata.GetName() != "actor-1" {
		t.Error("setCreateMetadata overwrote the caller's atespace/name")
	}
}

func TestSetCreateMetadataIssuesADistinctUIDEachTime(t *testing.T) {
	first := &ateapipb.ResourceMetadata{}
	second := &ateapipb.ResourceMetadata{}

	setCreateMetadata(first)
	setCreateMetadata(second)

	if first.GetUid() == second.GetUid() {
		t.Error("two resources were created with the same Uid; the uid is what distinguishes incarnations sharing a name")
	}
}

// TestSetUpdateMetadataPreservesIdentity pins the fields an update must carry
// forward.  Losing Uid would make the resource a new incarnation to every
// precondition check; losing CreateTime would make creation time drift
// forward on every write.
func TestSetUpdateMetadataPreservesIdentity(t *testing.T) {
	createTime := timestamppb.New(timestamppb.Now().AsTime().Add(-time.Hour))
	oldMeta := &ateapipb.ResourceMetadata{
		Atespace:   "space-1",
		Name:       "actor-1",
		Uid:        "uid-1",
		Version:    4,
		CreateTime: createTime,
		UpdateTime: createTime,
	}
	newMeta := &ateapipb.ResourceMetadata{Atespace: "space-1", Name: "actor-1"}

	setUpdateMetadata(newMeta, oldMeta)

	if got := newMeta.GetUid(); got != "uid-1" {
		t.Errorf("Uid = %q, want it carried forward from the stored metadata", got)
	}
	if got := newMeta.GetVersion(); got != 5 {
		t.Errorf("Version = %d, want 5", got)
	}
	if !newMeta.GetCreateTime().AsTime().Equal(createTime.AsTime()) {
		t.Errorf("CreateTime = %v, want the original %v", newMeta.GetCreateTime().AsTime(), createTime.AsTime())
	}
	if !newMeta.GetUpdateTime().AsTime().After(createTime.AsTime()) {
		t.Error("UpdateTime was not advanced past the previous write")
	}
}

// TestNewUpdateMetadataLeavesItsInputAlone guards the clone.  The caller holds
// the stored metadata while the update is in flight, so mutating it in place
// would corrupt the value a retry or an error path reads back.
func TestNewUpdateMetadataLeavesItsInputAlone(t *testing.T) {
	current := &ateapipb.ResourceMetadata{Uid: "uid-1", Version: 4, CreateTime: timestamppb.Now()}
	before := proto.Clone(current).(*ateapipb.ResourceMetadata)

	updated := newUpdateMetadata(current)

	if !proto.Equal(current, before) {
		t.Errorf("newUpdateMetadata mutated its argument: %v, want %v", current, before)
	}
	if got := updated.GetVersion(); got != 5 {
		t.Errorf("Version = %d, want 5", got)
	}
}

func TestNewCreateMetadata(t *testing.T) {
	metadata := newCreateMetadata("space-1", "actor-1")

	if metadata.GetAtespace() != "space-1" || metadata.GetName() != "actor-1" {
		t.Errorf("atespace/name = %q/%q, want space-1/actor-1", metadata.GetAtespace(), metadata.GetName())
	}
	if metadata.GetUid() == "" {
		t.Error("Uid is empty")
	}
	if got := metadata.GetVersion(); got != 1 {
		t.Errorf("Version = %d, want 1", got)
	}
}

// TestValidateProtoMetadataMatchesColumns covers the consistency check between
// the indexed columns and the metadata inside the stored proto.  They are
// written together and can only disagree if something wrote one without the
// other, so a mismatch means the row is corrupt and must not be served.
func TestValidateProtoMetadataMatchesColumns(t *testing.T) {
	metadata := &ateapipb.ResourceMetadata{Uid: "uid-1", Version: 4}

	if err := validateProtoMetadataMatchesColumns("actor", metadata, "uid-1", 4); err != nil {
		t.Errorf("validateProtoMetadataMatchesColumns = %v for a consistent row, want nil", err)
	}
	if err := validateProtoMetadataMatchesColumns("actor", metadata, "uid-2", 4); err == nil {
		t.Error("a uid disagreeing with the column projection was accepted")
	}
	if err := validateProtoMetadataMatchesColumns("actor", metadata, "uid-1", 9); err == nil {
		t.Error("a version disagreeing with the column projection was accepted")
	}
}

// --- mutation validation --------------------------------------------------

// TestValidateUpdateActorTemplateMutation pins the immutable fields.  The
// mutate callback is caller-supplied, so nothing else stops it renaming the
// resource mid-update -- which would write the mutated proto into the row
// addressed by the original name, leaving the stored name and the indexed name
// permanently disagreeing.
func TestValidateUpdateActorTemplateMutation(t *testing.T) {
	stored := &ateapipb.ActorTemplate{
		Metadata: &ateapipb.ResourceMetadata{Atespace: "space-1", Name: "template-1"},
	}

	for _, tc := range []struct {
		name    string
		mutated *ateapipb.ActorTemplate
		wantErr bool
	}{
		{
			name:    "untouched identity",
			mutated: &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "space-1", Name: "template-1"}},
		},
		{
			name:    "atespace changed",
			mutated: &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "space-2", Name: "template-1"}},
			wantErr: true,
		},
		{
			name:    "name changed",
			mutated: &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "space-1", Name: "template-2"}},
			wantErr: true,
		},
		{
			name:    "metadata dropped entirely",
			mutated: &ateapipb.ActorTemplate{},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUpdateActorTemplateMutation(stored, tc.mutated)
			if tc.wantErr && err == nil {
				t.Error("validateUpdateActorTemplateMutation accepted a mutation of an immutable field")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateUpdateActorTemplateMutation = %v, want nil", err)
			}
		})
	}
}
