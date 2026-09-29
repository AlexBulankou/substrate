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

package ateletpath

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/internal/nodepath"
)

// This file is the on-disk path contract for the surface atelet owns. It used
// to be one half of a pair: internal/ateompath carried the other, and the
// split was forced rather than chosen, because this package lives under
// cmd/atelet/internal/ and nothing outside cmd/atelet/ can import it.
// Upstream has since deleted internal/ateompath, so this is the whole
// contract, and the invariants that suite carried have been brought here
// rather than deleted with the package that happened to host them.

const (
	testActorUID  = "123e4567-e89b-12d3-a456-426614174000"
	otherActorUID = "987f6543-e21b-32d1-b654-246614174111"
)

// TestLayoutIsStable pins the literal on-disk layout this package declares.
//
// ateom and atelet are separate binaries, built and rolled independently, and
// they must agree on these strings. A rename that looks local is really a wire
// change between two processes: the writer starts using the new name while the
// reader still looks at the old one, and the symptom is a missing file rather
// than a build break. Spelling the strings out here makes that class of change
// impossible to land silently.
func TestLayoutIsStable(t *testing.T) {
	const (
		actor  = "/var/lib/ate/actors/" + testActorUID
		bundle = actor + "/bundles/main"
	)
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ImageCacheDir", ImageCacheDir, "/var/lib/ate/image-cache"},

		{"RunSCBinaryPath", RunSCBinaryPath("deadbeef"), "/var/lib/ate/static-files/runsc-deadbeef"},
		{"GVisorReleaseDir", GVisorReleaseDir("deadbeef"), "/var/lib/ate/static-files/gvisor-deadbeef"},

		{"ActorPath", ActorPath(testActorUID), actor},
		{"ActorSandboxAssetsFile", ActorSandboxAssetsFile(testActorUID), actor + "/sandbox-assets.json"},
		{"OCIBundleDir", OCIBundleDir(testActorUID), actor + "/bundles"},
		{"OCIBundlePath", OCIBundlePath(testActorUID, "main"), bundle},
		{"CheckpointStateDir", CheckpointStateDir(testActorUID), actor + "/checkpoint-state"},
		{"LocalCheckpointsDir", LocalCheckpointsDir(testActorUID), actor + "/local-checkpoint"},
		{"LocalSnapshotDir", LocalSnapshotDir(testActorUID, "snap"), actor + "/local-checkpoint/snap"},
		{"DurableDirVolumeMountsDir", DurableDirVolumeMountsDir(testActorUID), actor + "/durable-dir"},
		{"DurableDirVolumeMountPoint", DurableDirVolumeMountPoint(testActorUID, "vol"), actor + "/durable-dir/vol"},
		{"SystemInfoVolumeRootsDir", SystemInfoVolumeRootsDir(testActorUID), actor + "/system-info"},
		{"SystemInfoVolumeRoot", SystemInfoVolumeRoot(testActorUID, "vol"), actor + "/system-info/vol"},
		{"RestoreStateDir", RestoreStateDir(testActorUID), actor + "/restore-state"},
		{"VolumesDir", VolumesDir(testActorUID), actor + "/volumes"},
		{"VolumeHostPath", VolumeHostPath(testActorUID, "vol"), actor + "/volumes/vol"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}

// TestContentAddressedPathsSeparateTheirKinds checks that a runsc binary and a
// gVisor release directory sharing one sha256 do not land on the same path:
// both are content-addressed into nodepath.StaticFilesDir, and the prefixes are
// the only thing keeping them apart.
func TestContentAddressedPathsSeparateTheirKinds(t *testing.T) {
	const sha = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	bin, release := RunSCBinaryPath(sha), GVisorReleaseDir(sha)
	if bin == release {
		t.Fatalf("RunSCBinaryPath and GVisorReleaseDir both resolve to %q for sha %s", bin, sha)
	}
	for name, got := range map[string]string{"RunSCBinaryPath": bin, "GVisorReleaseDir": release} {
		if !isUnderDir(got, nodepath.StaticFilesDir) {
			t.Errorf("%s(%q) = %q, want a path under nodepath.StaticFilesDir %q", name, sha, got, nodepath.StaticFilesDir)
		}
	}
	if RunSCBinaryPath(sha) == RunSCBinaryPath(strings.Repeat("f", 64)) {
		t.Error("RunSCBinaryPath is not content-addressed: two shas share a path")
	}
}

// TestSystemInfoRootsAreOutsideDurableDirMounts guards the exclusion
// SystemInfoVolumeRootsDir documents: the micro-VM checkpoint tars all of
// DurableDirVolumeMountsDir, so system-info volumes -- which atelet regenerates
// on every Run/Restore and must never be captured -- are excluded only by
// living somewhere else. Nesting them would silently start shipping
// regenerated node state inside every snapshot.
func TestSystemInfoRootsAreOutsideDurableDirMounts(t *testing.T) {
	durable := DurableDirVolumeMountsDir(testActorUID)
	for name, got := range map[string]string{
		"SystemInfoVolumeRootsDir": SystemInfoVolumeRootsDir(testActorUID),
		"SystemInfoVolumeRoot":     SystemInfoVolumeRoot(testActorUID, "vol"),
	} {
		if isUnderDir(got, durable) {
			t.Errorf("%s = %q is under DurableDirVolumeMountsDir(%q); the micro-VM checkpoint would capture system-info contents", name, got, durable)
		}
	}
}

// actorScopedPaths returns every path this package derives from an actor UID,
// keyed by constructor name, so the containment, collision and cross-actor
// invariants below cover each of them.
func actorScopedPaths(uid string) map[string]string {
	return map[string]string{
		"ActorSandboxAssetsFile":     ActorSandboxAssetsFile(uid),
		"OCIBundleDir":               OCIBundleDir(uid),
		"OCIBundlePath":              OCIBundlePath(uid, "main"),
		"CheckpointStateDir":         CheckpointStateDir(uid),
		"LocalCheckpointsDir":        LocalCheckpointsDir(uid),
		"LocalSnapshotDir":           LocalSnapshotDir(uid, "snap"),
		"DurableDirVolumeMountsDir":  DurableDirVolumeMountsDir(uid),
		"DurableDirVolumeMountPoint": DurableDirVolumeMountPoint(uid, "vol"),
		"SystemInfoVolumeRootsDir":   SystemInfoVolumeRootsDir(uid),
		"SystemInfoVolumeRoot":       SystemInfoVolumeRoot(uid, "vol"),
		"RestoreStateDir":            RestoreStateDir(uid),
		"VolumesDir":                 VolumesDir(uid),
		"VolumeHostPath":             VolumeHostPath(uid, "vol"),
	}
}

// TestActorScopedPathsStayUnderActorPath is what makes atelet's removeActorDirs
// safe: it reclaims an actor by deleting ActorPath(uid) alone, on the stated
// grounds that nothing else on the node holds that actor's state. A constructor
// that joined to nodepath.BasePath instead would leak state past termination
// without any caller changing.
func TestActorScopedPathsStayUnderActorPath(t *testing.T) {
	root := ActorPath(testActorUID)
	for name, got := range actorScopedPaths(testActorUID) {
		if !isUnderDir(got, root) {
			t.Errorf("%s = %q, want a path under ActorPath = %q", name, got, root)
		}
	}
	if !isUnderDir(root, nodepath.ActorsDir) {
		t.Errorf("ActorPath = %q, want a path under nodepath.ActorsDir = %q", root, nodepath.ActorsDir)
	}
}

// TestActorScopedPathsDoNotCollide checks that no two subsystems were handed
// the same directory. A collision is silent: both sides create it, both write
// into it, and the damage only shows up as one subsystem's files vanishing when
// the other resets its own directory.
func TestActorScopedPathsDoNotCollide(t *testing.T) {
	seen := map[string]string{ActorPath(testActorUID): "ActorPath"}
	for name, got := range actorScopedPaths(testActorUID) {
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s both resolve to %q", prev, name, got)
			continue
		}
		seen[got] = name
	}
}

// TestActorScopedPathsDoNotCrossActors is the isolation property: one actor's
// state must never sit inside another's tree, or terminating actor A would
// delete live state belonging to actor B.
func TestActorScopedPathsDoNotCrossActors(t *testing.T) {
	otherRoot := ActorPath(otherActorUID)
	for name, got := range actorScopedPaths(testActorUID) {
		if isUnderDir(got, otherRoot) || got == otherRoot {
			t.Errorf("%s for actor %s = %q, which lies inside actor %s's tree %q", name, testActorUID, got, otherActorUID, otherRoot)
		}
	}
}

// isUnderDir reports whether path lies strictly inside dir.
func isUnderDir(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// TestRestoreStateDirIsSeparateFromCheckpointStateDir keeps a suspension
// checkpoint from writing over the file runsc is still paging in. The two
// directories are distinct today only because two constructors happen to spell
// different names; nothing else holds them apart.
func TestRestoreStateDirIsSeparateFromCheckpointStateDir(t *testing.T) {
	restore := RestoreStateDir(testActorUID)
	checkpoint := CheckpointStateDir(testActorUID)
	if restore == checkpoint {
		t.Fatalf("RestoreStateDir and CheckpointStateDir are the same directory %q; a suspension checkpoint would overwrite the file runsc is still paging in", restore)
	}
	if isUnderDir(restore, checkpoint) || isUnderDir(checkpoint, restore) {
		t.Errorf("RestoreStateDir(%q) and CheckpointStateDir(%q) nest; they must be disjoint trees", restore, checkpoint)
	}
}

// TestContainmentHoldsForEveryValidIdentifier widens the containment invariant
// past the single UUID the rest of this file uses. The awkward identifiers are
// the short and dash-heavy ones, and a path bug that only shows up for "a" or
// "1-2-3" is invisible to a suite that only ever passes a UUID.
func TestContainmentHoldsForEveryValidIdentifier(t *testing.T) {
	// All DNS-1123 labels: lower-case alphanumerics and dashes, starting and
	// ending alphanumeric.
	uids := []string{
		"a",
		"0",
		"a-b",
		"actor-0",
		"1-2-3",
		testActorUID,
		strings.Repeat("a", 63), // the label length limit
	}
	for _, uid := range uids {
		root := ActorPath(uid)
		if !isUnderDir(root, nodepath.ActorsDir) {
			t.Errorf("ActorPath(%q) = %q escaped nodepath.ActorsDir %q", uid, root, nodepath.ActorsDir)
			continue
		}
		for name, got := range actorScopedPaths(uid) {
			if !isUnderDir(got, root) {
				t.Errorf("%s(%q) = %q, want a path under %q", name, uid, got, root)
			}
		}
	}
}

// TestUnvalidatedIdentifiersEscape records the precondition this package
// carries but does not enforce: it composes paths, it does not sanitise them,
// and filepath.Join cleans the result rather than rejecting it. Callers keep
// the invariant, so a new call site that skips validation gets no help here.
//
// The two shapes below are the ones with teeth, because atelet's
// removeActorDirs does os.RemoveAll(ActorPath(actorUID)):
//
//   - empty collapses ActorPath onto nodepath.ActorsDir itself, turning
//     "reclaim this actor" into "delete every actor on the node";
//   - a traversal element leaves the tree entirely.
//
// If this test ever fails, the package has grown its own guard. That is an
// improvement: assert the new behaviour here and drop the warning from the
// package doc.
func TestUnvalidatedIdentifiersEscape(t *testing.T) {
	if got := ActorPath(""); got != nodepath.ActorsDir {
		t.Errorf("ActorPath(%q) = %q, want %q -- an empty UID no longer collapses onto the actors root, so the caller-side non-empty check may be redundant now", "", got, nodepath.ActorsDir)
	}
	if got := ActorPath("../../etc"); isUnderDir(got, nodepath.ActorsDir) {
		t.Errorf("ActorPath(%q) = %q, unexpectedly contained in %q", "../../etc", got, nodepath.ActorsDir)
	}
}

// TestSocketPathsFitTheUnixLimit covers the sockets the layout tests do not. A
// unix socket path over the limit fails at bind time, on the node, at runtime
// -- there is no earlier signal.
func TestSocketPathsFitTheUnixLimit(t *testing.T) {
	// sun_path is 108 bytes including the NUL terminator.
	const maxUnixSocketLen = 107
	for name, got := range map[string]string{
		"AteomSupportSocket": nodepath.AteomSupportSocket,
	} {
		if len(got) > maxUnixSocketLen {
			t.Errorf("%s = %q is %d bytes, over the %d-byte unix socket limit", name, got, len(got), maxUnixSocketLen)
		}
	}
}

// TestEveryActorScopedConstructorIsRegistered is what keeps the three
// invariants above from quietly narrowing to the set of functions that existed
// the day they were written. They all read from one hand-maintained map, so a
// constructor added later is covered by nothing until somebody remembers to
// list it -- and forgetting looks exactly like passing.
//
// This reads the package's own source and requires every exported function
// taking an actorUID to appear in that map. Adding one without registering it
// fails here, naming the function.
func TestEveryActorScopedConstructorIsRegistered(t *testing.T) {
	// Deliberately outside the invariants, each for a reason that is checked
	// below rather than taken on trust.
	exempt := map[string]string{
		"ActorPath": "the tree root itself, not a path within it",
		"ActorDirs": "an aggregate of already-registered constructors, not a new path (asserted by TestActorDirsExposesOnlyRegisteredPaths)",
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "ateletpath.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing ateletpath.go: %v", err)
	}

	registered := actorScopedPaths(testActorUID)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !fn.Name.IsExported() {
			continue
		}
		if !takesActorUID(fn) {
			continue
		}
		name := fn.Name.Name
		if reason, ok := exempt[name]; ok {
			t.Logf("%s is exempt from the actor-tree invariants: %s", name, reason)
			continue
		}
		if _, ok := registered[name]; !ok {
			t.Errorf("%s takes an actorUID but is missing from actorScopedPaths, so the containment, collision and cross-actor invariants do not cover it; add it there (or to the exempt map, with a reason)", name)
		}
	}
}

// TestActorDirsExposesOnlyRegisteredPaths discharges the ActorDirs exemption
// above. ActorDirs is exempt on the grounds that it only aggregates paths the
// registry already covers -- an unchecked claim is exactly the kind of
// exemption that rots, because a field added later pointing somewhere new
// would inherit the exemption and be covered by nothing.
func TestActorDirsExposesOnlyRegisteredPaths(t *testing.T) {
	known := map[string]bool{ActorPath(testActorUID): true}
	for _, got := range actorScopedPaths(testActorUID) {
		known[got] = true
	}

	dirs := ActorDirs(testActorUID)
	v := reflect.ValueOf(dirs).Elem()
	checked := 0
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if !field.IsExported() || field.Type.Kind() != reflect.String {
			continue
		}
		got := v.Field(i).String()
		if got == "" {
			continue
		}
		checked++
		if !known[got] {
			t.Errorf("ActorDirs().%s = %q, which no registered constructor produces; either register the constructor behind it or drop ActorDirs from the exempt map", field.Name, got)
		}
	}
	if checked == 0 {
		t.Error("inspected no ActorDirs path fields, so this test asserted nothing; the proto shape must have changed")
	}
}

// takesActorUID reports whether fn's first parameter is the actor UID.
func takesActorUID(fn *ast.FuncDecl) bool {
	params := fn.Type.Params
	if params == nil || len(params.List) == 0 {
		return false
	}
	for _, name := range params.List[0].Names {
		if name.Name == "actorUID" {
			return true
		}
	}
	return false
}
