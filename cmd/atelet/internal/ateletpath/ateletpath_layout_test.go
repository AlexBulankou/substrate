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
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/internal/nodepath"
)

// This file is the atelet half of the on-disk path contract; internal/ateompath
// carries the other half. The split is forced rather than chosen: this package
// lives under cmd/atelet/internal/, so nothing outside cmd/atelet/ can import
// it, and the paths declared here -- the image cache, the content-addressed
// static files, and the actor-scoped directories only atelet derives -- are
// unreachable from a test in internal/ateompath. The invariants are the same
// ones, applied to the surface this package owns.

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
