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

package ateompath

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testActorUID  = "123e4567-e89b-12d3-a456-426614174000"
	otherActorUID = "987f6543-e21b-32d1-b654-246614174111"
)

// TestLayoutIsStable pins the literal on-disk layout.
//
// This package exists because ateom and atelet -- separate binaries, built and
// rolled independently -- must agree on these paths. A rename that looks local
// is really a wire change between two processes: the writer starts using the
// new name while the reader still looks at the old one, and the symptom is a
// missing file rather than a build break. Spelling the strings out here makes
// that class of change impossible to land silently.
func TestLayoutIsStable(t *testing.T) {
	const (
		actor  = "/var/lib/ateom-gvisor/actors/" + testActorUID
		bundle = actor + "/bundles/main"
	)
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"BasePath", BasePath, "/var/lib/ateom-gvisor"},
		{"StaticFilesDir", StaticFilesDir, "/var/lib/ateom-gvisor/static-files"},
		{"ImageCacheDir", ImageCacheDir, "/var/lib/ateom-gvisor/image-cache"},
		{"ActorsDir", ActorsDir, "/var/lib/ateom-gvisor/actors"},
		{"AteomSupportSocket", AteomSupportSocket, "/var/lib/ateom-gvisor/ateom-support.sock"},
		{"DurableDirTarFile", DurableDirTarFile, "durable-dir.tar"},

		{"RunSCBinaryPath", RunSCBinaryPath("deadbeef"), "/var/lib/ateom-gvisor/static-files/runsc-deadbeef"},
		{"GVisorReleaseDir", GVisorReleaseDir("deadbeef"), "/var/lib/ateom-gvisor/static-files/gvisor-deadbeef"},
		{"AteletOTLPSocketPath", AteletOTLPSocketPath(), "/var/lib/ateom-gvisor/atelet-otlp.sock"},
		{"StagingDirPrefix", StagingDirPrefix(), "/var/lib/ateom-gvisor/staging"},
		{"KubeletPluginSocketPath", KubeletPluginSocketPath("csi.substrate.dev"), "/var/lib/kubelet/plugins/csi.substrate.dev/csi.sock"},

		{"AteomsDir", AteomsDir(), "/var/lib/ateom-gvisor/ateoms"},
		{"AteomPath", AteomPath(testActorUID), "/var/lib/ateom-gvisor/ateoms/" + testActorUID},
		{"AteomSocketPath", AteomSocketPath(testActorUID), "/var/lib/ateom-gvisor/ateoms/" + testActorUID + "/ateom.sock"},

		{"ActorNetNSName", ActorNetNSName(testActorUID), "ateom-actor:" + testActorUID},
		{"ActorNetNSPath", ActorNetNSPath(testActorUID), "/run/netns/ateom-actor:" + testActorUID},

		{"ActorPath", ActorPath(testActorUID), actor},
		{"ActorResolvConfPath", ActorResolvConfPath(testActorUID), actor + "/resolv.conf"},
		{"ActorSandboxAssetsFile", ActorSandboxAssetsFile(testActorUID), actor + "/sandbox-assets.json"},
		{"RunSCStateDir", RunSCStateDir(testActorUID), actor + "/runsc-state"},
		{"OCIBundleDir", OCIBundleDir(testActorUID), actor + "/bundles"},
		{"OCIBundlePath", OCIBundlePath(testActorUID, "main"), bundle},
		{"ImageVolumeMountPath", ImageVolumeMountPath(testActorUID, "main", "vol"), bundle + "/volumes/vol"},
		{"ImageVolumeMountPathInBundle", ImageVolumeMountPathInBundle(bundle, "vol"), bundle + "/volumes/vol"},
		{"RunscDebugLogDir", RunscDebugLogDir(testActorUID, "main"), actor + "/runsc-debug-logs/main"},
		{"CheckpointStateDir", CheckpointStateDir(testActorUID), actor + "/checkpoint-state"},
		{"LocalCheckpointsDir", LocalCheckpointsDir(testActorUID), actor + "/local-checkpoint"},
		{"LocalSnapshotDir", LocalSnapshotDir(testActorUID, "snap"), actor + "/local-checkpoint/snap"},
		{"DurableDirVolumeMountsDir", DurableDirVolumeMountsDir(testActorUID), actor + "/durable-dir"},
		{"DurableDirVolumeMountPoint", DurableDirVolumeMountPoint(testActorUID, "vol"), actor + "/durable-dir/vol"},
		{"SystemInfoVolumeRootsDir", SystemInfoVolumeRootsDir(testActorUID), actor + "/system-info"},
		{"SystemInfoVolumeRoot", SystemInfoVolumeRoot(testActorUID, "vol"), actor + "/system-info/vol"},
		{"RestoreStateDir", RestoreStateDir(testActorUID), actor + "/restore-state"},
		{"PIDFileDir", PIDFileDir(testActorUID), actor + "/pidfiles"},
		{"PIDFilePath", PIDFilePath(testActorUID, "main"), actor + "/pidfiles/main.pid"},
		{"VolumesDir", VolumesDir(testActorUID), actor + "/volumes"},
		{"VolumeHostPath", VolumeHostPath(testActorUID, "vol"), actor + "/volumes/vol"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}

// TestRestoreStateDirIsSeparateFromCheckpointStateDir guards the invariant the
// RestoreStateDir doc comment explains: `runsc restore -direct -background`
// demand-pages the checkpoint file while running, so a later suspension
// checkpoint must not be written over the file still being read.
func TestRestoreStateDirIsSeparateFromCheckpointStateDir(t *testing.T) {
	restore := RestoreStateDir(testActorUID)
	checkpoint := CheckpointStateDir(testActorUID)
	if restore == checkpoint {
		t.Fatalf("RestoreStateDir and CheckpointStateDir are the same directory %q; a suspension checkpoint would overwrite the file runsc is still paging in", restore)
	}
	if isUnder(restore, checkpoint) || isUnder(checkpoint, restore) {
		t.Errorf("RestoreStateDir(%q) and CheckpointStateDir(%q) nest; they must be disjoint trees", restore, checkpoint)
	}
}

// TestSystemInfoRootsAreOutsideDurableDirMounts guards the exclusion
// SystemInfoVolumeRootsDir documents: the micro-VM checkpoint tars all of
// DurableDirVolumeMountsDir, so system-info volumes -- which atelet
// regenerates on every Run/Restore and must never be captured -- are excluded
// only by living somewhere else. Nesting them would silently start shipping
// regenerated node state inside every snapshot.
func TestSystemInfoRootsAreOutsideDurableDirMounts(t *testing.T) {
	durable := DurableDirVolumeMountsDir(testActorUID)
	sysInfo := SystemInfoVolumeRootsDir(testActorUID)
	if isUnder(sysInfo, durable) {
		t.Errorf("SystemInfoVolumeRootsDir(%q) is under DurableDirVolumeMountsDir(%q); the micro-VM checkpoint would capture system-info contents", sysInfo, durable)
	}
	// Same check one level down, where the volumes actually land.
	if got := SystemInfoVolumeRoot(testActorUID, "vol"); isUnder(got, durable) {
		t.Errorf("SystemInfoVolumeRoot(%q) is under DurableDirVolumeMountsDir(%q)", got, durable)
	}
}

// actorScopedPaths returns every path this package derives from an actor UID,
// keyed by constructor name. Anything new belongs here so the containment,
// collision and cross-actor invariants below cover it for free.
func actorScopedPaths(uid string) map[string]string {
	return map[string]string{
		"ActorResolvConfPath":        ActorResolvConfPath(uid),
		"ActorSandboxAssetsFile":     ActorSandboxAssetsFile(uid),
		"RunSCStateDir":              RunSCStateDir(uid),
		"OCIBundleDir":               OCIBundleDir(uid),
		"OCIBundlePath":              OCIBundlePath(uid, "main"),
		"ImageVolumeMountPath":       ImageVolumeMountPath(uid, "main", "vol"),
		"RunscDebugLogDir":           RunscDebugLogDir(uid, "main"),
		"CheckpointStateDir":         CheckpointStateDir(uid),
		"LocalCheckpointsDir":        LocalCheckpointsDir(uid),
		"LocalSnapshotDir":           LocalSnapshotDir(uid, "snap"),
		"DurableDirVolumeMountsDir":  DurableDirVolumeMountsDir(uid),
		"DurableDirVolumeMountPoint": DurableDirVolumeMountPoint(uid, "vol"),
		"SystemInfoVolumeRootsDir":   SystemInfoVolumeRootsDir(uid),
		"SystemInfoVolumeRoot":       SystemInfoVolumeRoot(uid, "vol"),
		"RestoreStateDir":            RestoreStateDir(uid),
		"PIDFileDir":                 PIDFileDir(uid),
		"PIDFilePath":                PIDFilePath(uid, "main"),
		"VolumesDir":                 VolumesDir(uid),
		"VolumeHostPath":             VolumeHostPath(uid, "vol"),
	}
}

// TestActorScopedPathsStayUnderActorPath is what makes atelet's
// removeActorDirs safe: it reclaims an actor by deleting ActorPath(uid) alone,
// on the stated grounds that nothing else on the node holds that actor's
// state. A constructor that joined to BasePath instead would leak state past
// termination without any caller changing.
func TestActorScopedPathsStayUnderActorPath(t *testing.T) {
	root := ActorPath(testActorUID)
	for name, got := range actorScopedPaths(testActorUID) {
		if !isUnder(got, root) {
			t.Errorf("%s = %q, want a path under ActorPath = %q", name, got, root)
		}
	}
	if !isUnder(root, ActorsDir) {
		t.Errorf("ActorPath = %q, want a path under ActorsDir = %q", root, ActorsDir)
	}
}

// TestActorScopedPathsDoNotCollide checks that no two subsystems were handed
// the same directory. A collision is silent: both sides create it, both write
// into it, and the damage only shows up as one subsystem's files vanishing
// when the other resets its own directory.
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
		if isUnder(got, otherRoot) || got == otherRoot {
			t.Errorf("%s for actor %s = %q, which lies inside actor %s's tree %q", name, testActorUID, got, otherActorUID, otherRoot)
		}
	}
	if ActorNetNSName(testActorUID) == ActorNetNSName(otherActorUID) {
		t.Errorf("two actors share netns name %q", ActorNetNSName(testActorUID))
	}
}

// TestContainmentHoldsForEveryValidIdentifier runs the containment invariant
// over the identifier shapes callers are actually allowed to pass, rather than
// over one hand-picked UUID. Actor UIDs reach this package as DNS-1123 labels
// (resources.ValidateResourceName, applied to actor_uid at atelet's Terminate
// entry point) and container and volume names carry the same rule
// (validate.ShortName in the generated API validation), so a label that is
// legal there must not be able to leave the actor's tree.
func TestContainmentHoldsForEveryValidIdentifier(t *testing.T) {
	// All DNS-1123 labels: lower-case alphanumerics and dashes, starting and
	// ending alphanumeric. The awkward ones are the short and dash-heavy
	// spellings, not the UUID the rest of this file uses.
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
		if !isUnder(root, ActorsDir) {
			t.Errorf("ActorPath(%q) = %q escaped ActorsDir %q", uid, root, ActorsDir)
			continue
		}
		for name, got := range actorScopedPaths(uid) {
			if !isUnder(got, root) {
				t.Errorf("%s(%q) = %q, want a path under %q", name, uid, got, root)
			}
		}
	}
}

// TestUnvalidatedIdentifiersEscape records the precondition this package
// carries but does not enforce: it composes paths, it does not sanitise them,
// and filepath.Join cleans the result rather than rejecting it. Callers are
// what keep the invariant -- resources.ValidateResourceName on actor_uid,
// validate.ShortName on container and volume names, a server-minted UUID for
// snapshot names -- so a new call site that skips validation gets no help from
// here.
//
// The two shapes below are the ones with teeth, because atelet's
// removeActorDirs does os.RemoveAll(ActorPath(actorUID)):
//
//   - empty collapses ActorPath onto ActorsDir itself, turning "reclaim this
//     actor" into "delete every actor on the node";
//   - a traversal element leaves the tree entirely.
//
// If this test ever fails, the package has grown its own guard. That is an
// improvement: assert the new behaviour here and drop the warning from the
// package doc.
func TestUnvalidatedIdentifiersEscape(t *testing.T) {
	if got := ActorPath(""); got != ActorsDir {
		t.Errorf("ActorPath(%q) = %q, want %q -- an empty UID no longer collapses onto the actors root, so the caller-side non-empty check may be redundant now", "", got, ActorsDir)
	}
	if got := ActorPath("../../etc"); isUnder(got, ActorsDir) {
		t.Errorf("ActorPath(%q) = %q, unexpectedly contained in %q", "../../etc", got, ActorsDir)
	}
}

// TestSocketPathsFitTheUnixLimit covers the sockets the existing tests do not.
// A unix socket path over the limit fails at bind time, on the node, at
// runtime -- there is no earlier signal.
func TestSocketPathsFitTheUnixLimit(t *testing.T) {
	// sun_path is 108 bytes including the NUL terminator.
	const maxUnixSocketLen = 107
	for name, got := range map[string]string{
		"AteomSupportSocket":      AteomSupportSocket,
		"KubeletPluginSocketPath": KubeletPluginSocketPath("csi.substrate.dev"),
	} {
		if len(got) > maxUnixSocketLen {
			t.Errorf("%s = %q is %d bytes, over the %d-byte unix socket limit", name, got, len(got), maxUnixSocketLen)
		}
	}
}

// TestContentAddressedPathsSeparateTheirKinds checks that a runsc binary and a
// gVisor release directory sharing one sha256 do not land on the same path:
// both are content-addressed into StaticFilesDir, and the prefixes are the
// only thing keeping them apart.
func TestContentAddressedPathsSeparateTheirKinds(t *testing.T) {
	const sha = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	bin, release := RunSCBinaryPath(sha), GVisorReleaseDir(sha)
	if bin == release {
		t.Fatalf("RunSCBinaryPath and GVisorReleaseDir both resolve to %q for sha %s", bin, sha)
	}
	for name, got := range map[string]string{"RunSCBinaryPath": bin, "GVisorReleaseDir": release} {
		if !isUnder(got, StaticFilesDir) {
			t.Errorf("%s(%q) = %q, want a path under StaticFilesDir %q", name, sha, got, StaticFilesDir)
		}
	}
	if RunSCBinaryPath(sha) == RunSCBinaryPath(strings.Repeat("f", 64)) {
		t.Error("RunSCBinaryPath is not content-addressed: two shas share a path")
	}
}

// TestEveryActorScopedConstructorIsRegistered is what keeps the three
// invariants above from quietly narrowing to the set of functions that existed
// the day they were written. The invariants read from one hand-maintained map,
// so a constructor added later is covered by nothing until somebody remembers
// to list it -- and forgetting looks exactly like passing.
//
// This reads the package's own source and requires every exported function
// taking an actorUID to appear in that map. Adding one without registering it
// fails here, naming the function.
func TestEveryActorScopedConstructorIsRegistered(t *testing.T) {
	// Deliberately outside the actor's directory tree, so the containment
	// invariant does not apply to them.
	exempt := map[string]string{
		"ActorPath":      "the tree root itself, not a path within it",
		"ActorNetNSName": "a namespace name, not a filesystem path",
		"ActorNetNSPath": "lives under /run/netns, which the kernel owns",
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "ateompath.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing ateompath.go: %v", err)
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

// isUnder reports whether path lies strictly inside dir. It compares cleaned
// path elements rather than string prefixes, so a sibling directory whose name
// merely starts with dir's name is not mistaken for a child.
func isUnder(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
