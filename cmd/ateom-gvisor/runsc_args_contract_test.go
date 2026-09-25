//go:build linux

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

package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

const (
	testUID       = "actor-aaa"
	otherUID      = "actor-bbb"
	testContainer = "workload"
)

func testRunsc(uid string) *runsc {
	return &runsc{path: "/usr/bin/runsc", actorUID: uid}
}

// command describes one runsc invocation this package builds. Every argv
// builder belongs here: the invariant tests below iterate this table, so a
// builder that is not listed is covered by none of them.
type command struct {
	name string
	argv []string
	// sub is the runsc subcommand token. Everything before it is a global
	// flag, everything after it a subcommand flag or operand -- runsc rejects
	// a global flag placed after the subcommand.
	sub string
	// tail is the trailing operand(s), in order. runsc takes the container
	// name last on every subcommand that names one; `kill` appends the signal
	// after it, and `list` names no container at all.
	tail []string
}

func allCommands(r *runsc) []command {
	return []command{
		{"createArgs", r.createArgs(testContainer, nil), "create", []string{testContainer}},
		{"startArgs", r.startArgs(testContainer), "start", []string{testContainer}},
		{"checkpointArgs", r.checkpointArgs(testContainer, "/snap"), "checkpoint", []string{testContainer}},
		{"fsCheckpointArgs", r.fsCheckpointArgs(testContainer, "/snap", nil), "fscheckpoint", []string{testContainer}},
		{"restoreArgs", r.restoreArgs(testContainer, "/snap"), "restore", []string{testContainer}},
		{"pauseArgs", r.pauseArgs(testContainer), "pause", []string{testContainer}},
		{"resumeArgs", r.resumeArgs(testContainer), "resume", []string{testContainer}},
		{"deleteArgs", r.deleteArgs(testContainer), "delete", []string{testContainer}},
		{"stateArgs", r.stateArgs(testContainer), "state", []string{testContainer}},
		{"killArgs", r.killArgs(testContainer, "SIGTERM"), "kill", []string{testContainer, "SIGTERM"}},
		{"waitArgs", r.waitArgs(testContainer), "wait", []string{testContainer}},
		{"listArgs", r.listArgs(), "list", nil},
	}
}

// TestEveryCommandIsRootedAtTheActorsStateDir is the isolation invariant.
//
// `-root` is what confines a runsc invocation to one actor's state directory.
// Drop it from any single subcommand and runsc silently falls back to its own
// default root, which is shared: that invocation would then read and write
// container state belonging to every actor on the node. It is a global flag,
// so it also has to precede the subcommand -- runsc rejects it afterwards, and
// the failure would be at sandbox-management time on a node, not at build
// time.
func TestEveryCommandIsRootedAtTheActorsStateDir(t *testing.T) {
	r := testRunsc(testUID)
	wantRoot := ateompath.RunSCStateDir(testUID)

	for _, c := range allCommands(r) {
		i := slices.Index(c.argv, "-root")
		if i < 0 {
			t.Errorf("%s: no -root flag; runsc would fall back to its shared default root and touch other actors' state: %v", c.name, c.argv)
			continue
		}
		if i+1 >= len(c.argv) || c.argv[i+1] != wantRoot {
			t.Errorf("%s: -root is not the actor's state dir, want %q: %v", c.name, wantRoot, c.argv)
			continue
		}
		subIdx := slices.Index(c.argv, c.sub)
		if subIdx < 0 {
			t.Errorf("%s: subcommand %q missing from %v", c.name, c.sub, c.argv)
			continue
		}
		if i > subIdx {
			t.Errorf("%s: -root appears after the %q subcommand, where runsc will not accept it: %v", c.name, c.sub, c.argv)
		}
	}
}

// TestNoCommandLeaksAnotherActorsPaths checks the same confinement from the
// other side: nothing in an actor's argv may name a path belonging to a
// different actor.
func TestNoCommandLeaksAnotherActorsPaths(t *testing.T) {
	other := ateompath.ActorPath(otherUID)
	for _, c := range allCommands(testRunsc(testUID)) {
		for _, arg := range c.argv {
			if arg == other || (len(arg) > len(other) && arg[:len(other)+1] == other+"/") {
				t.Errorf("%s: argv names actor %s's tree (%q): %v", c.name, otherUID, arg, c.argv)
			}
		}
	}
}

// TestContainerNameIsLast pins the ordering runsc requires and that
// cmdFsCheckpoint's comment calls out explicitly ("name of the container must
// be the last parameter"). Get it wrong and runsc parses the container name as
// a flag value, or the flag value as the container name -- both of which act
// on the wrong container rather than failing.
func TestContainerNameIsLast(t *testing.T) {
	for _, c := range allCommands(testRunsc(testUID)) {
		if len(c.tail) == 0 {
			continue
		}
		if len(c.argv) < len(c.tail) {
			t.Errorf("%s: argv shorter than its expected operands: %v", c.name, c.argv)
			continue
		}
		if got := c.argv[len(c.argv)-len(c.tail):]; !reflect.DeepEqual(got, c.tail) {
			t.Errorf("%s: trailing operands = %v, want %v (full argv: %v)", c.name, got, c.tail, c.argv)
		}
	}
}

// TestCPUQuotaFlagPairsCreateWithRestore guards the pairing restoreArgs'
// comment states ("Match cmdCreate"). --cpu-num-from-quota sizes the sentry's
// vCPU count from the cgroup quota; without it runsc sizes to every host CPU.
// A restore that lost the flag would bring an actor back with a silently
// different CPU shape than it was created with -- no error, just a sandbox
// that no longer matches its pod limit.
func TestCPUQuotaFlagPairsCreateWithRestore(t *testing.T) {
	const flag = "--cpu-num-from-quota"
	want := map[string]bool{"createArgs": true, "restoreArgs": true}

	for _, c := range allCommands(testRunsc(testUID)) {
		got := slices.Contains(c.argv, flag)
		if got != want[c.name] {
			if want[c.name] {
				t.Errorf("%s: missing %s, so the sentry would size to all host CPUs instead of the pod's quota", c.name, flag)
			} else {
				t.Errorf("%s: unexpected %s; only create and restore size the sentry", c.name, flag)
			}
		}
		// It is a global flag, so it must precede the subcommand.
		if got {
			if slices.Index(c.argv, flag) > slices.Index(c.argv, c.sub) {
				t.Errorf("%s: %s appears after the %q subcommand, where runsc will not accept it", c.name, flag, c.sub)
			}
		}
	}
}

// TestAllowConnectedOnSaveIsStartOnly records that the flag permitting a save
// with live connections is scoped to `start` alone. It is listed here so
// spreading it to another subcommand is a deliberate edit rather than a copied
// argv block.
func TestAllowConnectedOnSaveIsStartOnly(t *testing.T) {
	for _, c := range allCommands(testRunsc(testUID)) {
		if got := slices.Contains(c.argv, "-allow-connected-on-save"); got != (c.name == "startArgs") {
			t.Errorf("%s: -allow-connected-on-save present = %v, want %v", c.name, got, c.name == "startArgs")
		}
	}
}

// TestEveryCommandLogsAsJSON checks the log-format contract the node's log
// pipeline parses. A subcommand emitting runsc's default text format is not an
// error anywhere -- its output simply stops being ingestible.
func TestEveryCommandLogsAsJSON(t *testing.T) {
	for _, c := range allCommands(testRunsc(testUID)) {
		if len(c.argv) < 3 || c.argv[0] != "-log-format" || c.argv[1] != "json" || c.argv[2] != "--alsologtostderr" {
			t.Errorf("%s: argv does not open with -log-format json --alsologtostderr: %v", c.name, c.argv)
		}
	}
}

// TestArgvIsExact pins each builder's full argv. The invariants above say the
// shape is right; this says the flags are the ones we meant, which is the half
// that catches a silently dropped or renamed runsc flag.
func TestArgvIsExact(t *testing.T) {
	r := testRunsc(testUID)
	root := ateompath.RunSCStateDir(testUID)
	bundle := ateompath.OCIBundlePath(testUID, testContainer)
	pidFile := ateompath.PIDFilePath(testUID, testContainer)
	head := []string{"-log-format", "json", "--alsologtostderr"}

	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{
			"createArgs",
			r.createArgs(testContainer, nil),
			append(slices.Clone(head), "-root", root, "--cpu-num-from-quota",
				"create", "-bundle", bundle, "-pid-file", pidFile, testContainer),
		},
		{
			"createArgs with additional args",
			r.createArgs(testContainer, []string{"-console-socket", "/sock"}),
			append(slices.Clone(head), "-root", root, "--cpu-num-from-quota",
				"create", "-bundle", bundle, "-pid-file", pidFile,
				"-console-socket", "/sock", testContainer),
		},
		{
			"startArgs",
			r.startArgs(testContainer),
			append(slices.Clone(head), "-allow-connected-on-save", "-root", root, "start", testContainer),
		},
		{
			"checkpointArgs",
			r.checkpointArgs(testContainer, "/snap"),
			append(slices.Clone(head), "-root", root, "checkpoint", "-image-path", "/snap", testContainer),
		},
		{
			"fsCheckpointArgs without durable volumes",
			r.fsCheckpointArgs(testContainer, "/snap", nil),
			append(slices.Clone(head), "-root", root, "fscheckpoint", "-image-path", "/snap", testContainer),
		},
		{
			"fsCheckpointArgs repeats -path per durable volume",
			r.fsCheckpointArgs(testContainer, "/snap", []string{"/d/one", "/d/two"}),
			append(slices.Clone(head), "-root", root, "fscheckpoint", "-image-path", "/snap",
				"-path", "/d/one", "-path", "/d/two", testContainer),
		},
		{
			"restoreArgs",
			r.restoreArgs(testContainer, "/snap"),
			append(slices.Clone(head), "-root", root, "--cpu-num-from-quota",
				"restore", "-bundle", bundle, "-image-path", "/snap",
				"-pid-file", pidFile, "-background", "-detach", testContainer),
		},
		{
			"deleteArgs",
			r.deleteArgs(testContainer),
			append(slices.Clone(head), "-root", root, "delete", "-force", testContainer),
		},
		{
			"stateArgs",
			r.stateArgs(testContainer),
			append(slices.Clone(head), "-root", root, "state", testContainer),
		},
		{
			"listArgs",
			r.listArgs(),
			append(slices.Clone(head), "-root", root, "list", "-quiet"),
		},
	}
	for _, tt := range tests {
		if !reflect.DeepEqual(tt.got, tt.want) {
			t.Errorf("%s =\n  %v\nwant\n  %v", tt.name, tt.got, tt.want)
		}
	}
}

// TestDeleteIsForced records that container deletion passes -force. Without
// it runsc refuses to delete a container that is still running, which would
// leave the actor's sandbox behind on a teardown path that reports success.
func TestDeleteIsForced(t *testing.T) {
	if !slices.Contains(testRunsc(testUID).deleteArgs(testContainer), "-force") {
		t.Error("deleteArgs dropped -force; a still-running container would survive teardown")
	}
}

// TestListIsQuiet records that `runsc list` asks for the bare-ID form. cmdList
// parses the output with strings.Fields, so the default table -- header row
// and all -- would be read back as container IDs.
func TestListIsQuiet(t *testing.T) {
	if !slices.Contains(testRunsc(testUID).listArgs(), "-quiet") {
		t.Error("listArgs dropped -quiet; cmdList's strings.Fields parse would read the table header as container IDs")
	}
}

func TestDurableVolumeNames(t *testing.T) {
	mount := func(name string) *ateompb.DurableDirVolumeMount {
		return &ateompb.DurableDirVolumeMount{VolumeName: name}
	}
	container := func(names ...string) *ateompb.Container {
		c := &ateompb.Container{}
		for _, n := range names {
			c.DurableDirVolumeMounts = append(c.DurableDirVolumeMounts, mount(n))
		}
		return c
	}

	tests := []struct {
		name string
		spec *ateompb.WorkloadSpec
		want []string
	}{
		{"nil spec", nil, nil},
		{"no containers", &ateompb.WorkloadSpec{}, nil},
		{"container with no durable mounts", &ateompb.WorkloadSpec{
			Containers: []*ateompb.Container{container()},
		}, nil},
		{"single mount", &ateompb.WorkloadSpec{
			Containers: []*ateompb.Container{container("data")},
		}, []string{"data"}},
		{"sorted", &ateompb.WorkloadSpec{
			Containers: []*ateompb.Container{container("zeta", "alpha", "mid")},
		}, []string{"alpha", "mid", "zeta"}},
		{
			// The deduplication is the load-bearing part: two containers of one
			// actor may mount the same durable volume, and the result is
			// declared to the sandbox as the set of durable mounts. A repeat
			// would declare the same mount twice.
			"deduplicated across containers",
			&ateompb.WorkloadSpec{
				Containers: []*ateompb.Container{container("data", "logs"), container("data")},
			},
			[]string{"data", "logs"},
		},
		{"deduplicated within one container", &ateompb.WorkloadSpec{
			Containers: []*ateompb.Container{container("data", "data")},
		}, []string{"data"}},
	}
	for _, tt := range tests {
		if got := durableVolumeNames(tt.spec); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("durableVolumeNames(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
