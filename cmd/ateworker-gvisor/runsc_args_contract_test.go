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
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.ate.dev/substrate/internal/proto/ateworkerpb"
)

// The tests in runsc_test.go pin one example argv per builder. These pin the
// properties that have to hold across *every* command, which an example set
// cannot: a per-command example only fails when someone edits that command,
// and the failures these guard against come from editing a different one --
// or, since the flags config moved out of the binary, from editing no code
// at all.

// contractActorDirs is the directory set atelet sends for an actor.
// ateworker takes these from the request rather than deriving them from the
// actor UID, so the confinement asserted below is a property of what the
// request carries: one actor's argv may never name a path under another's
// RootDir. Per-UID rather than reusing runsc_test.go's single-actor
// testActorDirs, because the cross-actor test needs two disjoint trees.
func contractActorDirs(uid string) *ateworkerpb.ActorDirs {
	root := filepath.Join("/node/actors", uid)
	return &ateworkerpb.ActorDirs{
		RootDir:      root,
		OciBundleDir: filepath.Join(root, "bundle"),
	}
}

func contractRunsc(t *testing.T, uid string, flagsJSON string) *runsc {
	t.Helper()
	store := &flagStore{cfg: &flagConfig{}}
	if flagsJSON != "" {
		path := filepath.Join(t.TempDir(), "flags.json")
		if err := os.WriteFile(path, []byte(flagsJSON), 0o600); err != nil {
			t.Fatalf("write flags config: %v", err)
		}
		var err error
		if store, err = newFlagStore(context.Background(), path); err != nil {
			t.Fatalf("newFlagStore: %v", err)
		}
	}
	return &runsc{
		path:      "/usr/bin/runsc",
		actorUID:  uid,
		actorDirs: contractActorDirs(uid),
		flags:     store,
	}
}

const contractContainer = "my-container"

// invocation is one runsc command this binary issues.
type invocation struct {
	// command is the runsc subcommand token. Everything before it is a global
	// flag, everything after it a subcommand flag or an operand -- runsc
	// rejects a global flag placed after the subcommand.
	command string
	// argv is what the binary would execute, built the way the cmd* method
	// that issues this command builds it.
	argv []string
	// tail is the trailing operand(s), in order. runsc takes the container
	// name last on every subcommand that names one; kill appends the signal
	// after it, and list names no container at all.
	tail []string
}

// allInvocations mirrors every buildArgs call site in runsc.go. The invariant
// tests below iterate it, so a command missing from it is covered by none of
// them -- which is what TestEveryCommandTheBinaryIssuesIsUnderContract exists
// to catch.
func allInvocations(r *runsc) []invocation {
	return []invocation{
		{"create", r.createArgs(contractContainer, nil), []string{contractContainer}},
		{"start", r.buildArgs("start", contractContainer), []string{contractContainer}},
		{"checkpoint", r.checkpointArgs(contractContainer, "/snap", nil), []string{contractContainer}},
		{"fscheckpoint", r.fsCheckpointArgs(contractContainer, "/snap", []string{"/vol"}), []string{contractContainer}},
		{"restore", r.restoreArgs(contractContainer, "/snap"), []string{contractContainer}},
		{"delete", r.buildArgs("delete", contractContainer), []string{contractContainer}},
		{"state", r.buildArgs("state", contractContainer), []string{contractContainer}},
		{"list", r.buildArgs("list", ""), nil},
		{"kill", r.buildArgs("kill", "", contractContainer, "SIGTERM"), []string{contractContainer, "SIGTERM"}},
		{"wait", r.buildArgs("wait", contractContainer), []string{contractContainer}},
		{"wait -restore", r.buildArgs("wait", contractContainer, "-restore"), []string{contractContainer}},
		{"wait -fsrestore", r.buildArgs("wait", contractContainer, "-fsrestore"), []string{contractContainer}},
	}
}

// subcommandIndex returns the position of the subcommand token, which
// buildArgs always places directly after the -root value it appends itself.
// Reported rather than searched for, because a flags config may legitimately
// contain a token equal to the command name.
func subcommandIndex(t *testing.T, argv []string) int {
	t.Helper()
	i := slices.Index(argv, "-root")
	// The effective -root is the last one: runsc parses with Go's flag
	// package, where a repeated flag takes its final value.
	for j := i + 1; j < len(argv); j++ {
		if argv[j] == "-root" {
			i = j
		}
	}
	if i < 0 || i+2 >= len(argv) {
		t.Fatalf("argv has no -root followed by a subcommand: %v", argv)
	}
	return i + 2
}

// TestEveryCommandIsRootedAtTheActorsStateDir is the isolation invariant.
//
// -root is what confines a runsc invocation to one actor's state directory.
// Drop it from any single subcommand and runsc falls back to its own default
// root, which is shared: that invocation would then read and write container
// state belonging to every actor on the node. It is a global flag, so it also
// has to precede the subcommand -- runsc rejects it afterwards, and that
// failure surfaces at sandbox-management time on a node, not at build time.
func TestEveryCommandIsRootedAtTheActorsStateDir(t *testing.T) {
	r := contractRunsc(t, "actor-a", "")
	wantDir := runscStateDir(r.actorDirs)

	for _, inv := range allInvocations(r) {
		t.Run(inv.command, func(t *testing.T) {
			sub := subcommandIndex(t, inv.argv)
			if got := inv.argv[sub-2]; got != "-root" {
				t.Fatalf("argv = %v, want -root before the subcommand", inv.argv)
			}
			if got := inv.argv[sub-1]; got != wantDir {
				t.Errorf("-root = %q, want %q", got, wantDir)
			}
			if got := inv.argv[sub]; got != strings.Fields(inv.command)[0] {
				t.Errorf("subcommand = %q, want %q", got, inv.command)
			}
		})
	}
}

// TestNoCommandNamesAnotherActorsPaths checks the same confinement from the
// other side: nothing in an actor's argv may name a path belonging to a
// different actor. A builder that derived a path from a package-level value
// instead of r.actorDirs would pass every single-actor example test and fail
// only here.
func TestNoCommandNamesAnotherActorsPaths(t *testing.T) {
	a := contractRunsc(t, "actor-a", "")
	foreign := contractActorDirs("actor-b").GetRootDir()

	for _, inv := range allInvocations(a) {
		t.Run(inv.command, func(t *testing.T) {
			for _, arg := range inv.argv {
				if strings.Contains(arg, foreign) {
					t.Errorf("argv names another actor's tree: %q in %v", arg, inv.argv)
				}
			}
		})
	}
}

// TestTheContainerNameIsTheLastOperand pins the ordering runsc requires and
// that cmdFsCheckpoint's own comment calls out ("name of the container must
// be the last parameter"). Get it wrong and runsc parses the container name
// as a flag value, or a flag value as the container name -- both of which act
// on the wrong container rather than failing.
func TestTheContainerNameIsTheLastOperand(t *testing.T) {
	r := contractRunsc(t, "actor-a", "")

	for _, inv := range allInvocations(r) {
		if inv.tail == nil {
			continue
		}
		t.Run(inv.command, func(t *testing.T) {
			got := inv.argv[len(inv.argv)-len(inv.tail):]
			if !slices.Equal(got, inv.tail) {
				t.Errorf("argv tail = %v, want %v (full: %v)", got, inv.tail, inv.argv)
			}
		})
	}
}

// contractFlagsJSON exercises every splice point the config has: flags global
// to all commands, flags global to one, and subcommand flags.
const contractFlagsJSON = `{
  "globalFlags": ["-every-command"],
  "commands": {
    "delete": {"globalFlags": ["-delete-global"], "subcommandFlags": ["-force"]},
    "list": {"subcommandFlags": ["-quiet"]}
  }
}`

// TestConfiguredFlagsLandOnTheirSideOfTheSubcommand covers the surface that
// did not exist when these commands were argv literals: the flags config is a
// file ateworker reloads at runtime, so its contents reach runsc's command
// line without a build. A global flag spliced in after the subcommand, or a
// subcommand flag spliced in before it, is rejected by runsc at the moment an
// actor is being managed.
func TestConfiguredFlagsLandOnTheirSideOfTheSubcommand(t *testing.T) {
	r := contractRunsc(t, "actor-a", contractFlagsJSON)

	for _, inv := range allInvocations(r) {
		t.Run(inv.command, func(t *testing.T) {
			sub := subcommandIndex(t, inv.argv)
			cmd := strings.Fields(inv.command)[0]
			cfg := r.flags.get()
			for _, f := range cfg.globalFlags(cmd) {
				if i := slices.Index(inv.argv, f); i < 0 || i > sub {
					t.Errorf("global flag %q at index %d, want before the subcommand at %d (%v)", f, i, sub, inv.argv)
				}
			}
			for _, f := range cfg.subcommandFlags(cmd) {
				if i := slices.Index(inv.argv, f); i < sub {
					t.Errorf("subcommand flag %q at index %d, want after the subcommand at %d (%v)", f, i, sub, inv.argv)
				}
			}
		})
	}
}

// TestAConfiguredRootCannotMoveTheActorsStateDir is the config-era form of
// the isolation invariant. Nothing validates the contents of the flags file:
// an operator (or anything that can write that path) may put "-root" in
// globalFlags. buildArgs appends the configured globals before the -root it
// adds itself, so the actor's own state dir is the last value and wins under
// Go's flag parsing -- but that is a consequence of append order, not a
// stated rule, and reordering those two appends would silently hand one
// actor's runsc the shared state of every other.
func TestAConfiguredRootCannotMoveTheActorsStateDir(t *testing.T) {
	const hostile = `{"globalFlags": ["-root", "/node/actors/actor-b/runsc-state"], "commands": {}}`
	r := contractRunsc(t, "actor-a", hostile)
	wantDir := runscStateDir(r.actorDirs)

	for _, inv := range allInvocations(r) {
		t.Run(inv.command, func(t *testing.T) {
			sub := subcommandIndex(t, inv.argv)
			if got := inv.argv[sub-1]; got != wantDir {
				t.Errorf("effective -root = %q, want the actor's own %q (%v)", got, wantDir, inv.argv)
			}
		})
	}
}

// TestEveryCommandTheBinaryIssuesIsUnderContract keeps allInvocations honest.
// The invariants above are only as broad as that table, and a new cmd* method
// added to runsc.go would be covered by none of them while every existing
// test stayed green -- the exact silence this file exists to remove.
func TestEveryCommandTheBinaryIssuesIsUnderContract(t *testing.T) {
	src, err := os.ReadFile("runsc.go")
	if err != nil {
		t.Fatalf("read runsc.go: %v", err)
	}
	// buildArgs is the single chokepoint: every command reaches runsc through
	// it, either directly or via a *Args builder.
	re := regexp.MustCompile(`buildArgs\("([a-z]+)"`)
	var issued []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		if !slices.Contains(issued, m[1]) {
			issued = append(issued, m[1])
		}
	}
	if len(issued) == 0 {
		t.Fatal("found no buildArgs call sites in runsc.go; the pattern needs updating, not the table")
	}

	var covered []string
	for _, inv := range allInvocations(contractRunsc(t, "actor-a", "")) {
		covered = append(covered, strings.Fields(inv.command)[0])
	}
	for _, cmd := range issued {
		if !slices.Contains(covered, cmd) {
			t.Errorf("runsc.go issues %q but allInvocations does not list it, so no invariant covers it", cmd)
		}
	}
	for _, cmd := range covered {
		if !slices.Contains(issued, cmd) {
			t.Errorf("allInvocations lists %q but runsc.go no longer issues it", cmd)
		}
	}
}
