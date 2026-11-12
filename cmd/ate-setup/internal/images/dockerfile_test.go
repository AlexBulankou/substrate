// Copyright 2026 The Agent Substrate Authors
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

package images

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDockerBuildArgs(t *testing.T) {
	got := dockerBuildArgs("linux/amd64", []string{"--cache-from", "type=gha"}, "repo/img:build-1", "meta.json", "ctx")
	want := []string{"buildx", "build", "--platform=linux/amd64", "--push", "--metadata-file", "meta.json", "--cache-from", "type=gha", "-t", "repo/img:build-1", "ctx"}
	if !slices.Equal(got, want) {
		t.Errorf("dockerBuildArgs() = %q, want %q", got, want)
	}
	got = dockerBuildArgs("linux/amd64", nil, "repo/img:build-1", "meta.json", "ctx")
	want = []string{"buildx", "build", "--platform=linux/amd64", "--push", "--metadata-file", "meta.json", "-t", "repo/img:build-1", "ctx"}
	if !slices.Equal(got, want) {
		t.Errorf("dockerBuildArgs() without flags = %q, want %q", got, want)
	}
}

// The digest comes from what buildx pushed, so a tag that names another push
// cannot stand in for it.
func TestPushedDigest(t *testing.T) {
	const digest = "sha256:bab239626dc054856e882a2ef022dfa845834113d213697e1dccd27dfbfac1a5"
	for _, tc := range []struct {
		name     string
		metadata string
		want     string
		wantErr  bool
	}{
		{
			name:     "multi-platform push",
			metadata: `{"buildx.build.ref":"ate-release/ate-release0/x","containerimage.digest":"` + digest + `","image.name":"localhost:5000/substrate/envoy-dataplane:v1"}`,
			want:     digest,
		},
		{name: "no digest", metadata: `{"buildx.build.ref":"ate-release/ate-release0/x"}`, wantErr: true},
		{name: "not JSON", metadata: ``, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pushedDigest([]byte(tc.metadata))
			if (err != nil) != tc.wantErr {
				t.Fatalf("pushedDigest() error = %v, want error %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("pushedDigest() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ko builds for .ko.yaml's defaultPlatforms unless KO_DEFAULTPLATFORMS says
// otherwise, and a Dockerfile image installed beside the ko images has to
// cover the same platforms or it cannot run on some of their nodes.
func TestDockerfilePlatforms(t *testing.T) {
	const twoPlatforms = "defaultPlatforms:\n  - linux/amd64\n  - linux/arm64\n"
	for _, tc := range []struct {
		name         string
		koYAML       string // empty: no ko config
		koYAMLFile   string // where it is written, relative to the root; default .ko.yaml
		koConfigPath string
		koPlatforms  string
		want         string
	}{
		{name: "explicit platforms win", koYAML: twoPlatforms, koPlatforms: "linux/s390x", want: "linux/s390x"},
		{name: "ko config", koYAML: twoPlatforms, want: "linux/amd64,linux/arm64"},
		{name: "ko config without platforms", koYAML: "defaultBaseImage: example.com/base\n", want: "linux/amd64"},
		{name: "no ko config", want: "linux/amd64"},
		{name: "KO_CONFIG_PATH file", koYAML: twoPlatforms, koYAMLFile: "conf/ko.yaml", koConfigPath: "conf/ko.yaml", want: "linux/amd64,linux/arm64"},
		{name: "KO_CONFIG_PATH directory", koYAML: twoPlatforms, koYAMLFile: "conf/.ko.yaml", koConfigPath: "conf", want: "linux/amd64,linux/arm64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("KO_CONFIG_PATH", tc.koConfigPath)
			if tc.koYAML != "" {
				file := filepath.Join(root, cmp.Or(tc.koYAMLFile, ".ko.yaml"))
				if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(tc.koYAML), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := dockerfilePlatforms(root, tc.koPlatforms)
			if err != nil {
				t.Fatalf("dockerfilePlatforms() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("dockerfilePlatforms() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The hint exists to tell a user who HAS buildx why --push still failed, so it
// must fire only for the one driver that refuses --push by default. Firing on
// a docker-container builder would send a working setup chasing a non-problem.
func TestPushDriverHint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inspect string
		want    bool
	}{
		{name: "default docker driver", inspect: "Name:   default\nDriver: docker\n", want: true},
		{name: "indented and lowercased", inspect: "  driver:  docker  \n", want: true},
		{name: "docker-container can push", inspect: "Name:   mybuilder\nDriver: docker-container\n", want: false},
		{name: "remote driver can push", inspect: "Driver: remote\n", want: false},
		{name: "no inspect output at all", inspect: "", want: false},
		{name: "no driver line", inspect: "Name: default\nStatus: running\n", want: false},
		// "Driver" must be matched as a field name, not as a substring: a
		// builder whose NAME contains the word would otherwise decide this.
		{name: "name mentioning a driver is not the driver", inspect: "Name: docker-driver-test\nDriver: docker-container\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pushDriverHint(tc.inspect) != ""
			if got != tc.want {
				t.Errorf("pushDriverHint(%q) fired = %v, want %v", tc.inspect, got, tc.want)
			}
		})
	}
}

// A missing plugin must be named. The whole point of the precondition is that
// docker's exit status 125 and its top-level usage text name neither buildx
// nor the step that needed it.
func TestErrNoBuildxNamesTheFix(t *testing.T) {
	for _, want := range []string{"buildx", "docker-buildx-plugin", "docker buildx version"} {
		if !strings.Contains(errNoBuildx.Error(), want) {
			t.Errorf("errNoBuildx does not mention %q: %v", want, errNoBuildx)
		}
	}
}
