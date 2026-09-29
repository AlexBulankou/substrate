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

package netns

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// Only EROFS takes the remount path: any other error is reported as it is,
// and /proc/sys is left as it was found. Remounting it read-only on the way
// out would break every later write.
func TestSetSysctlReportsAnUnrelatedError(t *testing.T) {
	// Sampled before the call, because the invariant is that setSysctl leaves
	// the mount as it found it -- not that it finds it writable. Plenty of
	// containers mount /proc/sys read-only to begin with, and asserting the
	// absolute state fails those for behaving correctly.
	before := procSysReadOnly(t)

	err := setSysctl("net/ipv4/ateomnet_no_such_sysctl", "0")
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("setSysctl() on a missing key: got %v, want ENOENT", err)
	}
	if after := procSysReadOnly(t); after != before {
		t.Errorf("setSysctl() left /proc/sys read-only = %v, want it as found (%v)", after, before)
	}
}

func procSysReadOnly(t *testing.T) bool {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs("/proc/sys", &st); err != nil {
		t.Fatalf("statfs /proc/sys: %v", err)
	}
	return st.Flags&unix.ST_RDONLY != 0
}
