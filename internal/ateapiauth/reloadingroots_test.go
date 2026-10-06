//  Copyright 2026 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package ateapiauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
)

// The end-to-end reload is covered by TestDialOptionsReloadsCAFile. These
// cover the credentials.TransportCredentials surface around it, which that
// test never exercises.
func TestReloadingRoots(t *testing.T) {
	loader := func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }

	t.Run("a RootCAs already on the template is dropped", func(t *testing.T) {
		// Otherwise a caller who set it would keep dialling against the pool
		// they froze at construction, which is the bug this type exists for.
		pinned := x509.NewCertPool()
		c := newReloadingRootCredentials(&tls.Config{RootCAs: pinned}, loader).(*reloadingRoots)
		if c.template.RootCAs != nil {
			t.Fatal("template kept a RootCAs; the per-handshake pool would never be the one used")
		}
	})

	t.Run("the template is copied, not aliased", func(t *testing.T) {
		tmpl := &tls.Config{ServerName: "a"}
		c := newReloadingRootCredentials(tmpl, loader)
		if err := c.OverrideServerName("b"); err != nil {
			t.Fatalf("OverrideServerName() error = %v", err)
		}
		if tmpl.ServerName != "a" {
			t.Fatalf("caller's config mutated: ServerName = %q, want %q", tmpl.ServerName, "a")
		}
	})

	t.Run("OverrideServerName reaches Info, which grpc-go reads for the authority", func(t *testing.T) {
		c := newReloadingRootCredentials(&tls.Config{ServerName: "a"}, loader)
		if err := c.OverrideServerName("b"); err != nil {
			t.Fatalf("OverrideServerName() error = %v", err)
		}
		if got := c.Info().ServerName; got != "b" {
			t.Fatalf("Info().ServerName = %q, want %q", got, "b")
		}
	})

	t.Run("a clone is independent of its source", func(t *testing.T) {
		c := newReloadingRootCredentials(&tls.Config{ServerName: "a"}, loader)
		clone := c.Clone()
		if err := clone.OverrideServerName("b"); err != nil {
			t.Fatalf("OverrideServerName() error = %v", err)
		}
		if got := c.Info().ServerName; got != "a" {
			t.Fatalf("source ServerName = %q after cloning and overriding the clone, want %q", got, "a")
		}
	})

	t.Run("serving is refused", func(t *testing.T) {
		c := newReloadingRootCredentials(&tls.Config{}, loader)
		if _, _, err := c.ServerHandshake(nil); err == nil {
			t.Fatal("ServerHandshake() succeeded; dial-only credentials must not serve")
		}
	})

	t.Run("a loader error fails the handshake rather than dialling unverified", func(t *testing.T) {
		boom := errors.New("trust bundle unreadable")
		c := newReloadingRootCredentials(&tls.Config{}, func() (*x509.CertPool, error) { return nil, boom })
		_, _, err := c.ClientHandshake(t.Context(), "example.invalid:443", nil)
		if !errors.Is(err, boom) {
			t.Fatalf("ClientHandshake() error = %v, want it to wrap %v", err, boom)
		}
	})
}
