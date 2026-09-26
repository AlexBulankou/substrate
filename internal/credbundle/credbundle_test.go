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

package credbundle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestParsePKCS8PrivateKeyBlock(t *testing.T) {
	key := generateRSAKey(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	certDER := generateCertificate(t, 1)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)

	bundlePath := writeBundle(t, bundle)
	cert, err := Parse(bundlePath)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("Parse() certificate chain length = %d, want 1", len(cert.Certificate))
	}
	if cert.PrivateKey == nil {
		t.Fatalf("Parse() private key is nil")
	}
	if cert.Leaf == nil {
		t.Fatalf("Parse() leaf certificate is nil")
	}
}

func TestParseRejectsNonPKCS8PrivateKeyBlock(t *testing.T) {
	certDER := generateCertificate(t, 1)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(generateRSAKey(t))})...)

	bundlePath := writeBundle(t, bundle)
	if _, err := Parse(bundlePath); err == nil {
		t.Fatalf("Parse() error = nil, want unsupported private key block error")
	}
}

func TestLoaderServesCachedParseWhileFileUnchanged(t *testing.T) {
	path := writeBundle(t, makeBundle(t, 7))
	getCert := Loader(path)

	first, err := getCert(nil)
	if err != nil {
		t.Fatalf("Loader() first call error = %v", err)
	}
	second, err := getCert(nil)
	if err != nil {
		t.Fatalf("Loader() second call error = %v", err)
	}

	// Pointer identity, not serial equality: a re-parse of the same file
	// produces an equal certificate but a different object, so this is what
	// actually distinguishes a cache hit from a silent re-parse. Asserting on
	// the value would pass either way.
	if first != second {
		t.Fatalf("Loader() re-parsed an unchanged file, want the cached parse")
	}
}

// The invalidation must be on the bundle contents, not on the stat triple
// (os.SameFile + mtime + size), because all three survive a real rotation: an
// in-place rewrite keeps the inode, two credentials from the same template
// encode to the same length, and mtime resolution is a filesystem timestamp
// tick, so a rewrite in the same tick keeps the mtime as well. Restoring the
// mtime here makes that collision deterministic instead of leaving it to the
// scheduler. A stat-triple cache serves serial 1 forever.
func TestLoaderPicksUpRotationWithAnIdenticalStatTriple(t *testing.T) {
	before := makeBundle(t, 1)
	path := writeBundle(t, before)
	getCert := Loader(path)

	if _, err := getCert(nil); err != nil {
		t.Fatalf("Loader() first call error = %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}

	after := makeBundle(t, 2)
	if len(after) != len(before) {
		t.Fatalf("test setup: rotated bundle is %d bytes, want the same %d as the original", len(after), len(before))
	}
	if err := os.WriteFile(path, after, 0o600); err != nil {
		t.Fatalf("rotate bundle in place: %v", err)
	}
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatalf("restore mtime: %v", err)
	}
	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("re-stat bundle: %v", err)
	}
	if !os.SameFile(fi, fi2) || !fi2.ModTime().Equal(fi.ModTime()) || fi2.Size() != fi.Size() {
		t.Fatalf("test setup: stat triple changed across the rotation, so this would pass without the fix")
	}

	cert, err := getCert(nil)
	if err != nil {
		t.Fatalf("Loader() after rotation error = %v", err)
	}
	if got := leafSerial(t, cert); got != 2 {
		t.Fatalf("Loader() leaf serial = %d, want the rotated-in 2 -- a rotated-out credential is still being presented", got)
	}
}

func TestLoaderPicksUpProjectedVolumeRotation(t *testing.T) {
	path := writeProjectedBundle(t, makeBundle(t, 1))
	getCert := Loader(path)

	cert, err := getCert(nil)
	if err != nil {
		t.Fatalf("Loader() first call error = %v", err)
	}
	if got := leafSerial(t, cert); got != 1 {
		t.Fatalf("Loader() leaf serial = %d, want 1", got)
	}

	if err := rotateProjectedBundle(path, makeBundle(t, 2)); err != nil {
		t.Fatalf("rotate bundle: %v", err)
	}

	cert, err = getCert(nil)
	if err != nil {
		t.Fatalf("Loader() after rotation error = %v", err)
	}
	if got := leafSerial(t, cert); got != 2 {
		t.Fatalf("Loader() leaf serial after rotation = %d, want 2", got)
	}
}

func TestLoaderPicksUpInPlaceRewrite(t *testing.T) {
	path := writeBundle(t, makeBundle(t, 1))
	getCert := Loader(path)

	if _, err := getCert(nil); err != nil {
		t.Fatalf("Loader() first call error = %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	// Rewrite the file in place (same inode) and push the mtime forward so
	// the change is visible even on filesystems with coarse timestamps.
	if err := os.WriteFile(path, makeBundle(t, 2), 0o600); err != nil {
		t.Fatalf("rewrite bundle: %v", err)
	}
	bumped := fi.ModTime().Add(time.Second)
	if err := os.Chtimes(path, bumped, bumped); err != nil {
		t.Fatalf("bump mtime: %v", err)
	}

	cert, err := getCert(nil)
	if err != nil {
		t.Fatalf("Loader() after rewrite error = %v", err)
	}
	if got := leafSerial(t, cert); got != 2 {
		t.Fatalf("Loader() leaf serial after rewrite = %d, want 2", got)
	}
}

func TestLoaderErrorWhenBundleMissing(t *testing.T) {
	getCert := Loader(t.TempDir() + "/absent.pem")
	if _, err := getCert(nil); err == nil {
		t.Fatalf("Loader() error = nil, want missing-file error")
	}
}

func TestLoaderRecoversAfterError(t *testing.T) {
	bundle := makeBundle(t, 3)
	path := writeBundle(t, bundle)
	getCert := Loader(path)

	if _, err := getCert(nil); err != nil {
		t.Fatalf("Loader() first call error = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove bundle: %v", err)
	}
	if _, err := getCert(nil); err == nil {
		t.Fatalf("Loader() error = nil after bundle removed, want error")
	}
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("restore bundle: %v", err)
	}

	cert, err := getCert(nil)
	if err != nil {
		t.Fatalf("Loader() after restore error = %v", err)
	}
	if got := leafSerial(t, cert); got != 3 {
		t.Fatalf("Loader() leaf serial after restore = %d, want 3", got)
	}
}

func TestClientLoaderCachesAndReloads(t *testing.T) {
	path := writeProjectedBundle(t, makeBundle(t, 1))
	getCert := ClientLoader(path)

	cert, err := getCert(nil)
	if err != nil {
		t.Fatalf("ClientLoader() first call error = %v", err)
	}
	if got := leafSerial(t, cert); got != 1 {
		t.Fatalf("ClientLoader() leaf serial = %d, want 1", got)
	}

	if err := rotateProjectedBundle(path, makeBundle(t, 2)); err != nil {
		t.Fatalf("rotate bundle: %v", err)
	}

	cert, err = getCert(nil)
	if err != nil {
		t.Fatalf("ClientLoader() after rotation error = %v", err)
	}
	if got := leafSerial(t, cert); got != 2 {
		t.Fatalf("ClientLoader() leaf serial after rotation = %d, want 2", got)
	}
}

func TestPoolLoaderServesCachedParseWhileFileUnchanged(t *testing.T) {
	path := writeBundle(t, makeTrustBundle(t, 5))
	getPool := PoolLoader(path)

	first, err := getPool()
	if err != nil {
		t.Fatalf("PoolLoader() first call error = %v", err)
	}
	second, err := getPool()
	if err != nil {
		t.Fatalf("PoolLoader() second call error = %v", err)
	}

	// Pointer identity for the same reason as the Loader case: x509.CertPool
	// has an Equal method, so a re-parse of the same file compares equal and
	// a value assertion could not tell the two apart.
	if first != second {
		t.Fatalf("PoolLoader() re-parsed an unchanged file, want the cached parse")
	}
}

// The trust-anchor counterpart of TestLoaderPicksUpRotationWithAnIdenticalStatTriple,
// and the more serious direction of the two: the pool is the root set a peer is
// verified against, so a stat-triple cache keeps trusting a rotated-out CA.
func TestPoolLoaderPicksUpRotationWithAnIdenticalStatTriple(t *testing.T) {
	before := makeTrustBundle(t, 1)
	path := writeBundle(t, before)
	getPool := PoolLoader(path)

	first, err := getPool()
	if err != nil {
		t.Fatalf("PoolLoader() first call error = %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}

	after := makeTrustBundle(t, 2)
	if len(after) != len(before) {
		t.Fatalf("test setup: rotated trust bundle is %d bytes, want the same %d as the original", len(after), len(before))
	}
	if err := os.WriteFile(path, after, 0o600); err != nil {
		t.Fatalf("rotate trust bundle in place: %v", err)
	}
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatalf("restore mtime: %v", err)
	}
	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("re-stat bundle: %v", err)
	}
	if !os.SameFile(fi, fi2) || !fi2.ModTime().Equal(fi.ModTime()) || fi2.Size() != fi.Size() {
		t.Fatalf("test setup: stat triple changed across the rotation, so this would pass without the fix")
	}

	second, err := getPool()
	if err != nil {
		t.Fatalf("PoolLoader() after rotation error = %v", err)
	}
	if second.Equal(first) {
		t.Fatalf("PoolLoader() served the pre-rotation pool -- a rotated-out CA is still a trust anchor")
	}
	wantPool := x509.NewCertPool()
	if !wantPool.AppendCertsFromPEM(after) {
		t.Fatalf("test setup: rotated trust bundle holds no certificates")
	}
	if !second.Equal(wantPool) {
		t.Fatalf("PoolLoader() pool does not match the rotated-in trust bundle")
	}
}

func TestPoolLoaderPicksUpProjectedVolumeRotation(t *testing.T) {
	path := writeProjectedBundle(t, makeTrustBundle(t, 1))
	getPool := PoolLoader(path)

	before, err := getPool()
	if err != nil {
		t.Fatalf("PoolLoader() first call error = %v", err)
	}

	rotated := makeTrustBundle(t, 2)
	if err := rotateProjectedBundle(path, rotated); err != nil {
		t.Fatalf("rotate bundle: %v", err)
	}

	after, err := getPool()
	if err != nil {
		t.Fatalf("PoolLoader() after rotation error = %v", err)
	}
	if after.Equal(before) {
		t.Fatalf("PoolLoader() did not pick up the rotated trust bundle")
	}
	want, err := ParsePool(path)
	if err != nil {
		t.Fatalf("ParsePool() error = %v", err)
	}
	if !after.Equal(want) {
		t.Fatalf("PoolLoader() pool does not match the rotated trust bundle")
	}
}

func TestPoolLoaderErrorWhenBundleMissing(t *testing.T) {
	getPool := PoolLoader(t.TempDir() + "/absent.pem")
	if _, err := getPool(); err == nil {
		t.Fatalf("PoolLoader() error = nil, want missing-file error")
	}
}

func TestParsePoolRejectsBundleWithoutCertificates(t *testing.T) {
	path := writeBundle(t, []byte("not a certificate"))
	if _, err := ParsePool(path); err == nil {
		t.Fatalf("ParsePool() error = nil, want no-certificates error")
	}
}

func TestLoaderConcurrentHandshakes(t *testing.T) {
	bundles := [][]byte{makeBundle(t, 1), makeBundle(t, 2)}
	path := writeProjectedBundle(t, bundles[0])
	getCert := Loader(path)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 25; i++ {
			if err := rotateProjectedBundle(path, bundles[i%2]); err != nil {
				t.Errorf("rotate bundle: %v", err)
				return
			}
		}
	}()
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				cert, err := getCert(nil)
				if err != nil {
					// macOS rename(2) is not atomic with respect to
					// concurrent path resolution through the swapped
					// symlink and can surface a transient EINVAL from
					// stat. Linux, where this runs in production and CI,
					// guarantees resolution sees the old or new target.
					if errors.Is(err, syscall.EINVAL) {
						continue
					}
					t.Errorf("Loader() error = %v", err)
					return
				}
				if cert.Leaf == nil {
					t.Errorf("Loader() returned certificate with nil leaf")
					return
				}
				if s := cert.Leaf.SerialNumber.Int64(); s != 1 && s != 2 {
					t.Errorf("Loader() leaf serial = %d, want 1 or 2", s)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func generateCertificate(t *testing.T, serial int64) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "api.ate-system.svc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"api.ate-system.svc"},
	}
	key := generateRSAKey(t)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func writeBundle(t *testing.T, bundle []byte) string {
	t.Helper()
	path := t.TempDir() + "/bundle.pem"
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

// makeBundle returns a PEM credential bundle whose leaf certificate carries
// the given serial number, so tests can tell which bundle a parsed
// certificate came from.
func makeBundle(t *testing.T, serial int64) []byte {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(generateRSAKey(t))
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	return append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: generateCertificate(t, serial)}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
}

// makeTrustBundle returns a PEM trust bundle of a single CERTIFICATE block
// whose serial number lets tests tell one bundle from another.
func makeTrustBundle(t *testing.T, serial int64) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: generateCertificate(t, serial)})
}

func leafSerial(t *testing.T, cert *tls.Certificate) int64 {
	t.Helper()
	if cert == nil || cert.Leaf == nil {
		t.Fatalf("parsed bundle has no leaf certificate")
	}
	return cert.Leaf.SerialNumber.Int64()
}

// writeProjectedBundle lays a bundle out the way the kubelet's atomic writer
// (k8s.io/kubernetes/pkg/volume/util/atomic_writer.go) materializes projected
// volumes:
//
//	<dir>/bundle.pem -> ..data/bundle.pem
//	<dir>/..data     -> ..payload-<unique>/  (kubelet uses a timestamped name)
//	<dir>/..payload-<unique>/bundle.pem
//
// and returns the visible <dir>/bundle.pem path.
func writeProjectedBundle(t *testing.T, bundle []byte) string {
	t.Helper()
	dir := t.TempDir()
	payload, err := os.MkdirTemp(dir, "..payload-")
	if err != nil {
		t.Fatalf("create payload dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(payload, "bundle.pem"), bundle, 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := os.Symlink(filepath.Base(payload), filepath.Join(dir, "..data")); err != nil {
		t.Fatalf("symlink ..data: %v", err)
	}
	if err := os.Symlink(filepath.Join("..data", "bundle.pem"), filepath.Join(dir, "bundle.pem")); err != nil {
		t.Fatalf("symlink bundle.pem: %v", err)
	}
	return filepath.Join(dir, "bundle.pem")
}

// rotateProjectedBundle rotates the bundle behind a writeProjectedBundle path
// the way the kubelet's atomic writer does: write the new payload into a
// fresh directory, point a ..data_tmp symlink at it, atomically rename that
// over ..data, and remove the old payload directory. The visible path is
// untouched throughout; only what it resolves to changes.
func rotateProjectedBundle(path string, bundle []byte) error {
	dir, name := filepath.Dir(path), filepath.Base(path)
	oldPayload, err := os.Readlink(filepath.Join(dir, "..data"))
	if err != nil {
		return fmt.Errorf("readlink ..data: %w", err)
	}
	payload, err := os.MkdirTemp(dir, "..payload-")
	if err != nil {
		return fmt.Errorf("create payload dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(payload, name), bundle, 0o600); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	tmpLink := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(filepath.Base(payload), tmpLink); err != nil {
		return fmt.Errorf("symlink ..data_tmp: %w", err)
	}
	if err := os.Rename(tmpLink, filepath.Join(dir, "..data")); err != nil {
		return fmt.Errorf("swap ..data: %w", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, oldPayload)); err != nil {
		return fmt.Errorf("remove old payload dir: %w", err)
	}
	return nil
}
