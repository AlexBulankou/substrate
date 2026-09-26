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

// Package credbundle handles credential bundle files written by Kubernetes Pod Certificates.
//
// A credential bundle is a single file with multiple PEM entries. The first entry is a PRIVATE KEY
// block, and all remaining entries are CERTIFICATE blocks. The CERTIFICATE blocks are in
// leaf-to-root order, and may or may not include the root.
package credbundle

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
)

// Loader reads a private key and certificate chain from a credential bundle file as written by the
// Kubernetes Pod Certificates mechanism.
//
// Returns a function that can be used as GetCertificate in a tls.Config. The parsed bundle is
// cached: each handshake reads the file and re-parses it only when the contents have changed, so
// pod-certificate rotations are picked up on the next handshake without paying the parse cost
// when nothing changed.
func Loader(path string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := &certCache{path: path}
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.get()
	}
}

// ClientLoader is the client-side counterpart to Loader. It returns a function
// suitable for use as GetClientCertificate in a tls.Config, caching the parsed
// bundle in the same way so that pod-certificate rotations are picked up on
// the next handshake.
func ClientLoader(path string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c := &certCache{path: path}
	return func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return c.get()
	}
}

// PoolLoader reads a set of trust anchors from a PEM trust-bundle file, as
// projected from a Kubernetes ClusterTrustBundle, and returns a function that
// yields the parsed *x509.CertPool.
//
// A tls.Config's ClientCAs (and RootCAs) is frozen once the config is in use,
// so a pool built at startup never sees a CA rotation. Calling the returned
// function per connection — from GetConfigForClient on the server side — keeps
// verification current: the parsed pool is cached and re-parsed only when the
// file contents change, mirroring Loader, so a rotation is picked up on the
// next handshake without paying the parse cost when nothing changed.
func PoolLoader(path string) func() (*x509.CertPool, error) {
	c := &poolCache{path: path}
	return c.get
}

// certCache holds the parse of a credential bundle file together with the exact
// bytes it was parsed from, so unchanged files are not re-parsed on every TLS
// handshake.
type certCache struct {
	path string

	mu sync.Mutex
	// raw is the content cert was parsed from; nil until the first successful
	// parse. cert is served while a fresh read of path returns the same bytes.
	raw  []byte
	cert *tls.Certificate
}

// get returns the parsed bundle, re-parsing only when the file contents differ
// from the content of the last successful parse.
//
// Change detection is on the bytes rather than on a stat triple (identity,
// mtime, size) because all three survive a genuine rotation. An in-place
// rewrite keeps the inode, so os.SameFile holds; two credentials issued from
// the same template encode to the same length, so the size holds; and mtime
// resolution is a filesystem timestamp tick -- 1ms on a CONFIG_HZ=1000 host --
// so a rewrite landing in the same tick as the write the cache last observed
// keeps the mtime too. Both remaining paths point the wrong way: a rotated-out
// trust anchor stays in the verification root set, and a rotated-out client
// credential keeps being presented. The exposure is small but it is a trust
// surface, and the bytes are the thing actually being asked about.
//
// The cost is a read per call instead of a stat; the parse, which is the
// expensive part, is still skipped when nothing changed. Reading also removes
// the stat/read skew the previous implementation had to reason about: the
// bytes stored are exactly the bytes parsed.
//
// Errors leave the previous entry in place and are returned to the caller:
// handshakes fail exactly as they would without caching, and every later call
// retries until a parse succeeds.
func (c *certCache) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	raw, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("while reading credential bundle %q: %w", c.path, err)
	}
	// c.cert != nil, not len(c.raw) != 0: on the first call c.raw is nil, and
	// bytes.Equal(nil, []byte{}) is true, so an empty file would otherwise be
	// served as a cache hit holding no credential at all.
	if c.cert != nil && bytes.Equal(c.raw, raw) {
		return c.cert, nil
	}

	cert, err := parseBundle(raw)
	if err != nil {
		return nil, err
	}
	c.raw, c.cert = raw, cert
	return cert, nil
}

// poolCache holds the parse of a trust-bundle file together with the exact
// bytes it was parsed from, so unchanged files are not re-parsed on every TLS
// handshake. It mirrors certCache; see get for the change-detection and
// concurrency reasoning.
type poolCache struct {
	path string

	mu   sync.Mutex
	raw  []byte
	pool *x509.CertPool
}

// get returns the parsed trust pool, re-parsing only when the file contents
// differ from the content of the last successful parse. Change detection and
// error handling match certCache.get.
func (c *poolCache) get() (*x509.CertPool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	raw, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("while reading trust bundle %q: %w", c.path, err)
	}
	if c.pool != nil && bytes.Equal(c.raw, raw) {
		return c.pool, nil
	}

	pool, err := parsePool(raw, c.path)
	if err != nil {
		return nil, err
	}
	c.raw, c.pool = raw, pool
	return pool, nil
}

// Parse reads a private key and certificate chain from a credential bundle file as written by the
// Kubernetes Pod Certificates mechanism.
func Parse(bundlePath string) (*tls.Certificate, error) {
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("while reading credential bundle: %w", err)
	}
	return parseBundle(bundleBytes)
}

// parseBundle is Parse over content already in hand. The caches read the file
// themselves -- change detection is on the bytes -- so they parse what they
// compared rather than re-reading and risking a parse of different content.
func parseBundle(bundleBytes []byte) (*tls.Certificate, error) {
	var leafKeyBytes []byte
	var chainBytes [][]byte

	for {
		var block *pem.Block
		block, bundleBytes = pem.Decode(bundleBytes)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			chainBytes = append(chainBytes, block.Bytes)
		case "PRIVATE KEY":
			leafKeyBytes = block.Bytes
		default:
			return nil, fmt.Errorf("unknown PEM block type %q", block.Type)
		}
	}

	if leafKeyBytes == nil {
		return nil, fmt.Errorf("no PRIVATE KEY block found")
	}

	if len(chainBytes) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found")
	}

	leafKey, err := x509.ParsePKCS8PrivateKey(leafKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("while parsing private key: %w", err)
	}

	leafCert, err := x509.ParseCertificate(chainBytes[0])
	if err != nil {
		return nil, fmt.Errorf("while parsing leaf certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: chainBytes,
		Leaf:        leafCert,
		PrivateKey:  leafKey,
	}, nil
}

// ParsePool reads a PEM trust-bundle file into an *x509.CertPool. It returns an
// error if the file holds no certificates: an empty trust pool would silently
// reject every peer, which is never what a workload should receive.
func ParsePool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("while reading trust bundle: %w", err)
	}
	return parsePool(pemBytes, path)
}

// parsePool is ParsePool over content already in hand; path is used only to
// name the file in the error. See parseBundle for why the caches need this.
func parsePool(pemBytes []byte, path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("trust bundle %q contains no certificates", path)
	}
	return pool, nil
}
