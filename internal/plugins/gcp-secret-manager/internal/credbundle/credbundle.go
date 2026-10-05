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

// Package credbundle loads Kubernetes Pod Certificate credential bundles and PEM
// trust bundles. A credential bundle is one PEM file holding a PRIVATE KEY block
// and the CERTIFICATE chain, leaf first, with or without the root.
//
// It is the server-side subset of substrate's internal/credbundle, copied so
// this module depends only on substrate's public packages.
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

// Loader returns a tls.Config GetCertificate function serving the credential
// bundle at path. The parse is cached and redone only when the file contents
// change, so a rotation is picked up on the next handshake.
func Loader(path string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := &certCache{path: path}
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return c.get()
	}
}

// PoolLoader returns a function yielding the trust pool in the PEM file at
// path, cached like Loader's. Call it per connection, e.g. from
// GetConfigForClient: a tls.Config's ClientCAs is fixed once in use, so a pool
// built at startup would miss a CA rotation.
//
// This pool is the root set client certificates are verified against, so a
// missed rotation here keeps trusting a CA that was rotated out.
func PoolLoader(path string) func() (*x509.CertPool, error) {
	c := &poolCache{path: path}
	return c.get
}

// certCache caches a credential bundle's parse with the bytes it came from.
type certCache struct {
	path string

	mu sync.Mutex
	// raw is the content cert was parsed from; nil until the first successful
	// parse. cert is served while a fresh read returns the same bytes.
	raw  []byte
	cert *tls.Certificate
}

// get returns the cached bundle, re-parsing only when the file contents have
// changed since the last successful parse.
//
// The comparison is over the bytes, not the file's metadata. Stat-based
// invalidation is what a rotation can slip past: filesystem timestamps are
// granular (a millisecond on a typical CONFIG_HZ=1000 kernel), an in-place
// rewrite leaves the inode unchanged, and two certificates minted from one
// template encode to the same length, so a rotation landing inside that window
// is invisible in identity, mtime and size at once. Reading the file is what
// makes the check exact, and it costs nothing worth saving: a bundle is a few
// kilobytes, read once per handshake, against the public-key operations that
// follow. The parse is what the cache is for, and byte-identical content still
// yields the identical parse.
//
// The already-parsed guard is load-bearing rather than an optimisation: bytes
// are equal when both are empty, so without it a first call against an empty
// file would serve a nil result as if it were a cache hit.
//
// A change between the read and the caller's use of the result is picked up by
// the next call, so the cache lags a rotation by at most one handshake. Errors
// are returned, never masked by the cache, and later calls retry.
func (c *certCache) get() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	raw, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("while reading credential bundle %q: %w", c.path, err)
	}
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

// poolCache is certCache for a trust bundle.
type poolCache struct {
	path string

	mu   sync.Mutex
	raw  []byte
	pool *x509.CertPool
}

// get returns the cached trust pool, re-parsing as certCache.get does; see
// there for the change-detection reasoning.
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

// Parse reads the PKCS#8 private key and certificate chain from a credential
// bundle file.
func Parse(bundlePath string) (*tls.Certificate, error) {
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("while reading credential bundle: %w", err)
	}
	return parseBundle(bundleBytes)
}

// parseBundle is Parse over bytes already read, so the caches can compare the
// content they parsed without reading the file twice.
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

// ParsePool reads a PEM trust bundle into a pool. A file with no certificates
// is an error, since an empty pool would silently reject every peer.
func ParsePool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("while reading trust bundle: %w", err)
	}
	return parsePool(pemBytes, path)
}

// parsePool is ParsePool over bytes already read. path is carried only for the
// error message.
func parsePool(pemBytes []byte, path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("trust bundle %q contains no certificates", path)
	}
	return pool, nil
}
