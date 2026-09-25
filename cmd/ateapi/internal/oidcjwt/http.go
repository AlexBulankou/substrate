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

package oidcjwt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/agent-substrate/substrate/internal/credbundle"
)

// NewHTTPClient returns a client for OIDC discovery and JWKS requests.
func NewHTTPClient(issuer, certificateAuthorityFile, discoveryTokenFile string) (*http.Client, error) {
	if discoveryTokenFile != "" && certificateAuthorityFile == "" {
		return nil, fmt.Errorf("discovery token file requires a certificate authority file")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if certificateAuthorityFile != "" {
		loadRoots := credbundle.PoolLoader(certificateAuthorityFile)
		// Read once here so a missing or malformed CA file fails the provider
		// at startup rather than on the first discovery request.
		if _, err := loadRoots(); err != nil {
			return nil, fmt.Errorf("read certificate authority file: %w", err)
		}
		transport.DialTLSContext = rotatingDialTLS(transport, loadRoots)
	}
	var roundTripper http.RoundTripper = transport
	if discoveryTokenFile != "" {
		roundTripper = &issuerDiscoveryTransport{base: transport, tokenFile: discoveryTokenFile, issuer: issuer}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: roundTripper}, nil
}

// rotatingDialTLS returns a DialTLSContext that reads the trust anchors for
// every connection.
//
// Setting them on transport.TLSClientConfig instead would freeze them: a
// tls.Config's RootCAs is fixed once the transport is in use, so the issuer's
// CA would be pinned for the lifetime of the process and discovery would fail
// from the moment that CA rotated until ateapi restarted. The bearer token
// beside it is already re-read per request for the same reason.
//
// credbundle.PoolLoader caches on a stat triple, so a connection that finds an
// unchanged file pays one stat.
func rotatingDialTLS(transport *http.Transport, loadRoots func() (*x509.CertPool, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		roots, err := loadRoots()
		if err != nil {
			return nil, fmt.Errorf("read certificate authority file: %w", err)
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("split host and port of %q: %w", addr, err)
		}
		conn, err := transport.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, &tls.Config{
			RootCAs:    roots,
			ServerName: host,
			// net/http negotiates HTTP/2 over ALPN, which it can only do for
			// itself when it owns the dial. Advertise the same protocols it
			// would have.
			NextProtos: []string{"h2", "http/1.1"},
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}

// issuerDiscoveryTransport injects a bearer token for requests within the
// configured issuer and Kubernetes' standard JWKS path. Reads the token file
// on every request so rotation is handled automatically.
type issuerDiscoveryTransport struct {
	base      http.RoundTripper
	tokenFile string
	issuer    string
}

func (t *issuerDiscoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if issuerScopedURL(req.URL.String(), t.issuer) || isKubernetesJWKSURL(req.URL.String()) {
		token, err := os.ReadFile(t.tokenFile)
		if err != nil {
			return nil, fmt.Errorf("read discovery token file: %w", err)
		}
		trimmed := strings.TrimSpace(string(token))
		if trimmed == "" {
			return nil, fmt.Errorf("discovery token file %q is empty", t.tokenFile)
		}
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+trimmed)
	}
	return t.base.RoundTrip(req)
}

func issuerScopedURL(rawURL, issuer string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, issuerURL.Scheme) || !strings.EqualFold(u.Host, issuerURL.Host) {
		return false
	}
	issuerPath := strings.TrimRight(issuerURL.EscapedPath(), "/")
	if issuerPath == "" {
		issuerPath = "/"
	}
	requestPath := u.EscapedPath()
	if issuerPath == "/" {
		return strings.HasPrefix(requestPath, "/")
	}
	return requestPath == issuerPath || strings.HasPrefix(requestPath, issuerPath+"/")
}

func isKubernetesJWKSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https") && u.EscapedPath() == "/openid/v1/jwks"
}
