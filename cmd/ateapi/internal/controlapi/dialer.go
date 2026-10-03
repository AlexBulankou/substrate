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

package controlapi

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"

	"github.com/agent-substrate/substrate/internal/atelet"
	"github.com/agent-substrate/substrate/internal/credbundle"
	"github.com/agent-substrate/substrate/internal/installdefaults"
	"github.com/agent-substrate/substrate/internal/substratex509"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/lru"
)

// ErrNoAteletOnNode reports that the informer cache holds no atelet pod for
// the requested node — e.g. the atelet is restarting, or the node is gone.
// Retryable.
var ErrNoAteletOnNode = errors.New("no atelet pod found on node")

// ateletConn is a cached connection and the pod IP it was dialed on.
type ateletConn struct {
	ip   string
	conn *grpc.ClientConn
}

// AteletDialer handles gRPC connections to Atelet pods.
type AteletDialer struct {
	ateletIndexer cache.Indexer
	// mu makes each cache lookup, stale eviction and insert atomic, so
	// concurrent callers cannot evict each other's fresh conn. It is held for
	// cache access only, never across a dial — serializing the dial itself is
	// what dialFlight does, per atelet rather than per dialer.
	mu sync.Mutex
	// ateletConns holds one *ateletConn per atelet pod UID.
	ateletConns *lru.Cache
	// dialCredentials builds the transport credentials used to dial a given
	// atelet, keyed on the atelet's expected pod UID. Production wires this to
	// per-atelet mTLS; tests can override it with insecure credentials.
	dialCredentials func(expectedPodUID string) (credentials.TransportCredentials, error)
	// dialFlight collapses concurrent cache misses for the same atelet onto a
	// single dial. One dialer serves every node in the process, so the
	// exclusion has to be keyed on the atelet rather than held on the dialer:
	// a cold dial reads and parses the CA bundle off disk, and under a
	// dialer-wide lock every other node's callers — including cache hits —
	// wait behind it. Keyed on pod UID and IP together, so a pod that kept its
	// UID but moved IP is not handed an in-flight dial to its old address.
	dialFlight singleflight.Group
}

// DialerOption customizes an AteletDialer built by NewAteletDialer.
type DialerOption func(*AteletDialer)

// WithDialCredentials overrides how transport credentials are built for a given
// atelet pod UID. Tests use it to reach a fake atelet over insecure transport
// while still exercising the real lookup, dial and connection-cache path.
func WithDialCredentials(build func(expectedPodUID string) (credentials.TransportCredentials, error)) DialerOption {
	return func(d *AteletDialer) { d.dialCredentials = build }
}

// NewAteletDialer creates a new AteletDialer. clientBundlePath and serverCAPath
// are used to build the per-atelet mTLS credentials used for every atelet
// connection, and ateletSPIFFEID is the identity those credentials expect on
// the atelet serving cert.
func NewAteletDialer(ateletIndexer cache.Indexer, ateletSPIFFEID, clientBundlePath, serverCAPath string, opts ...DialerOption) *AteletDialer {
	d := &AteletDialer{
		ateletIndexer: ateletIndexer,
		ateletConns:   newAteletConnCache(1024),
		dialCredentials: func(expectedPodUID string) (credentials.TransportCredentials, error) {
			tlsConfig, err := buildTLSConfig(ateletSPIFFEID, clientBundlePath, serverCAPath, expectedPodUID)
			if err != nil {
				return nil, err
			}
			return credentials.NewTLS(tlsConfig), nil
		},
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// newAteletConnCache builds the atelet conn cache, which closes the
// connections it evicts. A conn pushed out of the LRU without Close is not
// reclaimed: grpc keeps most of its goroutines and buffers alive for the
// life of the process. Closing on eviction can fail an RPC still in flight
// on a conn that aged to the LRU tail, but that failure is visible and
// retryable, unlike the leak.
//
// TODO: Consider pool semantics instead of a cache: a conn evicted for
// capacity would drain — close only once its last in-flight RPC finishes
// (e.g. refcounted checkout/release) — rather than being closed out from
// under a caller. Worth revisiting if the retryable eviction failures show
// up in practice.
func newAteletConnCache(size int) *lru.Cache {
	return lru.NewWithEvictionFunc(size, func(_ lru.Key, value interface{}) {
		_ = value.(*ateletConn).conn.Close()
	})
}

// DialForAteletOnNode resolves the single atelet pod on nodeName and dials it
// with per-atelet pod-UID-pinned credentials, caching the connection by the
// atelet's pod UID. A pod that keeps its UID but gets a new IP, such as after a
// node restart, is redialed.
func (d *AteletDialer) DialForAteletOnNode(nodeName string) (*grpc.ClientConn, error) {
	matchingAtelets, err := d.ateletIndexer.ByIndex(byNode, nodeName)
	if err != nil {
		return nil, fmt.Errorf("while finding atelet on node %q: %w", nodeName, err)
	}

	if len(matchingAtelets) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoAteletOnNode, nodeName)
	}
	if len(matchingAtelets) > 1 {
		return nil, fmt.Errorf("found %d atelet pods on node %q, expected 1", len(matchingAtelets), nodeName)
	}

	selectedAtelet := matchingAtelets[0].(*corev1.Pod)
	if len(selectedAtelet.Status.PodIPs) == 0 {
		return nil, fmt.Errorf("selected atelet %q has no assigned IPs", selectedAtelet.ObjectMeta.Namespace+"/"+selectedAtelet.ObjectMeta.Name)
	}
	ateletKey := string(selectedAtelet.ObjectMeta.UID)
	ateletIP := selectedAtelet.Status.PodIPs[0].IP

	if conn, ok := d.cachedConn(ateletKey, ateletIP); ok {
		return conn, nil
	}

	// One dial per atelet, however many callers miss together; misses on other
	// atelets take other keys and dial in parallel.
	dialed, err, _ := d.dialFlight.Do(ateletKey+"\x00"+ateletIP, func() (any, error) {
		// A caller that missed just as an earlier flight was finishing is
		// served from the cache here rather than dialing a second time.
		if conn, ok := d.cachedConn(ateletKey, ateletIP); ok {
			return conn, nil
		}

		creds, err := d.dialCredentials(ateletKey)
		if err != nil {
			return nil, fmt.Errorf("while building atelet credentials: %w", err)
		}

		conn, err := grpc.NewClient(
			net.JoinHostPort(ateletIP, strconv.Itoa(atelet.DefaultPort)),
			grpc.WithTransportCredentials(creds),
			grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
		)
		if err != nil {
			return nil, fmt.Errorf("while creating atelet gRPC client connection: %w", err)
		}

		d.storeConn(ateletKey, ateletIP, conn)

		return conn, nil
	})
	if err != nil {
		return nil, err
	}

	return dialed.(*grpc.ClientConn), nil
}

// cachedConn returns the connection cached for ateletKey if it was dialed on
// ateletIP. A connection cached on a different IP belongs to a pod that kept
// its UID and moved, so it is evicted — which closes it — and reported as a
// miss.
func (d *AteletDialer) cachedConn(ateletKey, ateletIP string) (*grpc.ClientConn, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cached, ok := d.ateletConns.Get(ateletKey)
	if !ok {
		return nil, false
	}
	if c := cached.(*ateletConn); c.ip == ateletIP {
		return c.conn, true
	}
	// Remove closes the stale connection.
	d.ateletConns.Remove(ateletKey)
	return nil, false
}

// storeConn caches conn as the connection for ateletKey on ateletIP.
func (d *AteletDialer) storeConn(ateletKey, ateletIP string, conn *grpc.ClientConn) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Remove first: Add over an existing key replaces the value without
	// running the eviction func, so a connection displaced that way would
	// never be closed.
	d.ateletConns.Remove(ateletKey)
	d.ateletConns.Add(ateletKey, &ateletConn{ip: ateletIP, conn: conn})
}

func buildTLSConfig(ateletSPIFFEID, clientBundlePath, serverCAPath, expectedPodUID string) (*tls.Config, error) {
	trustDomain, err := spiffeid.TrustDomainFromString(installdefaults.AteletTrustDomain)
	if err != nil {
		return nil, fmt.Errorf("while parsing trust domain %q: %w", installdefaults.AteletTrustDomain, err)
	}
	bundle, err := x509bundle.Load(trustDomain, serverCAPath)
	if err != nil {
		return nil, fmt.Errorf("while loading CA bundle from %s: %w", serverCAPath, err)
	}
	expectedID, err := spiffeid.FromString(ateletSPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("while parsing expected atelet SPIFFE ID %q: %w", ateletSPIFFEID, err)
	}

	verify, err := verifyAteletServerCert(bundle, expectedID, expectedPodUID)
	if err != nil {
		return nil, fmt.Errorf("while creating atelet server cert verifier: %w", err)
	}

	tlsConfig := tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: credbundle.ClientLoader(clientBundlePath),
		// Skip the default verification because the peer is dialed by IP and its
		// certificate has no DNS/IP SAN.
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
	}

	return &tlsConfig, nil
}

func verifyAteletServerCert(bundle *x509bundle.Bundle, expectedID spiffeid.ID, expectedPodUID string) (func(tls.ConnectionState) error, error) {
	if expectedPodUID == "" {
		return nil, fmt.Errorf("expected pod UID must not be empty")
	}
	if expectedID.IsZero() {
		return nil, fmt.Errorf("expected pod spiffe ID must not be empty")
	}
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("server presented no certificate")
		}
		id, _, err := x509svid.Verify(cs.PeerCertificates, bundle)
		if err != nil {
			return fmt.Errorf("verifying server certificate chain: %w", err)
		}
		if id != expectedID {
			return fmt.Errorf("server SPIFFE ID %q does not match expected %q", id, expectedID)
		}

		leaf := cs.PeerCertificates[0]
		if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			return fmt.Errorf("server certificate lacks the serverAuth extended key usage")
		}

		identity, err := substratex509.PodIdentityFromCertificate(leaf)
		if err != nil {
			return fmt.Errorf("failed to parse PodIdentity extension: %w", err)
		}
		if identity == nil {
			return fmt.Errorf("server certificate has no PodIdentity extension, expected pod UID %q", expectedPodUID)
		}
		if identity.PodUID != expectedPodUID {
			return fmt.Errorf("pod UID %q does not match expected %q", identity.PodUID, expectedPodUID)
		}

		return nil
	}, nil
}
