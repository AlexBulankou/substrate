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
	"fmt"

	"github.com/agent-substrate/substrate/internal/credbundle"
	"github.com/agent-substrate/substrate/internal/k8sresolver"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
)

const DefaultServiceAccountCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

// roundRobinServiceConfig spreads RPCs across every address the resolver
// returns.
const roundRobinServiceConfig = `{"loadBalancingConfig": [{"round_robin":{}}]}`

// ClientConfig configures how to dial the ateapi gRPC server with mutual TLS.
// The credential bundle is re-read on every handshake so in-place
// pod-certificate rotations are picked up.
type ClientConfig struct {
	// CAFile is a PEM file containing CA certs that sign the server cert.
	// Required.
	CAFile string

	// ServerName overrides SNI / hostname verification. Optional.
	ServerName string

	// ClientCredBundle is a PEM file containing the client certificate chain
	// and PKCS8 private key presented to the server. Required.
	ClientCredBundle string

	// K8sClient is an optional Kubernetes client. When provided, an EndpointSlice
	// resolver builder using this client will be attached to DialOptions.
	K8sClient kubernetes.Interface
}

// DialOptions returns the grpc.DialOption set described by cfg, suitable to
// pass to grpc.NewClient.
func DialOptions(cfg ClientConfig) ([]grpc.DialOption, error) {
	if cfg.CAFile == "" {
		return nil, fmt.Errorf("ateapiauth: CAFile is required")
	}
	if cfg.ClientCredBundle == "" {
		return nil, fmt.Errorf("ateapiauth: a client credential bundle (mTLS) is required")
	}
	loadRootCAs := credbundle.PoolLoader(cfg.CAFile)
	if _, err := loadRootCAs(); err != nil {
		return nil, fmt.Errorf("ateapiauth: loading CA file: %w", err)
	}
	// Everything the dial needs except the trust anchors, which rotate and so
	// are supplied per handshake by the credentials below.
	//
	// There is deliberately no InsecureSkipVerify and no VerifyConnection here.
	// Reloading the anchors does not need either, and a hand-rolled verifier
	// that forwards ServerName into x509.VerifyOptions.DNSName silently skips
	// the hostname check whenever ServerName is unset -- which is the
	// documented default, and what cmd/atecontroller and the cmd/atenet router
	// both ship.
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// ServerName is optional. Left empty, grpc-go fills it from the
		// address being dialled, so the standard path verifies against that;
		// set, it both selects SNI and becomes the name verified.
		ServerName: cfg.ServerName,
	}

	opts := []grpc.DialOption{
		grpc.WithDefaultServiceConfig(roundRobinServiceConfig),
	}
	if cfg.K8sClient != nil {
		opts = append(opts, grpc.WithResolvers(k8sresolver.NewBuilder(cfg.K8sClient)))
	}

	tlsCfg.GetClientCertificate = credbundle.ClientLoader(cfg.ClientCredBundle)
	opts = append(opts, grpc.WithTransportCredentials(newReloadingRootCredentials(tlsCfg, loadRootCAs)))
	return opts, nil
}
