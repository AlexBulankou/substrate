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

package ateclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agent-substrate/substrate/internal/installdefaults"
	"github.com/agent-substrate/substrate/internal/portforward"
	"github.com/agent-substrate/substrate/internal/rotatingtls"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsv1beta1 "k8s.io/metrics/pkg/client/clientset/versioned"
)

// NamespaceEnv overrides the namespace the client looks for substrate in. The
// client runs outside the cluster, so it has no downward API to read and no pod
// namespace to fall back on.
const NamespaceEnv = "ATE_NAMESPACE"

// APIServiceEnv and ClientServiceAccountEnv override the ateapi Service and the
// ServiceAccount the client mints its token from. A deployment that prefixes
// resource names changes both, and the client has no way to discover that from
// outside the cluster.
const (
	APIServiceEnv           = "ATE_API_SERVICE_NAME"
	ClientServiceAccountEnv = "ATE_CLIENT_SERVICE_ACCOUNT"
)

// apiServiceName is the Service that fronts ateapi.
func apiServiceName() string {
	if n := os.Getenv(APIServiceEnv); n != "" {
		return n
	}
	return installdefaults.APIServiceName
}

// clientServiceAccount is the ServiceAccount the bearer token is minted from.
func clientServiceAccount() string {
	if n := os.Getenv(ClientServiceAccountEnv); n != "" {
		return n
	}
	return installdefaults.ClientServiceAccount
}

// systemNamespace is the namespace the client expects ateapi to be running in.
func systemNamespace() string {
	if ns := os.Getenv(NamespaceEnv); ns != "" {
		return ns
	}
	return installdefaults.SystemNamespace
}

// apiServerName is the in-cluster DNS name of the ateapi Service. It is both the
// name checked on ateapi's serving cert and the audience of the bearer token
// minted for it, so it has to track the namespace ateapi actually runs in.
func apiServerName() string {
	return fmt.Sprintf("%s.%s.svc", apiServiceName(), systemNamespace())
}

const (
	// serviceDNSSignerName and liveBundleSelector mirror the
	// clusterTrustBundle projected-volume sources that in-cluster clients
	// mount to verify ateapi's serving cert.
	serviceDNSSignerName = "servicedns.podcert.ate.dev/identity"
	liveBundleSelector   = "podcert.ate.dev/canarying=live"
)

// Client wraps the gRPC ControlClient and ensures the port-forward connection is closed when done.
type Client struct {
	ateapipb.ControlClient
	conn           *grpc.ClientConn
	cancel         func()
	tracerProvider *sdktrace.TracerProvider
}

// Close closes the underlying gRPC connection and stops the port-forwarder.

// roundRobinServiceConfig spreads RPCs over every address the resolver returns.
// ateapi is a headless Service, so that is one address per replica, and gRPC's
// default of pick_first would send an entire client's traffic to whichever one
// it connected to first. internal/ateapiauth dials with the same policy.
const roundRobinServiceConfig = `{"loadBalancingConfig": [{"round_robin":{}}]}`

func (c *Client) Close() {
	if c.tracerProvider != nil {
		// Best practice to ensure clean provider shutdown, even though we skip exporters for clients.
		_ = c.tracerProvider.Shutdown(context.Background())
	}
	if c.conn != nil {
		c.conn.Close()
	}
	if c.cancel != nil {
		c.cancel()
	}
}

// NewClient creates a new Ate API client. If endpoint is empty, it automatically
// port-forwards to the ate-api-server pod in substrate's system namespace.
func NewClient(ctx context.Context, kubeconfigPath, k8sContext, endpoint, tokenFile string, traceEnabled bool) (*Client, error) {
	tp, err := initTracing(ctx, traceEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tracing: %w", err)
	}

	var cli *Client
	if endpoint != "" {
		cli, err = dialDirect(ctx, kubeconfigPath, k8sContext, endpoint, tokenFile, traceEnabled)
	} else {
		cli, err = dialPortForward(ctx, kubeconfigPath, k8sContext, tokenFile, traceEnabled)
	}

	if err != nil {
		if tp != nil {
			_ = tp.Shutdown(ctx)
		}
		return nil, err
	}

	cli.tracerProvider = tp
	return cli, nil
}

func dialDirect(ctx context.Context, kubeconfigPath, k8sContext, endpoint, tokenFile string, traceEnabled bool) (*Client, error) {
	config, err := LoadKubeConfig(kubeconfigPath, k8sContext)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	// We fetch a ClusterTrustBundle via the certificates.k8s.io/v1beta1 API in
	// serverTLSConfig().  Until we migrate to certificates.k8s.io/v1
	// ClusterTrustBundle (which locks us into supporting only k8s 1.37+
	// clusters), client-go will print out a warning every time it initializes.
	config.WarningHandlerWithContext = &rest.NoWarnings{}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	// Verify the server before attaching the bearer token below: the token
	// must never be sent over an unauthenticated channel.
	creds, err := serverCredentials(ctx, clientset)
	if err != nil {
		return nil, err
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(creds))
	opts = append(opts, grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	opts = append(opts, grpc.WithDefaultServiceConfig(roundRobinServiceConfig))
	tokenOpt, err := bearerTokenDialOption(ctx, clientset, tokenFile)
	if err != nil {
		return nil, err
	}
	opts = append(opts, tokenOpt)

	if traceEnabled {
		opts = append(opts, grpc.WithUnaryInterceptor(newTraceInterceptor()))
	}

	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial manual endpoint: %w", err)
	}
	return &Client{
		ControlClient: ateapipb.NewControlClient(conn),
		conn:          conn,
		cancel:        func() {},
	}, nil
}

// LoadKubeConfig loads a Kubernetes client configuration from the specified kubeconfig path and context.
func LoadKubeConfig(kubeconfigPath, k8sContext string) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath
	configOverrides := &clientcmd.ConfigOverrides{CurrentContext: k8sContext}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
}

func dialPortForward(ctx context.Context, kubeconfigPath, k8sContext, tokenFile string, traceEnabled bool) (*Client, error) {
	config, err := LoadKubeConfig(kubeconfigPath, k8sContext)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	// We fetch a ClusterTrustBundle via the certificates.k8s.io/v1beta1 API in
	// serverTLSConfig().  Until we migrate to certificates.k8s.io/v1
	// ClusterTrustBundle (which locks us into supporting only k8s 1.37+
	// clusters), client-go will print out a warning every time it initializes.
	config.WarningHandlerWithContext = &rest.NoWarnings{}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	// TODO: Should we special-case a LoadBalancer "api" Service and dial its
	// address directly instead of port-forwarding?
	localPort, stopForward, err := portforward.ServicePortForward(ctx, config, clientset, systemNamespace(), apiServiceName(), 443)
	if err != nil {
		return nil, err
	}
	localEndpoint := fmt.Sprintf("127.0.0.1:%d", localPort)

	creds, err := serverCredentials(ctx, clientset)
	if err != nil {
		stopForward()
		return nil, err
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(creds))
	opts = append(opts, grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	tokenOpt, err := bearerTokenDialOption(ctx, clientset, tokenFile)
	if err != nil {
		stopForward()
		return nil, err
	}
	opts = append(opts, tokenOpt)

	if traceEnabled {
		opts = append(opts, grpc.WithUnaryInterceptor(newTraceInterceptor()))
	}

	conn, err := grpc.NewClient(localEndpoint, opts...)
	if err != nil {
		stopForward()
		return nil, fmt.Errorf("failed to dial gRPC over tunnel: %w", err)
	}

	return &Client{
		ControlClient: ateapipb.NewControlClient(conn),
		conn:          conn,
		cancel:        stopForward,
	}, nil
}

func serverTLSConfig(ctx context.Context, clientset kubernetes.Interface) (*tls.Config, error) {
	pool, err := serverTrustPool(ctx, clientset)
	if err != nil {
		return nil, err
	}
	cfg := serverTLSTemplate()
	cfg.RootCAs = pool
	return cfg, nil
}

// serverTLSTemplate is everything about the connection to ateapi other than the
// trust anchors, which rotate and so are filled in per handshake.
func serverTLSTemplate() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: apiServerName(),
	}
}

// serverTrustPool reads the live servicedns trust anchors from the API server.
func serverTrustPool(ctx context.Context, clientset kubernetes.Interface) (*x509.CertPool, error) {
	ctbs, err := clientset.CertificatesV1beta1().ClusterTrustBundles().List(ctx, metav1.ListOptions{
		LabelSelector: liveBundleSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterTrustBundles: %w", err)
	}

	pool := x509.NewCertPool()
	found := false
	for _, ctb := range ctbs.Items {
		if ctb.Spec.SignerName != serviceDNSSignerName {
			continue
		}
		if !pool.AppendCertsFromPEM([]byte(ctb.Spec.TrustBundle)) {
			return nil, fmt.Errorf("ClusterTrustBundle %q contains no valid certificates", ctb.ObjectMeta.Name)
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("no live ClusterTrustBundle found for signer %q", serviceDNSSignerName)
	}

	return pool, nil
}

const (
	// trustPoolTTL bounds how long after a servicedns CA rotation this client
	// can still be dialing with the pre-rotation anchor set.
	//
	// It is deliberately short, so that the correctness argument does not
	// depend on the overlap window the signer happens to maintain between
	// publishing a new CA and serving leaves from it. The cost is one LIST per
	// minute from a long-lived process and, because the TTL is only consulted
	// on a handshake, exactly zero extra calls from a kubectl-ate invocation
	// that dials once and exits.
	trustPoolTTL = time.Minute

	// trustPoolListTimeout bounds a refresh LIST. The reload runs inside a TLS
	// handshake, and the loader seam carries no context, so without this an
	// unresponsive API server would hang the handshake rather than fail it.
	trustPoolListTimeout = 10 * time.Second
)

// trustPoolCache serves the live servicedns trust anchors, re-reading them from
// the API server at most once per ttl.
//
// A LIST on every handshake is not acceptable and a pool fixed at construction
// is the defect; the TTL is the middle. Refresh errors are NOT papered over
// with the last good pool: serving a known-stale anchor set indefinitely is the
// frozen-pool defect on a slower clock, so a failed refresh fails the handshake
// and gRPC reconnects.
type trustPoolCache struct {
	load func(context.Context) (*x509.CertPool, error)
	ttl  time.Duration
	now  func() time.Time

	// mu is held across the reload so that concurrent handshakes past the TTL
	// produce one LIST between them, not one each.
	mu       sync.Mutex
	pool     *x509.CertPool
	loadedAt time.Time
}

func newTrustPoolCache(clientset kubernetes.Interface) *trustPoolCache {
	return &trustPoolCache{
		load: func(ctx context.Context) (*x509.CertPool, error) {
			return serverTrustPool(ctx, clientset)
		},
		ttl: trustPoolTTL,
		now: time.Now,
	}
}

// roots returns the cached anchors, refreshing them if they have aged out.
func (c *trustPoolCache) roots() (*x509.CertPool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pool != nil && c.now().Sub(c.loadedAt) < c.ttl {
		return c.pool, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), trustPoolListTimeout)
	defer cancel()
	pool, err := c.load(ctx)
	if err != nil {
		return nil, fmt.Errorf("refreshing the ateapi trust anchors: %w", err)
	}
	c.pool, c.loadedAt = pool, c.now()
	return pool, nil
}

// serverCredentials returns transport credentials for ateapi whose trust
// anchors follow a rotation of the servicedns CA (#9518).
//
// The anchors come from the API server rather than from a projected file, so
// the loader is a TTL-cached LIST rather than credbundle.PoolLoader's stat
// check; the per-handshake reload mechanism is the one #9517 established.
//
// The pool is read once here so that an unreachable API server or a missing
// bundle fails at construction, as it did before, rather than at the first RPC.
func serverCredentials(ctx context.Context, clientset kubernetes.Interface) (credentials.TransportCredentials, error) {
	cache := newTrustPoolCache(clientset)
	if err := cache.warm(ctx); err != nil {
		return nil, err
	}
	return cache.credentials(), nil
}

// warm primes the cache from ctx, so that an unreachable API server or a
// missing bundle is reported by the caller that built the client rather than
// by the first handshake.
func (c *trustPoolCache) warm(ctx context.Context) error {
	pool, err := c.load(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pool, c.loadedAt = pool, c.now()
	return nil
}

// credentials returns dial credentials that take their trust anchors from this
// cache at every handshake.
func (c *trustPoolCache) credentials() credentials.TransportCredentials {
	return rotatingtls.NewCredentials(serverTLSTemplate(), c.roots)
}

// bearerTokenDialOption attaches the configured token, or mints an ate-client
// ServiceAccount token when tokenFile is empty.
func bearerTokenDialOption(ctx context.Context, clientset *kubernetes.Clientset, tokenFile string) (grpc.DialOption, error) {
	if tokenFile == "-" {
		creds, err := readBearerToken(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read bearer token from stdin: %w", err)
		}
		return grpc.WithPerRPCCredentials(creds), nil
	}
	if tokenFile != "" {
		return grpc.WithPerRPCCredentials(fileBearerTokenCreds(tokenFile)), nil
	}
	expirationSeconds := int64(3600)
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         []string{apiServerName()},
			ExpirationSeconds: &expirationSeconds,
		},
	}
	token, err := clientset.CoreV1().ServiceAccounts(systemNamespace()).CreateToken(ctx, clientServiceAccount(), tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to request ateapi bearer token: %w", err)
	}
	if token.Status.Token == "" {
		return nil, fmt.Errorf("failed to request ateapi bearer token: token response was empty")
	}
	return grpc.WithPerRPCCredentials(bearerTokenCreds(token.Status.Token)), nil
}

func readBearerToken(r io.Reader) (bearerTokenCreds, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("bearer token is empty")
	}
	return bearerTokenCreds(token), nil
}

type bearerTokenCreds string

func (c bearerTokenCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	if c == "" {
		return nil, fmt.Errorf("bearer token is empty")
	}
	return map[string]string{"authorization": "Bearer " + string(c)}, nil
}

func (c bearerTokenCreds) RequireTransportSecurity() bool { return true }

type fileBearerTokenCreds string

func (c fileBearerTokenCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	b, err := os.ReadFile(string(c))
	if err != nil {
		return nil, fmt.Errorf("read bearer token file %q: %w", c, err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return nil, fmt.Errorf("bearer token file %q is empty", c)
	}
	return map[string]string{"authorization": "Bearer " + token}, nil
}

func (c fileBearerTokenCreds) RequireTransportSecurity() bool { return true }

// initTracing returns (nil, nil) when tracing is disabled: the OTel globals
// stay noop so no traceparent is injected, the server roots the trace, and the
// server side sampling ratio applies. A NeverSample provider here would
// instead pin every ParentBased sampler downstream to not sampled.
func initTracing(ctx context.Context, enabled bool) (*sdktrace.TracerProvider, error) {
	if !enabled {
		return nil, nil
	}

	res, err := resource.New(ctx,
		resource.WithSchemaURL(semconv.SchemaURL),
		resource.WithAttributes(
			semconv.UserAgentOriginal("kubectl-ate"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp, nil
}

func newTraceInterceptor() grpc.UnaryClientInterceptor {
	var once sync.Once
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		tracer := otel.Tracer("kubectl-ate")
		ctx, span := tracer.Start(ctx, method)
		defer span.End()

		once.Do(func() {
			fmt.Fprintf(os.Stderr, "Tracing enabled. Trace ID: %s\n", span.SpanContext().TraceID().String())
		})

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// NewMetricsClientset creates a new Kubernetes Metrics Clientset using the provided kubeconfig path and context.
func NewMetricsClientset(kubeconfigPath, k8sContext string) (*metricsv1beta1.Clientset, error) {
	config, err := LoadKubeConfig(kubeconfigPath, k8sContext)
	if err != nil {
		return nil, err
	}
	return metricsv1beta1.NewForConfig(config)
}
