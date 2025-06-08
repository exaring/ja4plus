package ja4plus

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// JA4Middleware is a helper to plug the JA4 fingerprinting into your HTTP server.
// It only exists because there is no direct way to pass information from the TLS handshake to the HTTP handler.
type JA4Middleware struct {
	connectionFingerprints sync.Map
	tlsConfig              *tls.Config
}

type ja4FingerprintCtxKey struct{}

// NewJ4AMiddleware returns a new initialized middleware wrapper
func NewJ4AMiddleware() *JA4Middleware {
	return &JA4Middleware{
		connectionFingerprints: sync.Map{},
	}
}

// NewHandlerWrapper takes a middleware, a tls config, and a http.handler and returns a modified handler that injects
// fingerprints into the context of the a connection so they can be consumed later.
func (m *JA4Middleware) NewHandlerWrapper(middleware *JA4Middleware, tlsConfig *tls.Config, next http.Handler) http.Handler {

	tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		// Protects against panics when generating the JA4
		if chi != nil {
			m.connectionFingerprints.Store(chi.Conn.RemoteAddr().String(), JA4(chi))
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to extract client tls hello")
	}
	middleware.tlsConfig = tlsConfig

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if cacheEntry, _ := m.connectionFingerprints.Load(r.RemoteAddr); cacheEntry != nil {
			ctx = context.WithValue(ctx, ja4FingerprintCtxKey{}, cacheEntry.(string))
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// NewListenerWrapper takes a middleware, a tls config and a address and returns a fully wrapped net.Listener.
// You will still need to manually clear fingerprints from memory as connections close with ListenerCallback.
func NewListenerWrapper(middleware *JA4Middleware, tlsConfig *tls.Config, addr string) (net.Listener, error) {

	tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		// Protects against panics when generating the JA4
		if chi != nil {
			middleware.connectionFingerprints.Store(chi.Conn.RemoteAddr().String(), JA4(chi))
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to extract client tls hello")
	}

	middleware.tlsConfig = tlsConfig

	listen, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err

	}

	return listen, nil
}

// HTTPCallback is a callback that should be set as the [http.Server]'s ConnState to clean up the fingerprint cache.
func (m *JA4Middleware) HTTPCallback(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed, http.StateHijacked:
		m.connectionFingerprints.Delete(conn.RemoteAddr().String())
	}
}

// ListenerCallback is a manually called deletion method for clearing fingerprint state after a connection is closed
func (m *JA4Middleware) ListenerCallback(conn net.Conn) {
	m.connectionFingerprints.Delete(conn.RemoteAddr().String())
}

// Returns the modified TLS config
func (m *JA4Middleware) ReturnTLSConfig() *tls.Config {
	return m.tlsConfig
}

// JA4FromContext extracts the JA4 fingerprint from the provided [http.Request.Context].
func JA4FromContext(ctx context.Context) (string, bool) {
	fingerprint, ok := ctx.Value(ja4FingerprintCtxKey{}).(string)
	return fingerprint, ok
}

// JA4FromContext extracts the JA4 fingerprint from the middleware using the a connection.
func (m *JA4Middleware) JA4FromConn(conn net.Conn) (string, bool) {
	fingerprint, ok := m.connectionFingerprints.Load(conn.RemoteAddr().String())
	if !ok {
		return "", ok
	}

	f, ok := fingerprint.(string)
	return f, ok
}
