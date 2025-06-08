# JA4Plus
<p align="center">
  <img src="./logo.png" width=300/>
</p>

<p align="center">
  <img src="https://github.com/exaring/ja4plus/actions/workflows/ci.yml/badge.svg">
  <img src="https://pkg.go.dev/badge/github.com/exaring/ja4plus.svg">
  <img src="https://goreportcard.com/badge/github.com/exaring/ja4plus">
</p>


JA4Plus is a pure Go library for generating [JA4+ fingerprints](https://github.com/FoxIO-LLC/ja4) on TLS port listeners and https servers.

## Overview

JA4Plus aims to provide a simple and reliable way to identify clients based on their TLS characteristics.  This is useful for various security applications, including:

*   Bot detection
*   Client profiling
*   Security monitoring

Currently, JA4Plus offers a single fingerprinting function based on [TLS ClientHello](https://pkg.go.dev/crypto/tls#ClientHelloInfo) information. Contributions are welcome for implementing other fingerprints in the JA4 family!

### Omission of JA4H

The JA4H hash, which relies on properties of the HTTP request, cannot currently be easily implemented in Go. This is because Go's standard library does not provide a direct mechanism for observing HTTP headers in the order they are sent by the client.  See [this issue](https://go.dev/issue/24375) for more details.

## Usage

The core challenge when integrating JA4 fingerprinting is that TLS handshake information is typically not directly accessible within standard HTTP handlers. The `ja4plus` library addresses this limitation with a middleware approach.

### The Middleware Pattern

The `JA4Middleware` struct and its associated methods are designed to bridge the gap between the TLS handshake and the HTTP request context.

1.  **TLS Configuration:**  The middleware modifies the TLS configuration to intercept the `ClientHello` information.
2.  **Fingerprint Storage:** When a `ClientHello` is received, the corresponding JA4 fingerprint is stored in a `sync.Map` associated with the client's remote address.
3.  **Context Injection:** The middleware wraps the HTTP handler and injects the JA4 fingerprint into the `http.Request.Context` before the handler is called.

### Important Considerations

*   **Certificate Management:** Ensure you have valid TLS certificates configured for your server.
*   **Connection Cache:** The `JA4Middleware` stores fingerprints in a `sync.Map` indexed by client's remote address. The `HTTPCallback` function should be set on your `http.Server`'s `ConnState` to clean up this cache automatically when connections are closed. The net listener though *must sadly be manually cleaned* up using the `ListenerCallback` to avoid memory leaks in the same way as the http server.

### HTTP Server Example

```go
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/exaring/ja4plus"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the hash back to the client
		hash, ok := ja4plus.JA4FromContext(r.Context())
		if !ok {
			io.WriteString(w, "missing hash")
			return
		}
		io.WriteString(w, hash)
	})

	// Load TLS certificates (replace with your actual certificates)
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key") // Example.  Consider using a proper configuration.
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create a new JA4Middleware instance
	middleware := ja4plus.NewJ4AMiddleware()

	// Create an HTTP server
	srv := http.Server{
		Addr:      ":9000",
		Handler:   middleware.NewHandlerWrapper(middleware, tlsConfig, handler), // Generate a new http wrapper
		ConnState: middleware.HTTPCallback, // Clean up connection cache
		TLSConfig: middleware.ReturnTLSConfig(), // Use the wrapped tls config
	}

	// Start the server
	log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
}
```

### TLS Listener Example

This demonstrates how to use JA4Plus with a raw TLS listener.

```go
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/exaring/ja4plus"
)

func main() {
	// Load TLS certificates (replace with your actual certificates)
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	middleware := ja4plus.NewJ4AMiddleware()

	listener, err := ja4plus.NewListenerWrapper(middleware, tlsConfig, ":9001")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go handleConnection(conn, middleware)
	}
}

func handleConnection(conn net.Conn, middleware *ja4plus.JA4Middleware) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Println("Connection is not TLS")
		return
	}

	tlsConn.Handshake()
	hash, ok := middleware.JA4FromConn(tlsConn)
	if ok {
		// Manually clean fingerprint from the middleware
		middleware.ListenerCallback(tlsConn)
		log.Println("Got fingerprint:", hash)
		return
	}

	log.Println("failed to retrieve hash from listener")
}

```

