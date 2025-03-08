# JA4Plus

JA4Plus is a Go-based project designed to provide advanced fingerprinting features for network and application protocols. This project aims to enhance security and analysis capabilities through its robust architecture and design.

## Overview

JA4Plus offers three main fingerprinting functions:
- **JA4**: Generates a fingerprint from TLS ClientHello information.
- **JA4H**: Generates a fingerprint from HTTP request details.
- **JA4T**: Generates a fingerprint from TCP connection parameters.

## Fingerprinting Functions

### JA4
Generates a fingerprint from TLS ClientHello information, extracting details like TLS version, cipher suites, extensions, and ALPN protocols.

### JA4H
Generates a fingerprint from HTTP request details, including HTTP method, version, cookies, referrer, headers, and accepted languages.

### JA4T
Generates a fingerprint from TCP connection parameters, such as window size and TCP options.

## Usage Examples

```go
package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"github.com/yourusername/ja4plus/ja4plus"
)

func main() {
	// Example for JA4
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}
	tlsFingerprint := ja4plus.JA4(hello)
	println("TLS Fingerprint:", tlsFingerprint)

	// Example for JA4H
	req := &http.Request{
		Method: "GET",
		Proto:  "HTTP/1.1",
		Header: http.Header{
			"Accept-Language": []string{"en-US"},
		},
	}
	httpFingerprint := ja4plus.JA4H(req)
	println("HTTP Fingerprint:", httpFingerprint)

	// Example for JA4T
	conn := &net.TCPConn{} // Placeholder for a real TCP connection
	tcpFingerprint := ja4plus.JA4T(conn)
	println("TCP Fingerprint:", tcpFingerprint)
}
```
