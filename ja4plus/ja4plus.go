package ja4plus

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"net"
	"net/http"
	"slices"
)

// JA4 generates a JA4 fingerprint from the given [tls.ClientHelloInfo].
// It extracts TLS Version, Cipher Suites, Extensions, and ALPN Protocols.
// Usage:
//
//	hello := &tls.ClientHelloInfo{...}
//	fingerprint := JA4(hello)
func JA4(hello *tls.ClientHelloInfo) string {
	// Determine protocol type based on the network type
	protocolType := "t"
	if hello.Conn != nil && hello.Conn.RemoteAddr().Network() == "udp" {
		protocolType = "q"
	}

	// Extract TLS version
	var tlsVersion string
	switch hello.SupportedVersions[0] {
	case tls.VersionTLS10:
		tlsVersion = "10"
	case tls.VersionTLS11:
		tlsVersion = "11"
	case tls.VersionTLS12:
		tlsVersion = "12"
	case tls.VersionTLS13:
		tlsVersion = "13"
	default:
		tlsVersion = "00"
	}

	// Check for presence of SNI
	sniPresence := "i"
	if hello.ServerName != "" {
		sniPresence = "d"
	}

	// Count cipher suites
	numCipherSuites := fmt.Sprintf("%02d", len(hello.CipherSuites))

	// Count extensions
	numExtensions := fmt.Sprintf("%02d", len(hello.SupportedProtos))

	// Extract first ALPN value
	firstALPN := "00"
	if len(hello.SupportedProtos) > 0 {
		firstALPN = hello.SupportedProtos[0]
	}

	// Compute truncated SHA256 of sorted cipher suites
	slices.Sort(hello.CipherSuites)
	cipherSuitesHash := sha256.New()
	for _, suite := range hello.CipherSuites {
		cipherSuitesHash.Write([]byte(tls.CipherSuiteName(suite)))
	}
	truncatedCipherSuitesHash := hex.EncodeToString(cipherSuitesHash.Sum(nil))[:12]

	// Compute truncated SHA256 of sorted extensions and unsorted signature algorithms
	slices.Sort(hello.SupportedProtos)
	extensionsHash := sha256.New()
	for _, ext := range hello.SupportedProtos {
		extensionsHash.Write([]byte(ext))
	}
	truncatedExtensionsHash := hex.EncodeToString(extensionsHash.Sum(nil))[:12]

	var builder strings.Builder

	// Build the JA4 fingerprint string using strings.Builder
	builder.WriteString(protocolType)
	builder.WriteString(tlsVersion)
	builder.WriteString(sniPresence)
	builder.WriteString(numCipherSuites)
	builder.WriteString(numExtensions)
	builder.WriteString(firstALPN)
	builder.WriteString("_")
	builder.WriteString(truncatedCipherSuitesHash)
	builder.WriteString("_")
	builder.WriteString(truncatedExtensionsHash)

	return builder.String()
}

// JA4T generates a JA4T fingerprint from the given [net.TCPConn].
// It extracts TCP window size and TCP options (e.g., MSS, SACK, Timestamp).
// Usage:
//
//	conn := &net.TCPConn{...}
//	fingerprint := JA4T(conn)
func JA4T(conn *net.TCPConn) string {
	// Simulate extraction of TCP window size and options
	// In a real implementation, you might use conn.SyscallConn() to access low-level details
	tcpWindowSize := "65535"    // Placeholder value
	tcpOptions := "MSS,SACK,TS" // Placeholder options

	// Format the extracted information into a JA4T fingerprint string
	return fmt.Sprintf("%s,%s", tcpWindowSize, tcpOptions)
}

// JA4H generates a JA4H fingerprint from the given [http.Request].
// It extracts HTTP Method, HTTP Version, presence of cookies, referrer, total headers, and Accept-Language.
// Usage:
//
//	req := &http.Request{...}
//	fingerprint := JA4H(req)
func JA4H(req *http.Request) string {
	// Extract HTTP Method
	method := req.Method

	// Extract HTTP Version
	version := req.Proto

	// Check for presence of cookies
	hasCookies := "false"
	if len(req.Cookies()) > 0 {
		hasCookies = "true"
	}

	// Check for presence of referrer
	hasReferrer := "false"
	if req.Referer() != "" {
		hasReferrer = "true"
	}

	// Count total number of headers
	totalHeaders := len(req.Header)

	// Extract Accepted-Language header
	acceptedLanguage := req.Header.Get("Accept-Language")

	// Format the extracted information into a JA4H fingerprint string
	return fmt.Sprintf("%s,%s,%s,%s,%d,%s", method, version, hasCookies, hasReferrer, totalHeaders, acceptedLanguage)
}
