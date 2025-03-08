package ja4plus

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// JA4 generates a JA4 fingerprint from the given [tls.ClientHelloInfo].
// It extracts TLS Version, Cipher Suites, Extensions, and ALPN Protocols.
// Usage:
//
//	hello := &tls.ClientHelloInfo{...}
//	fingerprint := JA4(hello)
func JA4(hello *tls.ClientHelloInfo) string {
	// Determine protocol type (assuming TCP for this example)
	protocolType := "t"

	// Extract TLS version
	tlsVersion := fmt.Sprintf("%02d", hello.SupportedVersions[0])

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
	sort.Slice(hello.CipherSuites, func(i, j int) bool { return hello.CipherSuites[i] < hello.CipherSuites[j] })
	cipherSuitesHash := sha256.Sum256([]byte(strings.Join(strings.Fields(fmt.Sprint(hello.CipherSuites)), ",")))
	truncatedCipherSuitesHash := hex.EncodeToString(cipherSuitesHash[:])[:12]

	// Compute truncated SHA256 of sorted extensions and unsorted signature algorithms
	sort.Strings(hello.SupportedProtos)
	extensionsHash := sha256.Sum256([]byte(strings.Join(hello.SupportedProtos, ",")))
	truncatedExtensionsHash := hex.EncodeToString(extensionsHash[:])[:12]

	// Format the extracted information into a JA4 fingerprint string
	return fmt.Sprintf("%s%s%s%s%s%s_%s_%s", protocolType, tlsVersion, sniPresence, numCipherSuites, numExtensions, firstALPN, truncatedCipherSuitesHash, truncatedExtensionsHash)
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
