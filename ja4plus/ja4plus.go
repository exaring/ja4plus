package ja4plus

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"net"
)

// JA4 generates a JA4 fingerprint from the given tls.ClientHelloInfo.
// It extracts TLS Version, Cipher Suites, Extensions, and ALPN Protocols.
// Usage:
//   hello := &tls.ClientHelloInfo{...}
//   fingerprint := JA4(hello)
func JA4(hello *tls.ClientHelloInfo) string {
	// Simulate extraction of TLS Version, Cipher Suites, Extensions, and ALPN Protocols
	tlsVersion := fmt.Sprintf("%d", hello.SupportedVersions[0])
	cipherSuites := make([]string, len(hello.CipherSuites))
	for i, suite := range hello.CipherSuites {
		cipherSuites[i] = fmt.Sprintf("%d", suite)
	}
	extensions := make([]string, len(hello.SupportedProtos))
	for i, ext := range hello.SupportedProtos {
		extensions[i] = ext
	}
	alpnProtocols := strings.Join(hello.SupportedProtos, ",")

	// Format the extracted information into a JA4 fingerprint string
	return fmt.Sprintf("%s,%s,%s,%s", tlsVersion, strings.Join(cipherSuites, "-"), strings.Join(extensions, "-"), alpnProtocols)
}

// JA4T generates a JA4T fingerprint from the given net.TCPConn.
// It extracts TCP window size and TCP options (e.g., MSS, SACK, Timestamp).
// Usage:
//   conn := &net.TCPConn{...}
//   fingerprint := JA4T(conn)
func JA4T(conn *net.TCPConn) string {
	// Simulate extraction of TCP window size and options
	// In a real implementation, you might use conn.SyscallConn() to access low-level details
	tcpWindowSize := "65535" // Placeholder value
	tcpOptions := "MSS,SACK,TS" // Placeholder options

	// Format the extracted information into a JA4T fingerprint string
	return fmt.Sprintf("%s,%s", tcpWindowSize, tcpOptions)
}

// JA4H generates a JA4H fingerprint from the given http.Request.
// It extracts HTTP Method, HTTP Version, presence of cookies, referrer, total headers, and Accepted-Language.
// Usage:
//   req := &http.Request{...}
//   fingerprint := JA4H(req)
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
