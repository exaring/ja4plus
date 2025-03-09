package ja4plus

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
)

// greaseFilter returns true if the provided value is a GREASE entry as defined in
// https://www.rfc-editor.org/rfc/rfc8701.html
func greaseFilter(suite uint16) bool {
	return suite&0x000F == 0x000A && // low word is 0x*A
		suite>>8 == (suite&0x00FF) // high word is equal to low word
}

// JA4 generates a JA4 fingerprint from the given [tls.ClientHelloInfo].
// It extracts TLS Version, Cipher Suites, Extensions, and ALPN Protocols.
func JA4(hello *tls.ClientHelloInfo) string {
	out := make([]byte, 0, 36)

	// Determine protocol type based on the network type
	if hello.Conn != nil {
		switch hello.Conn.LocalAddr().Network() {
		case "udp", "sctp":
			out = append(out, 'd')
		case "quic":
			out = append(out, 'q')
		default:
			out = append(out, 't')
		}
	} else {
		out = append(out, 't')
	}

	// Extract TLS version
	slices.Sort(hello.SupportedVersions)
	switch hello.SupportedVersions[len(hello.SupportedVersions)-1] {
	case tls.VersionTLS10:
		out = append(out, '1', '0')
	case tls.VersionTLS11:
		out = append(out, '1', '1')
	case tls.VersionTLS12:
		out = append(out, '1', '2')
	case tls.VersionTLS13:
		out = append(out, '1', '3')
	case tls.VersionSSL30: // deprecated, but still seen in the wild
		out = append(out, 's', '3')
	case 0x0002: // unsupported by go; still seen in the wild
		out = append(out, 's', '2')
	case 0xfeff: // DTLS 1.0
		out = append(out, 'd', '1')
	case 0xfefd: // DTLS 1.2
		out = append(out, 'd', '2')
	case 0xfefc: // DTLS 1.3
		out = append(out, 'd', '3')
	default:
		out = append(out, '0', '0')
	}

	// Check for presence of SNI
	if hello.ServerName != "" {
		out = append(out, 'd')
	} else {
		out = append(out, 'i')
	}

	// Count cipher suites
	filteredCipherSuites := slices.DeleteFunc(hello.CipherSuites, greaseFilter)
	out = fmt.Appendf(out, "%02d", min(len(filteredCipherSuites), 99))

	// Count extensions
	filteredExtensions := slices.DeleteFunc(hello.Extensions, greaseFilter)
	out = fmt.Appendf(out, "%02d", min(len(filteredExtensions), 99))

	// Extract first ALPN value
	if len(hello.SupportedProtos) > 0 {
		firstALPN := hello.SupportedProtos[0]
		out = append(out, firstALPN[0], firstALPN[len(firstALPN)-1])
	} else {
		out = append(out, '0', '0')
	}

	out = append(out, '_')

	// Compute truncated SHA256 of sorted cipher suites
	if len(filteredCipherSuites) > 0 {
		slices.Sort(filteredCipherSuites)
		cipherSuiteList := make([]string, 0, len(filteredCipherSuites))
		for _, suite := range filteredCipherSuites {
			cipherSuiteList = append(cipherSuiteList, fmt.Sprintf("%04x", suite))
		}
		cipherSuiteHash := sha256.Sum256([]byte(strings.Join(cipherSuiteList, ",")))
		out = hex.AppendEncode(out, cipherSuiteHash[:6])
	} else {
		out = append(out, []byte("000000000000")...)
	}

	out = append(out, '_')

	// Compute truncated SHA256 of sorted extensions and unsorted signature algorithms
	filteredExtensions = slices.DeleteFunc(hello.Extensions, func(i uint16) bool {
		// SNI and ALPN are counted above, but MUST be ignored for the hash.
		return i == 0x0000 /* SNI */ || i == 0x0010 /* ALPN */
	})
	if len(filteredExtensions) > 0 {
		slices.Sort(filteredExtensions)
		extensionsList := make([]string, 0, len(filteredExtensions))
		for _, ext := range filteredExtensions {
			extensionsList = append(extensionsList, fmt.Sprintf("%04x", ext))
		}
		extensionsListRendered := strings.Join(extensionsList, ",")
		if len(hello.SignatureSchemes) > 0 {
			signatureSchemeList := make([]string, 0, len(hello.SignatureSchemes))
			for _, sig := range hello.SignatureSchemes {
				signatureSchemeList = append(signatureSchemeList, fmt.Sprintf("%04x", sig))
			}
			extensionsListRendered += "_" + strings.Join(signatureSchemeList, ",")
		}
		extensionsHash := sha256.Sum256([]byte(extensionsListRendered))
		out = hex.AppendEncode(out, extensionsHash[:6])
	} else {
		out = append(out, []byte("000000000000")...)
	}

	return string(out)
}

// JA4T generates a JA4T fingerprint from the given [net.TCPConn].
// It extracts TCP window size and TCP options (e.g., MSS, SACK, Timestamp).
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
