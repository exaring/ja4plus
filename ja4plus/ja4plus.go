package ja4plus

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// JA4 generates a JA4 fingerprint from the given tls.ClientHelloInfo.
// It extracts TLS Version, Cipher Suites, Extensions, and ALPN Protocols.
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
