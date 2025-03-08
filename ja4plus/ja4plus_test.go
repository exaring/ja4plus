package ja4plus

import (
	"crypto/tls"
	"testing"
)

func TestJA4(t *testing.T) {
	// Create a mock instance of tls.ClientHelloInfo
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}

	// Call the JA4 function
	fingerprint := JA4(hello)

	// Expected fingerprint string
	expected := "772,4865-4866,h2-http/1.1,h2,http/1.1"

	// Verify the returned fingerprint string
	if fingerprint != expected {
		t.Errorf("Expected %s, but got %s", expected, fingerprint)
	}
}
}
