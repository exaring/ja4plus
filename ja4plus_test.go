package ja4plus

import (
	"crypto/tls"
	"encoding/hex"
	"math"
	"net"
	"net/http"
	"testing"
)

func TestJA4(t *testing.T) {
	tests := []struct {
		name     string
		hello    *tls.ClientHelloInfo
		expected string
	}{
		{
			name: "Basic ClientHelloInfo",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{tls.VersionTLS13},
				SupportedProtos:   []string{"http/1.1"},
			},
			expected: "t13i0000h1_000000000000_000000000000",
		},
		{
			name: "ClientHelloInfo with multiple versions and protocols",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS13},
				SupportedProtos:   []string{"h2", "http/1.1"},
			},
			expected: "t13i0000h2_000000000000_000000000000",
		},
		{
			name: "ClientHelloInfo with SNI",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{tls.VersionTLS13},
				SupportedProtos:   []string{"http/1.1"},
				ServerName:        "example.com",
			},
			expected: "t13d0000h1_000000000000_000000000000",
		},
		{
			name: "ClientHelloInfo with cipher suites",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{tls.VersionTLS13},
				CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
				SupportedProtos:   []string{"http/1.1"},
			},
			expected: "t13i0200h1_62ed6f6ca7ad_000000000000",
		},
		{
			name: "ClientHelloInfo with only ignored extensions",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{tls.VersionTLS13},
				SupportedProtos:   []string{"http/1.1"},
				Extensions:        []uint16{0x0000 /* SNI */, 0x0010 /* ALPN */, 0x1A1A /* GREASE */},
			},
			expected: "t13i0002h1_000000000000_000000000000",
		},
		{
			name: "ClientHelloInfo with extensions and signature schemes",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{tls.VersionTLS13},
				SupportedProtos:   []string{"http/1.1"},
				Extensions:        []uint16{0x0000 /* SNI */, 0x1A1A /* GREASE */, 0x0042 /* "early data" */},
				SignatureSchemes:  []tls.SignatureScheme{tls.PKCS1WithSHA256, tls.ECDSAWithP256AndSHA256},
				SupportedCurves:   []tls.CurveID{tls.CurveP256},
			},
			expected: "t13i0002h1_000000000000_820ab3bb01bb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprint := JA4(tt.hello)
			if fingerprint != tt.expected {
				t.Errorf("Expected %s, but got %s", tt.expected, fingerprint)
			}
		})
	}
}

func BenchmarkJA4(b *testing.B) {
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		SupportedProtos:   []string{"h2", "http/1.1"},
		Extensions:        []uint16{0x0000 /* SNI */, 0x1A1A /* GREASE */, 0x0042 /* "early data" */},
	}

	for b.Loop() {
		JA4(hello)
	}
}

func BenchmarkJA4H(b *testing.B) {
	req := &http.Request{
		Method: "GET",
		Proto:  "HTTP/1.1",
		Header: http.Header{
			"Accept-Language": []string{"en-US"},
		},
	}

	for b.Loop() {
		JA4H(req)
	}
}

func BenchmarkJA4T(b *testing.B) {
	mockConn := &net.TCPConn{} // Placeholder, as we can't set TCP options directly

	for b.Loop() {
		JA4T(mockConn)
	}
}

func TestJA4T(t *testing.T) {
	// Simulate a TCP connection using a mock or interface
	// Since we can't directly create a net.TCPConn with specific parameters, we'll simulate the expected output
	// This is a placeholder for a more complex mock setup if needed
	mockConn := &net.TCPConn{} // Placeholder, as we can't set TCP options directly

	// Call the JA4T function
	fingerprint := JA4T(mockConn)

	// Expected fingerprint string based on the simulated data
	expected := "65535,MSS,SACK,TS"

	// Verify the returned fingerprint string
	if fingerprint != expected {
		t.Errorf("Expected %s, but got %s", expected, fingerprint)
	}
}

func TestJA4H(t *testing.T) {
	tests := []struct {
		name     string
		request  *http.Request
		expected string
	}{
		{
			name: "Basic request without cookies or referrer",
			request: &http.Request{
				Method: "GET",
				Proto:  "HTTP/1.1",
				Header: http.Header{
					"Accept-Language": []string{"en-US"},
				},
			},
			expected: "GET,HTTP/1.1,false,false,1,en-US",
		},
		{
			name: "Request with cookies and referrer",
			request: &http.Request{
				Method: "POST",
				Proto:  "HTTP/2.0",
				Header: http.Header{
					"Cookie":          []string{"sessionId=abc123"},
					"Referer":         []string{"http://example.com"},
					"Accept-Language": []string{"fr-FR"},
				},
			},
			expected: "POST,HTTP/2.0,true,true,3,fr-FR",
		},
		{
			name: "Request with multiple headers and no Accept-Language",
			request: &http.Request{
				Method: "PUT",
				Proto:  "HTTP/1.0",
				Header: http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
					"Referer":    []string{"http://example.org"},
				},
			},
			expected: "PUT,HTTP/1.0,false,true,2,",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprint := JA4H(tt.request)
			if fingerprint != tt.expected {
				t.Errorf("Expected %s, but got %s", tt.expected, fingerprint)
			}
		})
	}
}
func TestGreaseFilter(t *testing.T) {
	greaseValues := map[uint16]bool{
		0x0A0A: true,
		0x1A1A: true,
		0x2A2A: true,
		0x3A3A: true,
		0x4A4A: true,
		0x5A5A: true,
		0x6A6A: true,
		0x7A7A: true,
		0x8A8A: true,
		0x9A9A: true,
		0xAAAA: true,
		0xBABA: true,
		0xCACA: true,
		0xDADA: true,
		0xEAEA: true,
		0xFAFA: true,
	}

	for i := range math.MaxUint16 {
		// test the fast method with the slow known-value check
		value := uint16(i)
		expected := greaseValues[value]
		result := greaseFilter(value)
		if result != expected {
			t.Errorf("For value 0x%04X, expected %v, but got %v", value, expected, result)
		}
	}
}
func TestExtensionHash(t *testing.T) {
	tests := []struct {
		name             string
		extensions       []uint16
		signatureSchemes []tls.SignatureScheme
		expected         string
	}{
		{
			name:             "No extensions or signature schemes",
			extensions:       []uint16{},
			signatureSchemes: []tls.SignatureScheme{},
			expected:         "000000000000",
		},
		{
			name:             "Only GREASE extensions",
			extensions:       []uint16{0x0A0A, 0x1A1A},
			signatureSchemes: []tls.SignatureScheme{},
			expected:         "000000000000",
		},
		{
			name:             "Extensions with SNI and ALPN",
			extensions:       []uint16{0x0000, 0x0010},
			signatureSchemes: []tls.SignatureScheme{},
			expected:         "000000000000",
		},
		{
			name:             "Valid extensions without signature schemes",
			extensions:       []uint16{0x0001, 0x0002},
			signatureSchemes: []tls.SignatureScheme{},
			expected:         "5b7701cdea2c",
		},
		{
			name:             "Valid unsorted extensions without signature schemes",
			extensions:       []uint16{0x0002, 0x0001},
			signatureSchemes: []tls.SignatureScheme{},
			expected:         "5b7701cdea2c",
		},
		{
			name:             "Valid extensions with signature schemes",
			extensions:       []uint16{0x0001, 0x0002},
			signatureSchemes: []tls.SignatureScheme{tls.PKCS1WithSHA256, tls.ECDSAWithP256AndSHA256},
			expected:         "7ca161ef5d14",
		},
		{
			name:             "Only signature schemes",
			extensions:       []uint16{},
			signatureSchemes: []tls.SignatureScheme{tls.PKCS1WithSHA256, tls.ECDSAWithP256AndSHA256},
			expected:         "000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := hex.EncodeToString(extensionHash(tt.extensions, tt.signatureSchemes))
			if hash != tt.expected {
				t.Errorf("Expected %s, but got %s", tt.expected, hash)
			}
		})
	}
}
