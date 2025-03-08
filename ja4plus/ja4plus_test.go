package ja4plus

import (
	"crypto/tls"
	"net"
	"net/http"
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

func BenchmarkJA4(b *testing.B) {
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}

	for i := 0; i < b.N; i++ {
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

	for i := 0; i < b.N; i++ {
		JA4H(req)
	}
}

func BenchmarkJA4T(b *testing.B) {
	mockConn := &net.TCPConn{} // Placeholder, as we can't set TCP options directly

	for i := 0; i < b.N; i++ {
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
