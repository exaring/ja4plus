package ja4plus

import (
	"crypto/tls"
	"testing"
	"net/http"
	"strings"
)

func TestJA4(t *testing.T) {
	// Create a mock instance of tls.ClientHelloInfo
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}
}

	// Call the JA4 function
	fingerprint := JA4(hello)

	// Expected fingerprint string
	expected := "772,4865-4866,h2-http/1.1,h2,http/1.1"

	// Verify the returned fingerprint string
	if fingerprint != expected {
		t.Errorf("Expected %s, but got %s", expected, fingerprint)
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
