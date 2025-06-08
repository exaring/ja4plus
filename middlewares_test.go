package ja4plus_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/exaring/ja4plus"
)

func TestHTTPMiddleware(t *testing.T) {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash, ok := ja4plus.JA4FromContext(r.Context())
		if !ok {
			io.WriteString(w, "missing hash")
			return
		}
		io.WriteString(w, hash)
	})

	certBytes, keyBytes, err := generateSelfSignedCert()
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile("server.crt", certBytes, 0600)
	if err != nil {
		t.Error(err)
	}
	err = os.WriteFile("server.key", keyBytes, 0600)
	if err != nil {
		t.Error(err)
	}
	defer os.Remove("server.key")
	defer os.Remove("server.crt")

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		t.Error(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certBytes)

	var supported []uint16
	for _, cs := range tls.CipherSuites() {
		supported = append(supported, cs.ID)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert, // Optional - for mutual TLS, use tls.RequireAndVerifyClientCert
		RootCAs:      certPool,
		CipherSuites: supported,
	}

	ja4Middleware := ja4plus.NewJ4AMiddleware()

	srv := http.Server{
		Addr:      ":9000",
		Handler:   ja4Middleware.NewHandlerWrapper(ja4Middleware, config, handler),
		ConnState: ja4Middleware.HTTPCallback,
		TLSConfig: ja4Middleware.ReturnTLSConfig(),
	}
	go srv.ListenAndServeTLS("server.crt", "server.key")

	time.Sleep(time.Second * 30)
}

func TestMiddlewareListener(t *testing.T) {
	certBytes, keyBytes, err := generateSelfSignedCert()
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile("server.crt", certBytes, 0600)
	if err != nil {
		t.Error(err)
	}
	err = os.WriteFile("server.key", keyBytes, 0600)
	if err != nil {
		t.Error(err)
	}
	defer os.Remove("server.key")
	defer os.Remove("server.crt")

	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		t.Error(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certBytes)

	var supported []uint16
	for _, cs := range tls.CipherSuites() {
		supported = append(supported, cs.ID)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert, // Optional - for mutual TLS, use tls.RequireAndVerifyClientCert
		RootCAs:      certPool,
		CipherSuites: supported,
	}

	middleware := ja4plus.NewJ4AMiddleware()

	listener, err := ja4plus.NewListenerWrapper(middleware, config, ":9001")
	if err != nil {
		t.Error(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				t.Error(err)
			}
			defer conn.Close()

			tlsConn, ok := conn.(*tls.Conn)
			if ok {
				tlsConn.Handshake()
				fmt.Println(middleware.JA4FromConn(tlsConn))

				buffer := make([]byte, 1024)
				for {
					_, err := tlsConn.Read(buffer)
					if err != nil {
						middleware.ListenerCallback(tlsConn)
						break
					}
				}

				return
			}

			t.Error("Connection is not TLS")
		}
	}()

	time.Sleep(time.Second * 30)
}

func generateSelfSignedCert() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ja4plus-test-cert"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyPEM})

	return certPEM, keyPEMBlock, nil
}
