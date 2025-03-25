package ja4plus_test

import (
	"crypto/tls"
	"io"
	"net/http"

	"github.com/exaring/ja4plus"
)

func ExampleJA4Middleware() {
	exampleHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, ja4plus.JA4FromContext(r.Context()))
	})

	ja4middleware := ja4plus.JA4Middleware{}
	
	/* srv */ _ = http.Server{
		Addr:    ":8080",
		Handler: ja4middleware.Wrap(exampleHandler),
		TLSConfig: &tls.Config{
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				ja4middleware.StoreFingerprintFromClientHello(chi)
				return nil, nil
			},
		},
		ConnState: ja4middleware.ConnStateCallback,
	}

	// srv.ListenAndServeTLS(...)
}
