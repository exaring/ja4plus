package ja4plus_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/exaring/ja4plus"
)

func ExampleJA4() {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	srv.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Println(ja4plus.JA4(hello))
			return nil, nil
		},
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	client := srv.Client()

	resp, err := client.Get(srv.URL)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	// Output: t13i1310h2_f57a46bbacb6_e7c285222651
}
