/* proxy is an HTTPS proxy for internal webservers.

Example usage:
  $ proxy \
    --certificate=/opt/ssl/ssl.crt \
    --key=/opt/ssl/ssl.key \
    --domain=jgilik.com
*/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var (
	cert = flag.String("certificate", "", "Location of HTTPS .crt file.")
	key = flag.String("key", "", "Location of HTTPS .key private key file.")
	domain = flag.String("domain", "", "Which domain to proxy subdomains for.")
	addr = flag.String("address", ":443", "Address to listen on.")
	cacert = flag.String("certificate_authority",
		"/etc/pki/ca-trust/source/anchors/machine-audio-research-ca.pem",
		"PEM file for certificate authority responsible for client certs.")
)

type proxyHandler struct {
	domain string
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Validate the client certificate details.
	var username string
	for _, chain := range r.TLS.VerifiedChains {
		for _, cert := range chain {
			if !cert.IsCA {
				if username != "" {
					log.Printf("Found multiple certs (one is %q)", username)
					http.Error(w, "", http.StatusForbidden)
					return
				}
				username = cert.Subject.CommonName
			}
		}
	}
	if username == "" {
		log.Printf("Invalid username: %q", username)
		http.Error(w, "", http.StatusForbidden)
		return
	}

	// Security validation - prevents us from being an open proxy if this
	// server is accidentally left exposed to the world.
	if !strings.HasSuffix(r.URL.Host, "." + h.domain) && r.URL.Host != h.domain {
		log.Printf("Invalid host: %q", r.URL.Host)
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// RequestURI cannot be set in requests, panics ensue otherwise.
	r.RequestURI = ""

	// Due to how Chrome handles HTTPS proxies, we will need to force HTTPS
	// instead of expecting correct client behavior.
	r.URL.Scheme = "https"
	log.Printf("Proxying request for %q to %q", username, r.URL.String())

	// The following is straightforward proxying magic.
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		log.Printf("Error proxying request for %q: %v", r.URL.String(), err)
		http.Error(w, fmt.Sprintf("error making proxied request: %v", err),
			http.StatusInternalServerError)
		return
	}
	log.Printf("Got response for %q from %q", username, r.URL.String())
	for k, values := range resp.Header {
		w.Header()[k] = values
	}
	w.WriteHeader(resp.StatusCode)
	for {
		buf := make([]byte, 1024)
		n, err := resp.Body.Read(buf)
		eof := err == io.EOF
		if err != nil && !eof {
			log.Printf("Error reading body: %v", err)
			http.Error(w, fmt.Sprintf("error reading body: %v", err),
				http.StatusInternalServerError)
			return
		}
		_, err = w.Write(buf[:n])
		if err != nil {
			log.Printf("Failed to write response: %v", err)
			return
		}
		if eof || n == 0 {
			break
		}
	}
	if err := resp.Body.Close(); err != nil {
		log.Printf("Error closing connection: %v", err)
	}
}

func main() {
	flag.Parse()

	http.Handle("/", &proxyHandler{
		domain: *domain,
	})

	pool := x509.NewCertPool()
	b, err := ioutil.ReadFile(*cacert)
	if err != nil {
		log.Fatalf("Failed to read client CA PEM file %q", *cacert)
	}
	ok := pool.AppendCertsFromPEM(b)
	if !ok {
		log.Fatalf("Failed to load client CA cert from %q", *cacert)
	}

	log.Printf("Listening on %s", *addr)
	server := &http.Server{
		Addr: *addr,
		Handler: http.DefaultServeMux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: pool,
		},
	}
	err = server.ListenAndServeTLS(*cert, *key)
	log.Fatalf("Server crashed: %v", err)
}

