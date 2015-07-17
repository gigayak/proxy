/* proxy is an HTTPS proxy for internal webservers.

Example usage:
  $ proxy \
    --certificate=/opt/ssl/ssl.crt \
    --key=/opt/ssl/ssl.key \
    --domain=jgilik.com
*/
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

var (
	cert = flag.String("certificate", "", "Location of HTTPS .crt file.")
	key = flag.String("key", "", "Location of HTTPS .key private key file.")
	domain = flag.String("domain", "", "Which domain to proxy subdomains for.")
	addr = flag.String("address", ":443", "Address to listen on.")
)

type proxyHandler struct {
	domain string
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Security validation - prevents us from being an open proxy if this
	// server is accidentally left exposed to the world.
	if !strings.HasSuffix(r.URL.Host, "." + h.domain) && r.URL.Host != h.domain {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// RequestURI cannot be set in requests, panics ensue otherwise.
	r.RequestURI = ""

	// Due to how Chrome handles HTTPS proxies, we will need to force HTTPS
	// instead of expecting correct client behavior.
	r.URL.Scheme = "https"
	log.Printf("Proxying request for %q", r.URL.String())

	// The following is straightforward proxying magic.
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		log.Printf("Error proxying request for %q: %v", r.URL.String(), err)
		http.Error(w, fmt.Sprintf("error making proxied request: %v", err),
			http.StatusInternalServerError)
		return
	}
	log.Printf("Got response for %q", r.URL.String())
	for k, values := range resp.Header {
		w.Header()[k] = values
	}
	w.WriteHeader(resp.StatusCode)
	for {
		buf := make([]byte, 1024)
		n, err := resp.Body.Read(buf)
		eof := err == io.EOF
		if err != nil && !eof {
			http.Error(w, fmt.Sprintf("error reading body: %v", err),
				http.StatusInternalServerError)
		}
		written, err := w.Write(buf[:n])
		if err != nil {
			log.Printf("Failed to write response: %v", err)
			return
		}
		log.Printf("Wrote %d response bytes", written)
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
	log.Printf("Listening on %s", *addr)
	err := http.ListenAndServeTLS(*addr, *cert, *key, nil)
	log.Fatal(err)
}

