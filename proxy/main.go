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
	"log"
	"net/http"
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
	//if (not subdomain of dir) fail
	_ = r
	http.Error(w, "not implemented", http.StatusInternalServerError)
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

