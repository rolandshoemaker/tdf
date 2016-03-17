package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/rolandshoemaker/dns"
	"golang.org/x/net/proxy"
)

type tdns struct {
	c         *dns.Client
	dialer    *net.Dialer
	upstreams []string
	proxy     string
}

func randomString() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%X", b)
}

func (t *tdns) newDialer() {
	randStr := randomString()
	p, err := proxy.SOCKS5(
		"tcp",
		t.proxy,
		&proxy.Auth{User: randStr, Password: randStr}, // required to force the creation of a new circuit per query
		t.dialer,
	)
	if err != nil {
		panic(err)
	}
	t.c.Dialer = p
}

func (t *tdns) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Println("query")
	t.newDialer()
	m := new(dns.Msg)
	m.SetReply(r)
	upstream := t.upstreams[0]
	rr, _, err := t.c.Exchange(r, upstream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send query to %s: %s\n", upstream, err)
		m.Response = true
		m.Rcode = dns.RcodeServerFailure
	} else {
		m = rr
	}
	err = w.WriteMsg(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write response: %s\n", err)
	}
	return
}

func (t *tdns) serve(addr, network string, rTimeout, wTimeout time.Duration) {
	dnsServer := &dns.Server{
		Addr:         addr,
		Net:          network,
		ReadTimeout:  rTimeout,
		WriteTimeout: wTimeout,
	}
	dns.HandleFunc(".", t.dnsHandler)
	err := dnsServer.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func main() {
	t := &tdns{
		c:         new(dns.Client),
		dialer:    &net.Dialer{Timeout: 10 * time.Second},
		proxy:     "127.0.0.1:9150",
		upstreams: []string{"8.8.8.8:53"},
	}
	t.c.Net = "tcp"
	t.serve("127.0.0.1:9053", "tcp", time.Millisecond, time.Millisecond)
}
