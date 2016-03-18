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

func (t *tdns) newDialer() proxy.Dialer {
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
	return p
}

func (t *tdns) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Println("query")
	upstream := t.upstreams[0]
	m := new(dns.Msg)
	m.SetReply(r)
	dialer := t.newDialer()
	conn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to dial upstream [%s]: %s\n", upstream, err)
		return
	}
	co := &dns.Conn{Conn: conn}
	co.WriteMsg(r)
	rr, err := co.ReadMsg()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send query to %s: %s\n", upstream, err)
		m.Rcode = dns.RcodeServerFailure
	} else {
		m = rr
		co.Close()
	}
	conn.Close()
	err = w.WriteMsg(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write response: %s\n", err)
	}
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
		dialer:    &net.Dialer{Timeout: 10 * time.Second},
		proxy:     "127.0.0.1:9150",
		upstreams: []string{"8.8.8.8:53"},
	}
	t.serve("127.0.0.1:9053", "tcp", time.Millisecond, time.Millisecond)
}
