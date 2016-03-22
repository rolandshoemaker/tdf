package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v2"
)

type tdns struct {
	dialer    *net.Dialer
	upstreams []string
	paths     int
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

func (t *tdns) forward(r *dns.Msg, upstream string) (*dns.Msg, error) {
	dialer := t.newDialer()
	conn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return nil, fmt.Errorf("failed to dial upstream [%s]: %s", upstream, err)
	}
	co := &dns.Conn{Conn: conn}
	defer conn.Close()
	err = co.WriteMsg(r)
	if err != nil {
		return nil, fmt.Errorf("failed to send query to %s: %s", upstream, err)
	}
	rr, err := co.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %s", err)
	}
	return rr, nil
}

func (t *tdns) dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	upstream := t.upstreams[mrand.Intn(len(t.upstreams))]
	fmt.Fprintf(
		os.Stdout,
		"Query from %s for %s %s %s forwarding to %s\n",
		w.RemoteAddr(),
		dns.ClassToString[r.Question[0].Qclass],
		dns.TypeToString[r.Question[0].Qtype],
		r.Question[0].Name,
		upstream,
	)
	results := make([]*dns.Msg, t.paths)
	wg := new(sync.WaitGroup)
	for i := 0; i < t.paths; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			response, err := t.forward(r, upstream)
			if err != nil {
				// something
				fmt.Fprintf(os.Stderr, "Failed to forward query: %s\n", err)
			}
			results[i] = response
		}(i)
	}
	wg.Wait()

	// merge results
	ret := new(dns.Msg)
	ret.SetReply(r)
	rcodes := make(map[int]int)
	answer := []dns.RR{}
	ns := []dns.RR{}
	extra := []dns.RR{}
	for _, result := range results {
		if result == nil {
			// bad
			continue
		}
		rcodes[result.Rcode]++
		answer = append(answer, result.Answer...)
		ns = append(ns, result.Ns...)
		extra = append(extra, result.Extra...)
	}
	li := 0
	for i, v := range rcodes {
		if v > rcodes[li] {
			li = i
		}
	}
	ret.Rcode = li
	if ret.Rcode == dns.RcodeSuccess {
		ret.Answer = dns.Dedup(answer, nil)
		ret.Ns = dns.Dedup(ns, nil)
		ret.Extra = dns.Dedup(extra, nil)
	}
	err := w.WriteMsg(ret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write response to query: %s\n", err)
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

type config struct {
	TorProxy          string
	UpstreamResolvers []string
	PathsPerQuery     int
	DNSAddr           string
}

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	flag.Parse()
	configBytes, err := ioutil.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config from '%s': %s", *configPath, err)
		os.Exit(1)
	}
	var c config
	err = yaml.Unmarshal(configBytes, &c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse config from '%s': %s", *configPath, err)
		os.Exit(1)
	}

	t := &tdns{
		dialer:    &net.Dialer{Timeout: 10 * time.Second},
		proxy:     "127.0.0.1:9150",
		upstreams: []string{"8.8.8.8:53", "8.8.4.4:53"},
		paths:     5,
	}
	t.serve("127.0.0.1:9053", "tcp", time.Millisecond, time.Millisecond)
}
