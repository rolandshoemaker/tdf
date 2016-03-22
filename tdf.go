package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	mrand "math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v2"
)

func randomString() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%X", b)
}

func majority(total int) int {
	if total == 1 {
		return 1
	}
	cm := float64(total) * (2.0 / 3.0) // require two thirds majority
	return int(math.Floor(cm))
}

type tdns struct {
	dialer    *net.Dialer
	upstreams []string
	paths     int
	majority  int
	proxy     string
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
	id := make([]byte, 4)
	_, err := rand.Read(id)
	if err != nil {
		panic(err)
	}
	upstream := t.upstreams[mrand.Intn(len(t.upstreams))]
	fmt.Fprintf(
		os.Stdout,
		"[%X] Query from %s for %s %s %s forwarding to %s\n",
		id,
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
				fmt.Fprintf(os.Stderr, "[%X] Forwarding failed: %s\n", id, err)
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
	failed := 0
	for _, result := range results {
		if result == nil {
			failed++
			continue
		}
		rcodes[result.Rcode]++
		answer = append(answer, result.Answer...)
		ns = append(ns, result.Ns...)
		extra = append(extra, result.Extra...)
	}
	if failed > t.majority {
		ret.Rcode = dns.RcodeServerFailure
		err := w.WriteMsg(ret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%X] Failed to write response to query: %s\n", id, err)
		}
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
	err = w.WriteMsg(ret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%X] Failed to write response to query: %s\n", id, err)
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
	fmt.Fprintf(os.Stdout, "Listening on %s/%s\n", addr, network)
	err := dnsServer.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

type config struct {
	TorProxy          string   `yaml:"tor-proxy"`
	UpstreamResolvers []string `yaml:"upstream-resolvers"`
	PathsPerQuery     int      `yaml:"paths-per-query"`
	DNSAddr           string   `yaml:"dns-addr"`
	DNSReadTimeout    string   `yaml:"dns-read-timeout"`
	DNSWriteTimeout   string   `yaml:"dns-write-timeout"`
	DNSNetwork        string   `yaml:"dns-network"`
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
		proxy:     c.TorProxy,
		upstreams: c.UpstreamResolvers,
		paths:     c.PathsPerQuery,
		majority:  majority(c.PathsPerQuery),
	}
	dnsWTimeout := time.Millisecond
	if c.DNSWriteTimeout != "" {
		dnsWTimeout, err = time.ParseDuration(c.DNSWriteTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse dns-write-timeout: %s\n", err)
			os.Exit(1)
		}
	}
	dnsRTimeout := time.Millisecond
	if c.DNSReadTimeout != "" {
		dnsRTimeout, err = time.ParseDuration(c.DNSReadTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse dns-read-timeout: %s\n", err)
			os.Exit(1)
		}
	}
	if c.DNSNetwork == "" {
		c.DNSNetwork = "udp"
	}
	t.serve(c.DNSAddr, c.DNSNetwork, dnsRTimeout, dnsWTimeout)
}
