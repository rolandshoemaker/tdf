package main

import (
	"bytes"
	"crypto/rand"
	"errors"
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

var majorityDef = 2.0 / 3.0

func majority(total int) int {
	if total == 1 {
		return 1
	}
	cm := float64(total) * majorityDef
	return int(math.Floor(cm))
}

type tdns struct {
	dialerFunc   func() proxy.Dialer
	stdDialer    *net.Dialer
	paths        int
	majority     int
	combiner     func([]*dns.Msg) (*dns.Msg, error)
	dnsQueryMode string

	upstreams []string
	torProxy  string

	vpnAddrs []net.Addr
}

func (t *tdns) torDialer() proxy.Dialer {
	randStr := randomString()
	p, err := proxy.SOCKS5(
		"tcp",
		t.torProxy,
		&proxy.Auth{User: randStr, Password: randStr}, // required to force the creation of a new circuit per query
		t.stdDialer,
	)
	if err != nil {
		panic(err)
	}
	return p
}

func (t *tdns) vpnDialer() proxy.Dialer {
	var d *net.Dialer
	*d = *t.stdDialer
	d.LocalAddr = t.vpnAddrs[mrand.Intn(len(t.vpnAddrs))]
	return d
}

func (t *tdns) forward(r *dns.Msg, upstream string) (*dns.Msg, error) {
	dialer := t.dialerFunc()
	conn, err := dialer.Dial(t.dnsQueryMode, upstream)
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
		"[%X] Query from %s for '%s' [%s %s] forwarding to %s\n",
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

	ret, err := t.combiner(results)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%X] response check failed: %s\n", id, err)
		ret := new(dns.Msg)
		ret.SetReply(r)
		ret.Rcode = dns.RcodeServerFailure
		err = w.WriteMsg(ret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%X] Failed to write response to query: %s\n", id, err)
		}
		return
	}
	ret.SetReply(r)

	err = w.WriteMsg(ret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%X] Failed to write response to query: %s\n", id, err)
	}
}

func (t *tdns) mergeCheck(msgs []*dns.Msg) (*dns.Msg, error) {
	ret := new(dns.Msg)
	rcodes := make(map[int]int)
	answer := []dns.RR{}
	ns := []dns.RR{}
	extra := []dns.RR{}
	failed := 0
	for _, m := range msgs {
		if m == nil {
			failed++
			continue
		}
		rcodes[m.Rcode]++
		answer = append(answer, m.Answer...)
		ns = append(ns, m.Ns...)
		extra = append(extra, m.Extra...)
	}
	if failed > t.majority {
		return nil, fmt.Errorf("%d queries failed or timed out (%d required to continue)", failed, t.majority)
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
	return ret, nil
}

func (t *tdns) strictCheck(msgs []*dns.Msg) (*dns.Msg, error) {
	failed := 0
	var firstPacked []byte
	for _, m := range msgs {
		if m == nil {
			failed++
			continue
		}
		packed, err := m.Pack()
		if err != nil {
			return nil, err
		}
		if firstPacked == nil {
			firstPacked = packed
		} else {
			if bytes.Compare(firstPacked, packed) != 0 {
				return nil, errors.New("returned response doesn't match others")
			}
		}
	}
	if failed > t.majority {
		return nil, fmt.Errorf("%d queries failed or timed out (%d required to continue)", failed, t.majority)
	}
	return msgs[0], nil
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
	TorProxy           string   `yaml:"tor-proxy"`
	VPNInterfaces      []string `yaml:"vpn-interfaces"`
	UpstreamResolvers  []string `yaml:"upstream-resolvers"`
	PathsPerQuery      int      `yaml:"paths-per-query"`
	DNSAddr            string   `yaml:"dns-addr"`
	DNSReadTimeout     string   `yaml:"dns-read-timeout"`
	DNSWriteTimeout    string   `yaml:"dns-write-timeout"`
	DNSListenNetwork   string   `yaml:"dns-listen-network"`
	DNSQueryNetwork    string   `yaml:"dns-query-network"`
	MajorityDefinition float64  `yaml:"majority-definition"`
	DNSMode            string   `yaml:"dns-mode"`
	ForwardingMode     string   `yaml:"forwarding-mode"`
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

	if c.MajorityDefinition > 0 {
		majorityDef = c.MajorityDefinition
	}
	if c.DNSListenNetwork == "" {
		c.DNSListenNetwork = "udp"
	}
	if c.DNSQueryNetwork == "" {
		c.DNSQueryNetwork = "tcp"
	}

	t := &tdns{
		stdDialer:    &net.Dialer{Timeout: 10 * time.Second},
		paths:        c.PathsPerQuery,
		majority:     majority(c.PathsPerQuery),
		dnsQueryMode: c.DNSQueryNetwork,
	}
	switch c.ForwardingMode {
	case "tor":
		t.dialerFunc = t.torDialer
		t.torProxy = c.TorProxy
		t.upstreams = c.UpstreamResolvers
		if c.DNSQueryNetwork != "tcp" {
			fmt.Fprintln(os.Stderr, "In 'tor' mode only TCP DNS forwarding is supported")
			os.Exit(1)
		}
	case "vpn":
		t.dialerFunc = t.vpnDialer
		if len(c.VPNInterfaces) < c.PathsPerQuery {
			fmt.Fprintf(os.Stderr, "Cannot construct %d paths using %d interfaces\n", c.PathsPerQuery, len(c.VPNInterfaces))
			os.Exit(1)
		}
		for _, i := range c.VPNInterfaces {
			inter, err := net.InterfaceByName(i)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to find interface '%s': %s\n", i, err)
				os.Exit(1)
			}
			addrs, err := inter.Addrs()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to get interface addresses for '%s': %s\n", i, err)
				os.Exit(1)
			}
			t.vpnAddrs = append(t.vpnAddrs, addrs[0])
		}
		t.vpnAddrs = []net.Addr{}
	default:
		fmt.Fprintln(os.Stderr, "forwarding-mode must be set to either 'tor' or 'vpn'")
		os.Exit(1)
	}
	switch c.DNSMode {
	case "", "strict":
		t.combiner = t.strictCheck
	case "merge":
		t.combiner = t.mergeCheck
	default:
		fmt.Fprintln(os.Stderr, "mode must be one of either 'strict' or 'merge'")
		os.Exit(1)
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
	t.serve(c.DNSAddr, c.DNSListenNetwork, dnsRTimeout, dnsWTimeout)
}
