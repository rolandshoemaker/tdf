package main

import (
	// "fmt"
	"testing"

	"github.com/miekg/dns"
)

func TestRandomString(t *testing.T) {

}

// I know math! (...right?)
func TestMajorityGenerator(t *testing.T) {
	tcs := []struct {
		def      float64
		total    int
		expected int
	}{
		{0, 3, 2},
		{0, 10, 6},
		{0.5, 10, 5},
		{0, 1, 1},
	}
	for _, tc := range tcs {
		if tc.def > 0 {
			majorityDef = tc.def
		}
		if m := majority(tc.total); m != tc.expected {
			t.Fatalf("majority(%d) returned %d, expected %d (majority definition: %3.2f)", tc.total, m, tc.expected, majorityDef)
		}
	}
}

func TestMerge(t *testing.T) {
	tdf := tdns{paths: 3, majority: 2}
	good := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
	bad := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}

	tcs := []struct {
		set         []*dns.Msg
		expectError bool
	}{
		// should fail
		{[]*dns.Msg{nil, nil, nil}, true},
		{[]*dns.Msg{good, nil, nil}, true},
		// should succeed
		{[]*dns.Msg{good, good, nil}, false},
		{[]*dns.Msg{good, good, good}, false},
	}

	for _, tc := range tcs {
		_, err := tdf.mergeCheck(tc.set)
		if err != nil && !tc.expectError {
			t.Fatalf("mergeCheck should not have failed: %s", err)
		} else if err == nil && tc.expectError {
			t.Fatal("mergeCheck should have failed")
		}
	}

	// test return code picker
	testSet := []*dns.Msg{good, bad, nil}
	_, err := tdf.mergeCheck(testSet)
	if err == nil {
		t.Fatal("mergeCheck should have failed")
	}

	testSet = []*dns.Msg{good, good, nil}
	result, err := tdf.mergeCheck(testSet)
	if err != nil {
		t.Fatal("mergeCheck should not have failed")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Fatalf(
			"mergeCheck returned a message with the wrong return code: %d -- %s",
			result.Rcode,
			dns.RcodeToString[result.Rcode],
		)
	}
	testSet = []*dns.Msg{bad, bad, nil}
	result, err = tdf.mergeCheck(testSet)
	if err != nil {
		t.Fatal("mergeCheck should not have failed")
	}
	if result.Rcode != dns.RcodeServerFailure {
		t.Fatalf(
			"mergeCheck returned a message with the wrong return code: %d -- %s",
			result.Rcode,
			dns.RcodeToString[result.Rcode],
		)
	}

	// test record merging
	goodA := good.Copy()
	goodA.Answer = []dns.RR{&dns.TXT{Txt: []string{"hi"}}, &dns.TXT{Txt: []string{"a"}}}
	goodB := good.Copy()
	goodB.Answer = []dns.RR{&dns.TXT{Txt: []string{"hi"}}, &dns.TXT{Txt: []string{"b"}}}
	goodB.Extra = []dns.RR{&dns.TXT{Txt: []string{"b"}}}
	goodC := good.Copy()
	goodC.Answer = []dns.RR{&dns.TXT{Txt: []string{"hi"}}, &dns.TXT{Txt: []string{"c"}}}
	goodC.Ns = []dns.RR{&dns.TXT{Txt: []string{"c"}}}

	testSet = []*dns.Msg{goodA, goodB, goodC}
	result, err = tdf.mergeCheck(testSet)
	if err != nil {
		t.Fatal("mergeCheck should not have failed")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Fatalf(
			"mergeCheck returned a message with the wrong return code: %d -- %s",
			result.Rcode,
			dns.RcodeToString[result.Rcode],
		)
	}
	expectedResult := `;; opcode: QUERY, status: NOERROR, id: 0
;; flags:; QUERY: 0, ANSWER: 4, AUTHORITY: 1, ADDITIONAL: 1

;; ANSWER SECTION:
	0	CLASS0	None	"hi"
	0	CLASS0	None	"a"
	0	CLASS0	None	"b"
	0	CLASS0	None	"c"

;; AUTHORITY SECTION:
	0	CLASS0	None	"c"

;; ADDITIONAL SECTION:
	0	CLASS0	None	"b"
`
	if result.String() != expectedResult {
		t.Fatalf("mergeCheck returned the incorrect result\n## wanted\n%s\n\n## got\n%s\n", expectedResult, result.String())
	}

	badA := bad.Copy()
	badA.Answer = []dns.RR{&dns.TXT{Txt: []string{"bad-a"}}}
	testSet[0] = badA
	result, err = tdf.mergeCheck(testSet)
	if err != nil {
		t.Fatal("mergeCheck should not have failed")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Fatalf(
			"mergeCheck returned a message with the wrong return code: %d -- %s",
			result.Rcode,
			dns.RcodeToString[result.Rcode],
		)
	}
	expectedResult = `;; opcode: QUERY, status: NOERROR, id: 0
;; flags:; QUERY: 0, ANSWER: 3, AUTHORITY: 1, ADDITIONAL: 1

;; ANSWER SECTION:
	0	CLASS0	None	"hi"
	0	CLASS0	None	"b"
	0	CLASS0	None	"c"

;; AUTHORITY SECTION:
	0	CLASS0	None	"c"

;; ADDITIONAL SECTION:
	0	CLASS0	None	"b"
`
	if result.String() != expectedResult {
		t.Fatalf("mergeCheck returned the incorrect result\n## expected\n%s\n\n## got\n%s\n", expectedResult, result.String())
	}
}

func TestStrict(t *testing.T) {

}
