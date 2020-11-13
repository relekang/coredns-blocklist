package coredns_blocklist

import (
	"bytes"
	"context"
	golog "log"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestExample(t *testing.T) {
	x := Blocklist{Next: test.ErrorHandler()}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)
	if a := b.String(); !strings.Contains(a, "[INFO] plugin/blocklist: example") {
		t.Errorf("Failed to print '%s', got %s", "[INFO] plugin/blocklist: example", a)
	}
}

func TestBlockedDomain(t *testing.T) {
	x := Blocklist{Next: test.ErrorHandler()}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)
	if a := b.String(); !strings.Contains(a, "[INFO] plugin/blocklist: example") {
		t.Errorf("Failed to print '%s', got %s", "[INFO] plugin/blocklist: blocked bad.domain.", a)
	}
}
