package blocklist

import (
	"bytes"
	"context"
	golog "log"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/stretchr/testify/assert"

	"github.com/miekg/dns"
)

func NextHandler() test.Handler {
	return test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		return r.Rcode, nil
	})
}

func TestExample(t *testing.T) {
	x := Blocklist{Next: test.NextHandler(dns.RcodeSuccess, nil)}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeSuccess, rec.Rcode)
}

func TestAllowedDomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), domains: map[string]bool{"bad.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.com.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeSuccess, rec.Rcode)
}

func TestBlockedDomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), domains: map[string]bool{"bad.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeNameError, rec.Rcode)
}

func TestBlockedParentDomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), domains: map[string]bool{"bad.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("child.bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeNameError, rec.Rcode)
}

func TestBlockedChildDomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), domains: map[string]bool{"child.bad.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeSuccess, rec.Rcode)
}

func TestBlockedRoot(t *testing.T) {
	x := Blocklist{Next: NextHandler(), domains: map[string]bool{".": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeNameError, rec.Rcode)
}
