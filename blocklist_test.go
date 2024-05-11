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
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"bad.domain.": true}, allowDomains: map[string]bool{"good.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("good.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeSuccess, rec.Rcode)
}

func TestBlockedDomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"bad.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, x.blockResponse, rec.Rcode)
}

func TestBlockedParentDomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"bad.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("child.bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, x.blockResponse, rec.Rcode)
}

func TestBlockedChildDomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"child.bad.domain.": true}}

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
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{".": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, x.blockResponse, rec.Rcode)
}

func TestAllowedDomainWithBlockedParentDomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"bad.domain.": true}, allowDomains: map[string]bool{"sub.good.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("sub.good.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeSuccess, rec.Rcode)
}

func TestBlockedDomainWithAllowedParentDomain(t *testing.T) {
	// This test should succeed, as the allowlist always takes precedence, even with a more-specific
	// block in place
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"sub.bad.domain.": true}, allowDomains: map[string]bool{"good.domain.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("sub.good.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeSuccess, rec.Rcode)
}

func TestAllowedDomainWithDomainMetrics(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"bad.domain.": true}, allowDomains: map[string]bool{"allow.bad.domain.": true}, domainMetrics: true}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("allow.bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeSuccess, rec.Rcode)
}

func TestBlockedDomainWithDomainMetrics(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"bad.domain.": true}, domainMetrics: true}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, x.blockResponse, rec.Rcode)
}

func TestBlockedLocalhostStillAllowed(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"localhost.": true}}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("localhost.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeSuccess, rec.Rcode)
}

func TestBlockedDomainWithNxdomain(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"bad.domain.": true}, blockResponse: dns.RcodeNameError}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeNameError, rec.Rcode)
}

func TestBlockedDomainWithRefused(t *testing.T) {
	x := Blocklist{Next: NextHandler(), blockDomains: map[string]bool{"bad.domain.": true}, blockResponse: dns.RcodeRefused}

	b := &bytes.Buffer{}
	golog.SetOutput(b)

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("bad.domain.", dns.TypeA)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	x.ServeDNS(ctx, rec, r)

	assert.Equal(t, dns.RcodeRefused, rec.Rcode)
}
