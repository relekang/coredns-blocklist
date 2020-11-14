package blocklist

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("blocklist")

type Blocklist struct {
	domains map[string]bool
	Next    plugin.Handler
}

func (b Blocklist) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	if b.shouldBlock(state.Name()) {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(resp)

		blockCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
		log.Debugf(
			"blocked \"%s IN %s %s\" from %s",
			state.Type(),
			state.Name(),
			state.Proto(),
			state.RemoteAddr(),
		)

		return dns.RcodeNameError, nil
	}

	return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
}

func (b Blocklist) shouldBlock(name string) bool {
	log.Debugf("shouldBlock(%s)", name)
	if name == "localhost." {
		return false
	}
	_, ok := b.domains[name]
	return ok
}

func (b Blocklist) Name() string { return "blocklist" }
