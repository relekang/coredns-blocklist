package blocklist

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"

	"strings"
)

var log = clog.NewWithPlugin("blocklist")

type Blocklist struct {
	domains       map[string]bool
	Next          plugin.Handler
	domainMetrics bool
}

func NewBlocklistPlugin(next plugin.Handler, domains []string, domainMetrics bool) Blocklist {

	log.Debugf(
		"Creating blocklist plugin with %d domains and domain metrics set to %v",
		len(domains),
		domainMetrics,
	)

	return Blocklist{
		domains:       toMap(domains),
		Next:          next,
		domainMetrics: domainMetrics,
	}
}

func (b Blocklist) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	if b.shouldBlock(state.Name()) {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNameError)
		err := w.WriteMsg(resp)

		if err != nil {
			log.Errorf("failed to write block for %s, %v+", state.Name(), err)
		}

		blockCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
		if b.domainMetrics {
			blockWithDomainsCount.WithLabelValues(metrics.WithServer(ctx), state.Name()).Inc()
		}

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

	inBlocklist := false

	nameParts := strings.Split(name, ".")
	for i := range nameParts {
		n := strings.Join(nameParts[i:], ".")

		// Because of how domains are passed through, the final iteration
		// of the joined array will be a zero-length string
		// Manually override that to be the DNS root RR
		if len(n) == 0 {
			n = "."
		}

		if _, inBlocklist = b.domains[n]; inBlocklist {
			break
		}
	}

	return inBlocklist
}

func (b Blocklist) Name() string { return "blocklist" }
