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
	blockDomains  map[string]bool
	allowDomains  map[string]bool
	Next          plugin.Handler
	domainMetrics bool
}

func NewBlocklistPlugin(next plugin.Handler, blockDomains []string, allowDomains []string, domainMetrics bool) Blocklist {

	log.Debugf(
		"Creating blocklist plugin with %d blocks, %d allows, and domain metrics set to %v",
		len(blockDomains),
		len(allowDomains),
		domainMetrics,
	)

	return Blocklist{
		blockDomains:  toMap(blockDomains),
		allowDomains:  toMap(allowDomains),
		Next:          next,
		domainMetrics: domainMetrics,
	}
}

// ServeDNS handles processing the DNS query in relation to the blocklist
// A count of metrics around the blocking and allowing status is maintained
// It returns the DNS RCODE
func (b Blocklist) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	shouldBlock, shouldAllow := b.shouldBlock(state.Name())

	if shouldBlock {
		// If an RR should be both blocked and allowed,
		// then allow it and update appropriate metrics
		if shouldAllow {
			allowCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
			if b.domainMetrics {
				allowWithDomainsCount.WithLabelValues(metrics.WithServer(ctx), state.Name()).Inc()
			}

		} else {
			// Handle the blocking of the RR
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
	}

	return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
}

// shouldBlock checks for the presence of a DNS name in the block and allow lists
// It returns the blockList and allowList status for that RR
func (b Blocklist) shouldBlock(name string) (isBlocked bool, isAllowed bool) {
	log.Debugf("shouldBlock(%s)", name)

	if name == "localhost." {
		return false, false
	}

	isBlocked = inList(name, b.blockDomains)
	isAllowed = inList(name, b.allowDomains)

	return isBlocked, isAllowed
}

func inList(name string, domainList map[string]bool) bool {
	inList := false

	nameParts := strings.Split(name, ".")
	for i := range nameParts {
		n := strings.Join(nameParts[i:], ".")

		// Because of how domains are passed through, the final iteration
		// of the joined array will be a zero-length string
		// Manually override that to be the DNS root RR
		if len(n) == 0 {
			n = "."
		}

		if _, inList = domainList[n]; inList {
			break
		}
	}

	return inList
}

func (b Blocklist) Name() string { return "blocklist" }
