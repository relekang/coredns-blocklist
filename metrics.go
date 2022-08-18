package blocklist

import (
	"sync"

	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var blockCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "blocklist",
	Name:      "block_count_total",
	Help:      "Counter of blocks made.",
}, []string{"server"})

var allowCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "blocklist",
	Name:      "allow_count_total",
	Help:      "Counter of allows that have overridden blocks.",
}, []string{"server"})

var blockWithDomainsCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "blocklist",
	Name:      "block_count_with_domains_total",
	Help:      "Counter of blocks made.",
}, []string{"server", "domain"})

var allowWithDomainsCount = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: "blocklist",
	Name:      "allow_count_with_domains_total",
	Help:      "Counter of allows that have overridden blocks, with domain.",
}, []string{"server", "domain"})

var domainCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: plugin.Namespace,
	Subsystem: "blocklist",
	Name:      "list_size",
	Help:      "Number of domains in list.",
}, []string{"file"})

var once sync.Once
