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

var once sync.Once
