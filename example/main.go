package main

import (
	"slices"

	_ "github.com/coredns/coredns/core/plugin"
	_ "github.com/coredns/coredns/plugin/view"
	_ "github.com/relekang/coredns-blocklist"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
)

func init() {
	dnsserver.Directives = slices.Insert(
		dnsserver.Directives,
		slices.Index(dnsserver.Directives, "local"),
		"blocklist",
	)
}

func main() {
	coremain.Run()
}
