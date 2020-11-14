package blocklist

import (
	"errors"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("blocklist", setup) }

func setup(c *caddy.Controller) error {
	var domains []string = []string{}
	for c.Next() {

		var name string
		c.Args(&name)

		if name == "" {
			return plugin.Error("blocklist", errors.New("Missing url or path to blocklist."))
		}

		if c.NextArg() {
			return plugin.Error("blocklist", errors.New("To many arguments for blocklist."))
		}

		loaded, err := loadBlockList(c, name)

		if err != nil {
			return plugin.Error("blocklist", err)
		}
		domains = append(domains, loaded...)
	}

	dnsserver.GetConfig(c).
		AddPlugin(func(next plugin.Handler) plugin.Handler {
			return Blocklist{Next: next, domains: toMap(domains)}
		})

	return nil
}
