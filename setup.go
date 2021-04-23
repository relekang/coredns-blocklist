package blocklist

import (
	"errors"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("blocklist", setup) }

func setup(c *caddy.Controller) error {
	for c.Next() {
		domainMetrics := false
		var name string
		c.Args(&name)

		if name == "" {
			return plugin.Error("blocklist", errors.New("Missing url or path to blocklist."))
		}

		for c.NextBlock() {
			name := c.Val()
			switch name {
			case "domain_metrics":
				domainMetrics = true
				break

			default:
				return plugin.Error("blocklist", c.Errf("unexpected '%v' command", name))
			}
		}

		if c.NextArg() {
			return plugin.Error("blocklist", errors.New("To many arguments for blocklist."))
		}

		loaded, err := loadBlockList(c, name)

		if err != nil {
			return plugin.Error("blocklist", err)
		}

		dnsserver.GetConfig(c).
			AddPlugin(func(next plugin.Handler) plugin.Handler {
				return NewBlocklistPlugin(next, loaded, domainMetrics)
			})
	}

	return nil
}
