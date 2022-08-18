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
		var blocklistLocation string
		var allowlistLocation string
		var allowlist []string
		c.Args(&blocklistLocation)

		if blocklistLocation == "" {
			return plugin.Error("blocklist", errors.New("Missing url or path to blocklist."))
		}

		for c.NextBlock() {
			option := c.Val()
			switch option {
			case "allowlist":
				remaining := c.RemainingArgs()
				if len(remaining) != 1 {
					return plugin.Error("blocklist", errors.New("allowlist requires a single argument."))
				}

				allowlistLocation = remaining[0]
				log.Debugf("Setting allowlist location to %s", allowlistLocation)
			case "domain_metrics":
				domainMetrics = true
			default:
				return plugin.Error("blocklist", c.Errf("unexpected '%v' command", option))
			}
		}

		if c.NextArg() {
			return plugin.Error("blocklist", errors.New("To many arguments for blocklist."))
		}

		blocklist, err := loadList(c, blocklistLocation)
		if err != nil {
			return plugin.Error("blocklist", err)
		}

		if allowlistLocation != "" {
			allowlist, err = loadList(c, allowlistLocation)
			if err != nil {
				return plugin.Error("blocklist", err)
			}
		}

		dnsserver.GetConfig(c).
			AddPlugin(func(next plugin.Handler) plugin.Handler {
				return NewBlocklistPlugin(next, blocklist, allowlist, domainMetrics)
			})
	}

	return nil
}
