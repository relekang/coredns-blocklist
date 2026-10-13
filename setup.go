package blocklist

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/miekg/dns"
)

func init() { plugin.Register("blocklist", setup) }

func setup(c *caddy.Controller) error {
	for c.Next() {
		domainMetrics := false
		failOnHTTPError := true
		var blocklistLocation string
		var allowlistLocation string
		var allowlist []string
		var blockResponse string
		var bootStrapDNS string
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
			case "fail_on_http_error":
				remaining := c.RemainingArgs()
				if len(remaining) != 1 {
					return plugin.Error("blocklist", errors.New("fail_on_http_error requires a single boolean argument."))
				}
				var err error
				failOnHTTPError, err = strconv.ParseBool(remaining[0])
				if err != nil {
					return plugin.Error("blocklist", err)
				}
			case "domain_metrics":
				domainMetrics = true
			case "bootstrap_dns":
				bootStrapDNS = c.RemainingArgs()[0]
			case "block_response":
				remaining := c.RemainingArgs()
				if len(remaining) != 1 {
					return plugin.Error("blocklist", errors.New("block_response requires a single argument."))
				}

				blockResponse = remaining[0]
				log.Debugf("Setting block response code to %s", blockResponse)
			default:
				return plugin.Error("blocklist", c.Errf("unexpected '%v' command", option))
			}
		}

		if c.NextArg() {
			return plugin.Error("blocklist", errors.New("To many arguments for blocklist."))
		}

		blocklist, err := loadList(c, blocklistLocation, bootStrapDNS, failOnHTTPError)
		if err != nil {
			return plugin.Error("blocklist", err)
		}

		if allowlistLocation != "" {
			allowlist, err = loadList(c, allowlistLocation, bootStrapDNS, failOnHTTPError)
			if err != nil {
				return plugin.Error("blocklist", err)
			}
		}

		if blockResponse == "" {
			blockResponse = "nxdomain"
		}
		blockResponseCode, err := getBlockResponseCode(blockResponse)
		if err != nil {
			return plugin.Error("blocklist", err)
		}

		dnsserver.GetConfig(c).
			AddPlugin(func(next plugin.Handler) plugin.Handler {
				return NewBlocklistPlugin(next, blocklist, allowlist, domainMetrics, blockResponseCode)
			})
	}

	return nil
}

func getBlockResponseCode(blockResponse string) (int, error) {
	switch blockResponse {
	case "nxdomain":
		return dns.RcodeNameError, nil
	case "refused":
		return dns.RcodeRefused, nil
	default:
		return 0, fmt.Errorf("unknown response code '%s', must be either 'nxdomain' or 'refused'", blockResponse)
	}
}
