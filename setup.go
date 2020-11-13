package blocklist

import (
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("blocklist", setup) }

func setup(c *caddy.Controller) error {
	var domains []string = []string{}
	for c.Next() {

		if !c.NextArg() {
			return plugin.Error("blocklist", c.ArgErr())
		}

		var list string
		c.Args(&list)

		if c.NextArg() {
			return plugin.Error("blocklist", c.ArgErr())
		}

		loaded, err := loadBlockList(list)

		if err != nil {
			return plugin.Error("blocklist", err)
		}
		domains = append(domains, loaded...)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Blocklist{Next: next, domains: domains}
	})

	return nil
}

func loadBlockList(list string) ([]string, error) {
	log.Infof("Loading from %s", list)
	if strings.HasPrefix(list, "http://") || strings.HasPrefix(list, "https://") {
		return loadBlockListFromUrl(list)
	}
	return loadBlockListFromFile(list)
}

func loadBlockListFromUrl(list string) ([]string, error) {
	response, err := http.Get(list)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	return strings.Split(string(body), "\n"), nil
}

func loadBlockListFromFile(list string) ([]string, error) {
	content, err := ioutil.ReadFile(list)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(content), "\n"), err
}
