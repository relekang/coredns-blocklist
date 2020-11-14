package blocklist

import (
	"errors"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

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

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Blocklist{Next: next, domains: domains}
	})

	return nil
}

func loadBlockList(c *caddy.Controller, name string) ([]string, error) {
	log.Infof("Loading from %s", name)
	if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") {
		return loadBlockListFromUrl(c, name)
	}
	return loadBlockListFromFile(c, name)
}

func loadBlockListFromUrl(c *caddy.Controller, name string) ([]string, error) {
	response, err := http.Get(name)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	domains, err := strings.Split(string(body), "\n"), nil
	if err == nil {
		log.Infof("Loaded %d domains from %s", len(domains), name)
	}
	return domains, err
}

func loadBlockListFromFile(c *caddy.Controller, name string) ([]string, error) {
	if !filepath.IsAbs(name) {
		name = filepath.Join(
			filepath.Dir(c.File()),
			name,
		)
	}

	content, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	domains, err := strings.Split(string(content), "\n"), err
	if err == nil {
		log.Infof("Loaded %d domains from %s", len(domains), name)
	}
	return domains, err
}
