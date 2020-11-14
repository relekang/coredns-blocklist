package blocklist

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/coredns/caddy"
)

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

func toMap(domains []string) map[string]bool {
	domainsMap := map[string]bool{}
	for _, domain := range domains {
		if strings.HasSuffix(domain, ".") {
			domainsMap[domain] = true
		} else {
			domainsMap[domain+"."] = true
		}
	}
	return domainsMap
}
