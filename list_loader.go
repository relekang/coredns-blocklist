package blocklist

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/coredns/caddy"
)

func loadList(c *caddy.Controller, location string) ([]string, error) {
	log.Infof("Loading from %s", location)
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return loadListFromUrl(c, location)
	}
	return loadListFromFile(c, location)
}

func loadListFromUrl(c *caddy.Controller, name string) ([]string, error) {
	response, err := http.Get(name)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	domains := strings.Split(string(body), "\n")
	log.Infof("Loaded %d domains from %s", len(domains), name)
	domainCount.WithLabelValues(name).Set(float64(len(domains)))
	return domains, err
}

func loadListFromFile(c *caddy.Controller, name string) ([]string, error) {
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
	domains := strings.Split(string(content), "\n")
	log.Infof("Loaded %d domains from %s", len(domains), name)
	domainCount.WithLabelValues(name).Set(float64(len(domains)))
	return domains, err
}

func toMap(domains []string) map[string]bool {
	domainsMap := map[string]bool{}
	fullLineCommentRegex := regexp.MustCompile(`^[ ]*#`)
	inlineCommentRegex := regexp.MustCompile(`[ ]*#.*$`)
	for _, line := range domains {
		if fullLineCommentRegex.MatchString(line) {
			log.Debugf("Filtered out comment '%s' from blocklist", line)
			continue
		}
		line = inlineCommentRegex.ReplaceAllString(line, "")
		line = strings.Replace(line, "0.0.0.0 ", "", 1)
		line = strings.Replace(line, "127.0.0.1 ", "", 1)
		if line == "" || line == "localhost" || strings.Contains(line, " ") {
			continue
		}
		log.Debugf("Loaded '%s' into blocklist", line)
		if strings.HasSuffix(line, ".") {
			domainsMap[line] = true
		} else {
			domainsMap[line+"."] = true
		}
	}
	return domainsMap
}
