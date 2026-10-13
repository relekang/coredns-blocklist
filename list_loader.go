package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/coredns/caddy"
)

const listDownloadTimeout = 30 * time.Second

func loadList(c *caddy.Controller, location string, bootStrapDNS string, failOnHTTPError bool) ([]string, error) {
	log.Infof("Loading from %s", location)
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return loadListFromUrl(c, location, bootStrapDNS, failOnHTTPError)
	}
	return loadListFromFile(c, location)
}

func loadListFromUrl(c *caddy.Controller, name string, bootStrapDNS string, failOnHTTPError bool) ([]string, error) {
	client := &http.Client{Timeout: listDownloadTimeout}
	if bootStrapDNS != "" {
		client = customDNS(bootStrapDNS)
	}
	response, err := client.Get(name)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if failOnHTTPError && (response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices) {
		return nil, fmt.Errorf("failed to load %s: HTTP %s", name, response.Status)
	}
	return collectDomains(response.Body, name)
}

func customDNS(bootStrapDNS string) *http.Client {
	var (
		dnsResolverIP        = bootStrapDNS // Google DNS resolver.
		dnsResolverProto     = "udp"        // Protocol to use for the DNS resolver
		dnsResolverTimeoutMs = 5000         // Timeout (ms) for the DNS resolver (optional)
	)

	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		DialContext:        dialContext,
	}
	client := &http.Client{Transport: tr, Timeout: listDownloadTimeout}

	return client
}

func loadListFromFile(c *caddy.Controller, name string) ([]string, error) {
	if !filepath.IsAbs(name) {
		name = filepath.Join(
			filepath.Dir(c.File()),
			name,
		)
	}
	readFile, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer readFile.Close()
	return collectDomains(readFile, name)
}

func collectDomains(r io.Reader, name string) ([]string, error) {
	var domains []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	log.Infof("Loaded %d domains from %s", len(domains), name)
	domainCount.WithLabelValues(name).Set(float64(len(domains)))
	return domains, nil
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
		fields := strings.Fields(inlineCommentRegex.ReplaceAllString(line, ""))
		if len(fields) > 0 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
			fields = fields[1:]
		}
		if len(fields) != 1 {
			continue
		}
		line = strings.ToLower(fields[0])
		if line == "localhost" {
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
