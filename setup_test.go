package blocklist

import (
	"testing"

	"github.com/coredns/caddy"
	"github.com/stretchr/testify/assert"

	"github.com/miekg/dns"
)

func TestSetupInvalidConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `blocklist`)

	err := setup(c)
	assert.EqualError(
		t,
		err,
		"plugin/blocklist: Missing url or path to blocklist.",
	)

	c = caddy.NewTestController("dns", `blocklist example/blocklist.txt example/blocklist.txt`)
	err = setup(c)
	assert.EqualError(
		t,
		err,
		"plugin/blocklist: To many arguments for blocklist.",
	)
}

func TestSetupAllowlistWithNoLocation(t *testing.T) {
	cfg := `blocklist https://mirror1.malwaredomains.com/files/justdomains {
            allowlist
          }`
	c := caddy.NewTestController("dns", cfg)

	err := setup(c)
	assert.EqualError(
		t,
		err,
		"plugin/blocklist: allowlist requires a single argument.",
	)
}

func TestSetupValidConfigWithAllowlist(t *testing.T) {
	cfg := `blocklist https://mirror1.malwaredomains.com/files/justdomains {
            allowlist example/allowlist.txt
          }`
	c := caddy.NewTestController("dns", cfg)

	err := setup(c)
	assert.NoError(t, err)
}

func TestSetupValidConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `blocklist example/blocklist.txt`)
	err := setup(c)
	assert.NoError(t, err)

	c = caddy.NewTestController("dns", `blocklist https://mirror1.malwaredomains.com/files/justdomains { domain_metrics }`)
	err = setup(c)
	assert.NoError(t, err)
}

func TestSetupValidConfigWithRefusedResponse(t *testing.T) {
	cfg := `blocklist example/blocklist.txt {
            block_response refused
          }`
	c := caddy.NewTestController("dns", cfg)

	err := setup(c)
	assert.NoError(t, err)
}

func TestSetupMissingBlockResponseValue(t *testing.T) {
	cfg := `blocklist example/blocklist.txt {
            block_response
          }`
	c := caddy.NewTestController("dns", cfg)

	err := setup(c)
	assert.EqualError(
		t,
		err,
		"plugin/blocklist: block_response requires a single argument.",
	)
}

func TestSetupInvalidBlockResponse(t *testing.T) {
	cfg := `blocklist example/blocklist.txt {
            block_response invalid
          }`
	c := caddy.NewTestController("dns", cfg)

	err := setup(c)
	assert.Error(t, err)
	assert.EqualError(
		t,
		err,
		"plugin/blocklist: unknown response code 'invalid', must be either 'nxdomain' or 'refused'",
	)
}

func TestSetupNxdomainBlockResponseCode(t *testing.T) {
	r, err := getBlockResponseCode("nxdomain")
	assert.NoError(t, err)
	assert.Equal(t, r, dns.RcodeNameError)
}

func TestSetupRefusedBlockResponseCode(t *testing.T) {
	r, err := getBlockResponseCode("refused")
	assert.NoError(t, err)
	assert.Equal(t, r, dns.RcodeRefused)
}
