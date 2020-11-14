package blocklist

import (
	"testing"

	"github.com/coredns/caddy"
	"github.com/stretchr/testify/assert"
)

func TestSetupInvalidConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `blocklist`)

	err := setup(c)
	assert.EqualError(
		t,
		err,
		"plugin/blocklist: Missing url or path to blocklist.",
	)

	c = caddy.NewTestController("dns", `blocklist example/list.txt example/list.txt`)
	err = setup(c)
	assert.EqualError(
		t,
		err,
		"plugin/blocklist: To many arguments for blocklist.",
	)
}
func TestSetupValidConfig(t *testing.T) {
	c := caddy.NewTestController("dns", `blocklist example/list.txt`)
	err := setup(c)
	assert.NoError(t, err)

	c = caddy.NewTestController("dns", `blocklist https://mirror1.malwaredomains.com/files/justdomains`)
	err = setup(c)
	assert.NoError(t, err)
}
