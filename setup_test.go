package blocklist

import (
	"testing"

	"github.com/coredns/caddy"
	"github.com/stretchr/testify/assert"
)

// TestSetup tests the various things that should be parsed by setup.
// Make sure you also test for parse errors.
func TestSetup(t *testing.T) {
	c := caddy.NewTestController("dns", `blocklist`)

	err := setup(c)
	assert.EqualError(
		t,
		err,
		"plugin/blocklist: Testfile:1 - Error during parsing: Wrong argument count or unexpected line ending after 'blocklist'",
	)

	c = caddy.NewTestController("dns", `blocklist example/list.txt`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `blocklist https://mirror1.malwaredomains.com/files/justdomains`)
	if err := setup(c); err == nil {
		t.Fatalf("Expected errors, but got: %v", err)
	}
}
