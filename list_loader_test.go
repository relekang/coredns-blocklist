package blocklist

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var tests = []struct {
	in  []string
	out map[string]bool
}{
	{[]string{"bad.domain"}, map[string]bool{"bad.domain.": true}},
	{[]string{"bad.domain."}, map[string]bool{"bad.domain.": true}},
}

func TestToMap(t *testing.T) {
	for _, item := range tests {
		t.Run(strings.Join(item.in, ","), func(t *testing.T) {
			assert.Equal(t, item.out, toMap(item.in))
		})
	}
}
