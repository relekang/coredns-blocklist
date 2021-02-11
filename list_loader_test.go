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
	{[]string{"0.0.0.0 bad.domain"}, map[string]bool{"bad.domain.": true}},
	{[]string{"127.0.0.1 bad.domain"}, map[string]bool{"bad.domain.": true}},
	{[]string{"# comment with.domain", "bad.domain."}, map[string]bool{"bad.domain.": true}},
	{[]string{"bad.domain # With a comment"}, map[string]bool{"bad.domain.": true}},
	{[]string{"localhost"}, map[string]bool{}},
	{[]string{"something else"}, map[string]bool{}},
}

func TestToMap(t *testing.T) {
	for _, item := range tests {
		t.Run(strings.Join(item.in, ","), func(t *testing.T) {
			assert.Equal(t, item.out, toMap(item.in))
		})
	}
}
