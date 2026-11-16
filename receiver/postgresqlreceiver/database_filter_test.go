// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDatabaseFilterMatches(t *testing.T) {
	tests := []struct {
		name     string
		entries  []string
		matching []string
		other    []string
	}{
		{
			name:     "exact name",
			entries:  []string{"sales"},
			matching: []string{"sales"},
			other:    []string{"Sales", "sales1", "presales", ""},
		},
		{
			name:     "prefix",
			entries:  []string{"sales*"},
			matching: []string{"sales", "sales_eu", "sales*"},
			other:    []string{"presales", "Sales_eu"},
		},
		{
			name:     "suffix",
			entries:  []string{"*sales"},
			matching: []string{"sales", "presales"},
			other:    []string{"sales_eu"},
		},
		{
			name:     "contains",
			entries:  []string{"*sales*"},
			matching: []string{"sales", "presales_eu"},
			other:    []string{"sale", "SALES"},
		},
		{
			name:     "single characters",
			entries:  []string{"sales_??"},
			matching: []string{"sales_eu", "sales_ü1"},
			other:    []string{"sales_e", "sales_eur", "salesXeu"},
		},
		{
			name:     "underscore is literal",
			entries:  []string{"a_b*"},
			matching: []string{"a_b", "a_bc"},
			other:    []string{"axb", "axbc"},
		},
		{
			name:     "percent is literal",
			entries:  []string{"100%*"},
			matching: []string{"100%", "100%x"},
			other:    []string{"100", "1000"},
		},
		{
			name:     "backslash is literal",
			entries:  []string{`a\*`},
			matching: []string{`a\`, `a\b`},
			other:    []string{"a", "ab"},
		},
		{
			name:     "regexp metacharacters are literal",
			entries:  []string{"a.b(c)+*"},
			matching: []string{"a.b(c)+", "a.b(c)+d"},
			other:    []string{"axb(c)+", "a.bcc"},
		},
		{
			name:     "wildcards match newlines",
			entries:  []string{"a*b?"},
			matching: []string{"a\nb\n"},
		},
		{
			name:     "literal names keep exact matching alongside patterns",
			entries:  []string{"otel", "tmp?"},
			matching: []string{"otel", "tmp1"},
			other:    []string{"otel2", "Otel", "tmp"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newDatabaseFilter(tc.entries)
			for _, db := range tc.matching {
				assert.True(t, f.matches(db), "%q should match %q", tc.entries, db)
			}
			for _, db := range tc.other {
				assert.False(t, f.matches(db), "%q should not match %q", tc.entries, db)
			}
		})
	}
}

func TestDatabaseFilterHasPatterns(t *testing.T) {
	assert.False(t, newDatabaseFilter(nil).hasPatterns())
	assert.False(t, newDatabaseFilter([]string{"otel", "a_b", "100%"}).hasPatterns())
	assert.True(t, newDatabaseFilter([]string{"otel", "otel?"}).hasPatterns())
	assert.True(t, newDatabaseFilter([]string{"*"}).hasPatterns())
}

func TestLikePattern(t *testing.T) {
	tests := map[string]string{
		"sales*":   "sales%",
		"*sales":   "%sales",
		"*sales*":  "%sales%",
		"sales_??": `sales\___`,
		"100%*":    `100\%%`,
		`a\b?`:     `a\\b_`,
		"*":        "%",
	}
	for pattern, expected := range tests {
		assert.Equal(t, expected, likePattern(pattern), pattern)
	}
}

func TestQuoteLikePatterns(t *testing.T) {
	assert.Equal(t,
		[]string{"'sales%'", `E'sales\\___'`, `E'it''s\\\\%'`},
		quoteLikePatterns([]string{"sales*", "sales_??", `it's\*`}),
	)
}

// TestDatabaseFilterAgreesWithLike checks that the Go matcher and the LIKE
// translation used for server-side filtering give every name the same verdict.
func TestDatabaseFilterAgreesWithLike(t *testing.T) {
	patterns := []string{
		"sales*", "*sales", "*sales*", "sales_??", "a_b*", "100%*", `a\*`, `*\`,
		"*_*", "?", "??*", "*%*", "a*b*c", "Sales*", "ü?",
	}
	names := []string{
		"", "a", "sales", "Sales", "sales_eu", "salesXeu", "presales", "sales_e",
		"a_b", "axb", "a_bc", "100%", "100", "1000", `a\`, `a\b`, `\`, "ab",
		"x_y", "xy", "%", "abc", "aXbYc", "acb", "ü1", "üü", "u1", "a\nb",
	}
	for _, pattern := range patterns {
		f := newDatabaseFilter([]string{pattern})
		like := likePattern(pattern)
		for _, name := range names {
			assert.Equal(t, likeMatch(like, name), f.matches(name),
				"pattern %q (LIKE %q) disagrees on %q", pattern, like, name)
		}
	}
}

// likeMatch evaluates a PostgreSQL LIKE pattern with ESCAPE '\' against s,
// treating both as sequences of characters as PostgreSQL does for UTF-8.
func likeMatch(pattern, s string) bool {
	return likeMatchRunes([]rune(pattern), []rune(s))
}

func likeMatchRunes(p, s []rune) bool {
	if len(p) == 0 {
		return len(s) == 0
	}
	switch p[0] {
	case '%':
		for i := 0; i <= len(s); i++ {
			if likeMatchRunes(p[1:], s[i:]) {
				return true
			}
		}
		return false
	case '_':
		return len(s) > 0 && likeMatchRunes(p[1:], s[1:])
	case '\\':
		p = p[1:]
		if len(p) == 0 {
			return false
		}
	}
	return len(s) > 0 && s[0] == p[0] && likeMatchRunes(p[1:], s[1:])
}
