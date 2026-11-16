// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package postgresqlreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver"

import (
	"regexp"
	"strings"

	"github.com/lib/pq"
)

// isDatabasePattern reports whether a databases/exclude_databases entry
// contains a wildcard: `*` matches any run of characters (including none) and
// `?` matches exactly one character. Every other character is literal.
func isDatabasePattern(entry string) bool {
	return strings.ContainsAny(entry, "*?")
}

// splitDatabasePatterns separates literal database names from wildcard patterns,
// preserving the configured order of each.
func splitDatabasePatterns(entries []string) (literals, patterns []string) {
	for _, entry := range entries {
		if isDatabasePattern(entry) {
			patterns = append(patterns, entry)
		} else {
			literals = append(literals, entry)
		}
	}
	return literals, patterns
}

// databaseFilter matches database names against databases/exclude_databases
// entries. Matching is case-sensitive, like PostgreSQL database names.
type databaseFilter struct {
	literals map[string]struct{}
	patterns []*regexp.Regexp
}

func newDatabaseFilter(entries []string) databaseFilter {
	literals, patterns := splitDatabasePatterns(entries)
	f := databaseFilter{literals: make(map[string]struct{}, len(literals))}
	for _, literal := range literals {
		f.literals[literal] = struct{}{}
	}
	for _, pattern := range patterns {
		f.patterns = append(f.patterns, compileDatabasePattern(pattern))
	}
	return f
}

// compileDatabasePattern compiles a wildcard pattern to an anchored regexp.
func compileDatabasePattern(pattern string) *regexp.Regexp {
	expr := regexp.QuoteMeta(pattern)
	expr = strings.ReplaceAll(expr, `\*`, ".*")
	expr = strings.ReplaceAll(expr, `\?`, ".")
	// (?s) lets the wildcards match newlines, as LIKE's % and _ do.
	return regexp.MustCompile(`(?s)\A` + expr + `\z`)
}

func (f databaseFilter) hasPatterns() bool {
	return len(f.patterns) > 0
}

func (f databaseFilter) matches(database string) bool {
	if _, ok := f.literals[database]; ok {
		return true
	}
	return f.matchesPattern(database)
}

func (f databaseFilter) matchesPattern(database string) bool {
	for _, re := range f.patterns {
		if re.MatchString(database) {
			return true
		}
	}
	return false
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// likePattern translates a wildcard pattern to a LIKE pattern for use with
// ESCAPE '\': LIKE metacharacters are escaped first so they match literally.
func likePattern(pattern string) string {
	escaped := likeEscaper.Replace(pattern)
	return strings.NewReplacer("*", "%", "?", "_").Replace(escaped)
}

// quoteLikePatterns renders wildcard patterns as quoted LIKE patterns.
func quoteLikePatterns(patterns []string) []string {
	quoted := make([]string, len(patterns))
	for i, pattern := range patterns {
		// QuoteLiteral prefixes E-strings with a space; drop it for tidier SQL.
		quoted[i] = strings.TrimSpace(pq.QuoteLiteral(likePattern(pattern)))
	}
	return quoted
}
