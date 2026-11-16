// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mysqlreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver"

import (
	"regexp"
	"strings"
)

// likeEscape is the escape character of the LIKE patterns the filter writes. It
// is bound as a parameter rather than written as the literal '\\', which the
// server rejects when the NO_BACKSLASH_ESCAPES SQL mode is enabled.
const likeEscape = `\`

// likePatternReplacer turns a database pattern into a LIKE pattern in a single
// pass, so the % and _ that * and ? map to are not escaped again.
var likePatternReplacer = strings.NewReplacer(
	`\`, `\\`,
	`%`, `\%`,
	`_`, `\_`,
	`*`, `%`,
	`?`, `_`,
)

// databaseFilter decides which databases (schemas) are reported on, from the
// databases and exclude_databases settings. Names match case-insensitively, *
// matches any run of characters and ? matches a single character.
type databaseFilter struct {
	include []databasePattern
	exclude []databasePattern
}

// databasePattern is a pattern of the databases or exclude_databases settings,
// compiled to the regexp metric rows are matched with and the LIKE pattern
// query rows are matched with.
type databasePattern struct {
	regexp *regexp.Regexp
	like   string
}

func newDatabaseFilter(cfg *Config) databaseFilter {
	return databaseFilter{
		include: newDatabasePatterns(cfg.Databases),
		exclude: newDatabasePatterns(cfg.ExcludeDatabases),
	}
}

func newDatabasePatterns(patterns []string) []databasePattern {
	compiled := make([]databasePattern, len(patterns))
	for i, pattern := range patterns {
		compiled[i] = newDatabasePattern(pattern)
	}
	return compiled
}

func newDatabasePattern(pattern string) databasePattern {
	expr := regexp.QuoteMeta(pattern)
	expr = strings.ReplaceAll(expr, `\*`, ".*")
	expr = strings.ReplaceAll(expr, `\?`, ".")
	return databasePattern{
		regexp: regexp.MustCompile("(?is)^" + expr + "$"),
		like:   likePattern(pattern),
	}
}

// likePattern converts a database pattern to the LIKE pattern, declared with
// ESCAPE '\', that matches the same lowercased names.
func likePattern(pattern string) string {
	return strings.ToLower(likePatternReplacer.Replace(pattern))
}

// allows reports whether rows of the named database are reported on. A row
// without a database is matched as an empty name.
func (f databaseFilter) allows(database string) bool {
	if matchesAny(f.exclude, database) {
		return false
	}
	return len(f.include) == 0 || matchesAny(f.include, database)
}

func matchesAny(patterns []databasePattern, database string) bool {
	for _, pattern := range patterns {
		if pattern.regexp.MatchString(database) {
			return true
		}
	}
	return false
}

// condition returns a condition that keeps only the rows whose database,
// given by expression, is allowed, so that a query can filter before its LIMIT.
// The patterns are bound to the parameters args returns. It is empty when every
// database is allowed.
func (f databaseFilter) condition(expression string) string {
	// A NULL database is compared as an empty name, as allows does. The name is
	// compared under a binary collation so that, as in allows, only case is
	// ignored: the default collations would also ignore accents.
	name := "LOWER(CONVERT(COALESCE(" + expression + ", '') USING utf8mb4)) COLLATE utf8mb4_bin"
	var conditions []string
	if len(f.include) > 0 {
		conditions = append(conditions, likeAny(name, len(f.include)))
	}
	if len(f.exclude) > 0 {
		conditions = append(conditions, "NOT "+likeAny(name, len(f.exclude)))
	}
	return strings.Join(conditions, " AND ")
}

func likeAny(name string, count int) string {
	likes := make([]string, count)
	for i := range likes {
		likes[i] = name + " LIKE ? ESCAPE ?"
	}
	return "(" + strings.Join(likes, " OR ") + ")"
}

// args binds the patterns to the parameters of a condition, so a query can hold
// only one. It is empty when every database is allowed.
func (f databaseFilter) args() []any {
	args := make([]any, 0, 2*(len(f.include)+len(f.exclude)))
	for _, pattern := range f.include {
		args = append(args, pattern.like, likeEscape)
	}
	for _, pattern := range f.exclude {
		args = append(args, pattern.like, likeEscape)
	}
	return args
}
