// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlserverreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver"

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

const (
	includeDatabaseParam = "includeDatabase"
	excludeDatabaseParam = "excludeDatabase"
)

// databaseFilterPlaceholder matches the {database_filter <keyword> <expression>}
// placeholder a query template puts where the database filter belongs: keyword
// joins the filter condition to the query, and expression gives the database
// name of a row.
var databaseFilterPlaceholder = regexp.MustCompile(`\{database_filter (WHERE|AND) ([^}]+)\}`)

// databaseFilter decides which databases are reported on, from the databases and
// exclude_databases settings. Each setting lists name patterns, in which `*`
// matches any run of characters and `?` exactly one character. Names match
// case-insensitively, as they do under the default SQL Server collation.
type databaseFilter struct {
	include []databasePattern
	exclude []databasePattern
}

// databasePattern is a lowercased name pattern, translated to a LIKE pattern for
// the queries and to a regular expression for the rows filtered as they are
// recorded, so both agree on which databases match.
type databasePattern struct {
	like   string
	regexp *regexp.Regexp
}

func newDatabaseFilter(cfg *Config) databaseFilter {
	return databaseFilter{
		include: compilePatterns(cfg.Databases),
		exclude: compilePatterns(cfg.ExcludeDatabases),
	}
}

func compilePatterns(patterns []string) []databasePattern {
	compiled := make([]databasePattern, len(patterns))
	for i, pattern := range patterns {
		pattern = strings.ToLower(pattern)
		compiled[i] = databasePattern{
			like:   likePattern(pattern),
			regexp: regexp.MustCompile(namePattern(pattern)),
		}
	}
	return compiled
}

// likeEscaper escapes the characters LIKE treats as wildcards, and the escape
// character itself, with the escape character the conditions declare.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`, `[`, `\[`)

var likeWildcards = strings.NewReplacer("*", "%", "?", "_")

func likePattern(pattern string) string {
	return likeWildcards.Replace(likeEscaper.Replace(pattern))
}

func namePattern(pattern string) string {
	var b strings.Builder
	b.WriteString("(?s)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return b.String()
}

func matchesAny(patterns []databasePattern, database string) bool {
	for _, pattern := range patterns {
		if pattern.regexp.MatchString(database) {
			return true
		}
	}
	return false
}

// allows reports whether rows of the named database are reported on.
func (f databaseFilter) allows(database string) bool {
	database = strings.ToLower(database)
	if matchesAny(f.exclude, database) {
		return false
	}
	return len(f.include) == 0 || matchesAny(f.include, database)
}

// apply resolves the database filter placeholders of query into conditions that
// keep only the rows of allowed databases, so that the filter applies before
// TOP limits the rows. The patterns are bound to the parameters args returns.
// When every database is allowed the placeholders are removed.
func (f databaseFilter) apply(query string) string {
	return databaseFilterPlaceholder.ReplaceAllStringFunc(query, func(placeholder string) string {
		match := databaseFilterPlaceholder.FindStringSubmatch(placeholder)
		condition := f.condition(match[2])
		if condition == "" {
			return ""
		}
		return " " + match[1] + " " + condition
	})
}

func (f databaseFilter) condition(expression string) string {
	// A row whose database cannot be resolved has a NULL name, which NOT LIKE
	// would drop as well, so it is compared as an empty name: kept by
	// exclude_databases, dropped by databases.
	name := "LOWER(ISNULL(" + expression + ", N''))"
	var conditions []string
	if len(f.include) > 0 {
		conditions = append(conditions, likeAny(name, includeDatabaseParam, len(f.include)))
	}
	if len(f.exclude) > 0 {
		conditions = append(conditions, "NOT "+likeAny(name, excludeDatabaseParam, len(f.exclude)))
	}
	return strings.Join(conditions, " AND ")
}

func likeAny(name, prefix string, count int) string {
	likes := make([]string, count)
	for i := range likes {
		likes[i] = fmt.Sprintf(`%s LIKE @%s%d ESCAPE '\'`, name, prefix, i)
	}
	return "(" + strings.Join(likes, " OR ") + ")"
}

// args binds the LIKE patterns to the parameters of the conditions apply
// writes. It is empty when every database is allowed.
func (f databaseFilter) args() []any {
	args := make([]any, 0, len(f.include)+len(f.exclude))
	for i, pattern := range f.include {
		args = append(args, sql.Named(fmt.Sprintf("%s%d", includeDatabaseParam, i), pattern.like))
	}
	for i, pattern := range f.exclude {
		args = append(args, sql.Named(fmt.Sprintf("%s%d", excludeDatabaseParam, i), pattern.like))
	}
	return args
}
