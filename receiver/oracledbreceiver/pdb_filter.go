// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oracledbreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver"

import (
	"regexp"
	"strings"
)

// pdbFilterPlaceholder marks the end of the WHERE clause of an event query
// template, whose rows carry their container name in C.NAME.
const pdbFilterPlaceholder = "{pdb_filter}"

// pdbFilter decides which containers are reported on, from the pdbs and
// exclude_pdbs settings. Names match case-insensitively; Oracle stores the
// names of containers created without quotes in upper case.
type pdbFilter struct {
	include []pdbPattern
	exclude []pdbPattern
}

func newPDBFilter(cfg *Config) pdbFilter {
	return pdbFilter{
		include: newPDBPatterns(cfg.PDBs),
		exclude: newPDBPatterns(cfg.ExcludePDBs),
	}
}

// pdbPattern is a container name in which * matches any run of characters
// and ? matches exactly one character. Every other character is literal.
type pdbPattern struct {
	// like is the upper-case pattern for a LIKE condition with ESCAPE '\'.
	like string
	// re matches the upper-case names the pattern matches.
	re *regexp.Regexp
}

func newPDBPatterns(names []string) []pdbPattern {
	patterns := make([]pdbPattern, len(names))
	for i, name := range names {
		patterns[i] = newPDBPattern(name)
	}
	return patterns
}

func newPDBPattern(name string) pdbPattern {
	var like, re strings.Builder
	re.WriteString(`(?s)^`)
	for _, r := range strings.ToUpper(name) {
		switch r {
		case '*':
			like.WriteRune('%')
			re.WriteString(".*")
		case '?':
			like.WriteRune('_')
			re.WriteRune('.')
		case '\\', '%', '_':
			like.WriteRune('\\')
			like.WriteRune(r)
			re.WriteString(regexp.QuoteMeta(string(r)))
		default:
			like.WriteRune(r)
			re.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	re.WriteRune('$')
	return pdbPattern{like: like.String(), re: regexp.MustCompile(re.String())}
}

func matchesAny(patterns []pdbPattern, container string) bool {
	for _, p := range patterns {
		if p.re.MatchString(container) {
			return true
		}
	}
	return false
}

// allows reports whether rows of the named container are reported on.
func (f pdbFilter) allows(container string) bool {
	container = strings.ToUpper(container)
	if matchesAny(f.exclude, container) {
		return false
	}
	return len(f.include) == 0 || matchesAny(f.include, container)
}

// apply resolves the placeholder of query into a condition that keeps only the
// rows of allowed containers, so that the filter applies before FETCH FIRST
// limits the rows. When every container is allowed the placeholder is removed.
func (f pdbFilter) apply(query string) string {
	return strings.ReplaceAll(query, pdbFilterPlaceholder, f.condition())
}

func (f pdbFilter) condition() string {
	var condition string
	if len(f.include) > 0 {
		condition += " AND " + likeAny(f.include)
	}
	// A session outside any container has a NULL name, which NOT LIKE would
	// drop as well. Oracle treats '' as NULL, so NVL cannot substitute an empty
	// name.
	if len(f.exclude) > 0 {
		condition += " AND (C.NAME IS NULL OR NOT " + likeAny(f.exclude) + ")"
	}
	return condition
}

// likeAny renders a condition that holds when C.NAME matches any of patterns.
// The patterns are Oracle string literals rather than bind parameters because
// go-ora binds by position and the event queries already use :1 and :2.
func likeAny(patterns []pdbPattern) string {
	likes := make([]string, len(patterns))
	for i, p := range patterns {
		likes[i] = "UPPER(C.NAME) LIKE '" + strings.ReplaceAll(p.like, "'", "''") + "' ESCAPE '\\'"
	}
	return "(" + strings.Join(likes, " OR ") + ")"
}

// excludesPDBRow reports whether a row of a per-PDB query of a CDB-root
// connection belongs to a container the filter leaves out. A row without
// PDB_NAME describes the whole CDB and is kept. Rows of any other connection
// describe the database the receiver is connected to, even when they carry the
// container name, and are kept too.
func (s *oracleScraper) excludesPDBRow(row metricRow) bool {
	name := row["PDB_NAME"]
	return s.isCDBRoot && name != "" && !s.pdbFilter.allows(name)
}
