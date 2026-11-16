// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oracledbreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver"

import (
	"slices"
	"strings"
)

// pdbFilterPlaceholder marks the end of the WHERE clause of an event query
// template, whose rows carry their container name in C.NAME.
const pdbFilterPlaceholder = "{pdb_filter}"

// pdbFilter decides which containers are reported on, from the pdbs and
// exclude_pdbs settings. Names match case-insensitively; Oracle stores the
// names of containers created without quotes in upper case.
type pdbFilter struct {
	include []string
	exclude []string
}

func newPDBFilter(cfg *Config) pdbFilter {
	return pdbFilter{
		include: upperAll(cfg.PDBs),
		exclude: upperAll(cfg.ExcludePDBs),
	}
}

func upperAll(names []string) []string {
	uppered := make([]string, len(names))
	for i, name := range names {
		uppered[i] = strings.ToUpper(name)
	}
	return uppered
}

// allows reports whether rows of the named container are reported on.
func (f pdbFilter) allows(container string) bool {
	container = strings.ToUpper(container)
	if slices.Contains(f.exclude, container) {
		return false
	}
	return len(f.include) == 0 || slices.Contains(f.include, container)
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
		condition += " AND UPPER(C.NAME) IN (" + quoteLiterals(f.include) + ")"
	}
	// A session outside any container has a NULL name, which NOT IN would drop
	// as well. Oracle treats '' as NULL, so NVL cannot substitute an empty name.
	if len(f.exclude) > 0 {
		condition += " AND (C.NAME IS NULL OR UPPER(C.NAME) NOT IN (" + quoteLiterals(f.exclude) + "))"
	}
	return condition
}

// quoteLiterals renders names as Oracle string literals for an IN list.
func quoteLiterals(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = "'" + strings.ReplaceAll(name, "'", "''") + "'"
	}
	return strings.Join(quoted, ", ")
}

// excludesPDBRow reports whether a row of a per-PDB query belongs to a
// container the filter leaves out. A row without PDB_NAME describes the whole
// instance and is kept.
func (s *oracleScraper) excludesPDBRow(row metricRow) bool {
	name := row["PDB_NAME"]
	return name != "" && !s.pdbFilter.allows(name)
}
