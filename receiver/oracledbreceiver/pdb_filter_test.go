// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oracledbreceiver

import (
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver/internal/metadata"
)

func TestPDBFilterAllows(t *testing.T) {
	tests := []struct {
		name     string
		include  []string
		exclude  []string
		allowed  []string
		rejected []string
	}{
		{
			name:    "no filter allows every container",
			allowed: []string{"CDB$ROOT", "PDB1"},
		},
		{
			name:     "include keeps only the listed containers",
			include:  []string{"PDB1", "PDB2"},
			allowed:  []string{"PDB1", "PDB2"},
			rejected: []string{"CDB$ROOT", "PDB3"},
		},
		{
			name:     "exclude drops the listed containers",
			exclude:  []string{"PDB$SEED"},
			allowed:  []string{"CDB$ROOT", "PDB1"},
			rejected: []string{"PDB$SEED"},
		},
		{
			name:     "exclude wins over include",
			include:  []string{"PDB1", "PDB2"},
			exclude:  []string{"PDB2"},
			allowed:  []string{"PDB1"},
			rejected: []string{"PDB2", "PDB3"},
		},
		{
			name:     "names match case-insensitively",
			include:  []string{"pdb1"},
			exclude:  []string{"Pdb2"},
			allowed:  []string{"PDB1", "pdb1"},
			rejected: []string{"PDB2"},
		},
		{
			name:     "a name without wildcards matches exactly",
			include:  []string{"PDB$SEED"},
			allowed:  []string{"PDB$SEED", "pdb$seed"},
			rejected: []string{"PDB$SEED2", "PDBXSEED", "CDB$ROOT"},
		},
		{
			name:     "trailing star matches a prefix",
			include:  []string{"sales*"},
			allowed:  []string{"SALES", "SALES_EU", "sales2"},
			rejected: []string{"PRESALES", "SALE"},
		},
		{
			name:     "leading star matches a suffix",
			include:  []string{"*SALES"},
			allowed:  []string{"SALES", "EU_SALES"},
			rejected: []string{"SALES_EU"},
		},
		{
			name:     "star on both sides matches a substring",
			include:  []string{"*SALES*"},
			allowed:  []string{"SALES", "EU_SALES_2", "PRESALES"},
			rejected: []string{"SALE", "S_ALES"},
		},
		{
			name:     "question mark matches exactly one character",
			include:  []string{"PDB?"},
			allowed:  []string{"PDB1", "PDBX", "PDB$"},
			rejected: []string{"PDB", "PDB12"},
		},
		{
			name:     "underscore and percent are literal",
			include:  []string{"SALES_EU", "100%"},
			allowed:  []string{"SALES_EU", "100%"},
			rejected: []string{"SALESXEU", "100", "1000"},
		},
		{
			name:     "backslash and quote are literal",
			include:  []string{`A\B*`, "IT'S"},
			allowed:  []string{`A\B`, `A\BC`, "IT'S"},
			rejected: []string{"AB", `A\\B`, "ITS"},
		},
		{
			name:     "exclude wins over include with patterns",
			include:  []string{"SALES*"},
			exclude:  []string{"*_TEST", "SALES?"},
			allowed:  []string{"SALES", "SALES_EU"},
			rejected: []string{"SALES_TEST", "SALES1", "HR"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := newPDBFilter(&Config{PDBs: tt.include, ExcludePDBs: tt.exclude})
			for _, pdb := range tt.allowed {
				assert.True(t, filter.allows(pdb), "container %q should be allowed", pdb)
			}
			for _, pdb := range tt.rejected {
				assert.False(t, filter.allows(pdb), "container %q should be rejected", pdb)
			}
		})
	}
}

func TestPDBFilterApply(t *testing.T) {
	const query = "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER'{pdb_filter}\nFETCH FIRST :1 ROWS ONLY"
	tests := []struct {
		name     string
		filter   pdbFilter
		expected string
	}{
		{
			name:     "no filter removes the placeholder",
			expected: "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER'\nFETCH FIRST :1 ROWS ONLY",
		},
		{
			name:   "include only",
			filter: newPDBFilter(&Config{PDBs: []string{"pdb1", "PDB2"}}),
			expected: "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER'" +
				` AND (UPPER(C.NAME) LIKE 'PDB1' ESCAPE '\' OR UPPER(C.NAME) LIKE 'PDB2' ESCAPE '\')` + "\nFETCH FIRST :1 ROWS ONLY",
		},
		{
			name:   "exclude keeps rows outside any container",
			filter: newPDBFilter(&Config{ExcludePDBs: []string{"PDB$SEED"}}),
			expected: "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER'" +
				` AND (C.NAME IS NULL OR NOT (UPPER(C.NAME) LIKE 'PDB$SEED' ESCAPE '\'))` + "\nFETCH FIRST :1 ROWS ONLY",
		},
		{
			name:   "include and exclude, with a quote in a name",
			filter: newPDBFilter(&Config{PDBs: []string{"PDB1"}, ExcludePDBs: []string{"it's"}}),
			expected: "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER'" +
				` AND (UPPER(C.NAME) LIKE 'PDB1' ESCAPE '\') AND (C.NAME IS NULL OR NOT (UPPER(C.NAME) LIKE 'IT''S' ESCAPE '\'))` +
				"\nFETCH FIRST :1 ROWS ONLY",
		},
		{
			name:   "wildcards become LIKE wildcards and LIKE wildcards are escaped",
			filter: newPDBFilter(&Config{PDBs: []string{"sales*", "PDB?"}, ExcludePDBs: []string{`a_b%c\d`}}),
			expected: "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER'" +
				` AND (UPPER(C.NAME) LIKE 'SALES%' ESCAPE '\' OR UPPER(C.NAME) LIKE 'PDB_' ESCAPE '\')` +
				` AND (C.NAME IS NULL OR NOT (UPPER(C.NAME) LIKE 'A\_B\%C\\D' ESCAPE '\'))` +
				"\nFETCH FIRST :1 ROWS ONLY",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.filter.apply(query))
		})
	}
}

// TestPDBPatternLikeMatchesRegexp checks that the LIKE pattern filtering the
// event queries and the regexp filtering the metric rows give every container
// name the same verdict.
func TestPDBPatternLikeMatchesRegexp(t *testing.T) {
	patterns := []string{
		"PDB1", "PDB$SEED", "CDB$ROOT", "SALES*", "*SALES", "*SALES*", "PDB?", "?DB*", "*",
		"SALES_EU", "100%", `A\B`, `A\*`, "IT'S", "*_*", "%", "_", `\`, `\%`, "**", "??",
	}
	names := []string{
		"PDB1", "PDB12", "PDB", "PDB$SEED", "PDBXSEED", "CDB$ROOT", "SALES", "SALES_EU", "SALESXEU",
		"EU_SALES", "PRESALES2", "100%", "100", "1000", `A\B`, `A\BC`, "AB", "IT'S", "ITS",
		"%", "_", "X", `\`, `\%`, "XY",
	}
	for _, pattern := range patterns {
		p := newPDBPattern(pattern)
		for _, name := range names {
			assert.Equal(t, likeMatches(t, p.like, name), p.re.MatchString(name),
				"pattern %q (LIKE %q) and name %q", pattern, p.like, name)
		}
	}
}

// likeMatches evaluates name LIKE pattern ESCAPE '\' as Oracle does.
func likeMatches(t *testing.T, pattern, name string) bool {
	type token struct {
		r         rune
		any, many bool
	}
	var tokens []token
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '%':
			tokens = append(tokens, token{many: true})
		case '_':
			tokens = append(tokens, token{any: true})
		case '\\':
			// Oracle rejects an escape character before any other character.
			i++
			require.Less(t, i, len(runes), "LIKE pattern %q ends with the escape character", pattern)
			require.Contains(t, `%_\`, string(runes[i]), "LIKE pattern %q escapes an ordinary character", pattern)
			tokens = append(tokens, token{r: runes[i]})
		default:
			tokens = append(tokens, token{r: runes[i]})
		}
	}
	var match func(tokens []token, name []rune) bool
	match = func(tokens []token, name []rune) bool {
		if len(tokens) == 0 {
			return len(name) == 0
		}
		switch tok := tokens[0]; {
		case tok.many:
			for i := 0; i <= len(name); i++ {
				if match(tokens[1:], name[i:]) {
					return true
				}
			}
			return false
		case len(name) == 0:
			return false
		case tok.any || tok.r == name[0]:
			return match(tokens[1:], name[1:])
		default:
			return false
		}
	}
	return match(tokens, []rune(name))
}

// TestPDBFilteredEventQueries checks that every event query puts the filter at
// the end of its WHERE clause, before FETCH FIRST limits the rows.
func TestPDBFilteredEventQueries(t *testing.T) {
	filter := newPDBFilter(&Config{ExcludePDBs: []string{"PDB2"}})
	const condition = ` AND (C.NAME IS NULL OR NOT (UPPER(C.NAME) LIKE 'PDB2' ESCAPE '\'))`
	queries := map[string]string{
		"top query":           oracleQueryMetricsSQL,
		"top query (CDB)":     oracleQueryMetricsCDBSQL,
		"top procedure":       oracleProcedureMetricsSQL,
		"top procedure (CDB)": oracleProcedureMetricsCDBSQL,
		"query sample":        samplesQuery,
		"query sample (CDB)":  samplesCDBQuery,
		"session wait event":  sessionEventQuery,
	}
	for name, query := range queries {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, 1, strings.Count(query, pdbFilterPlaceholder))
			rendered := filter.apply(query)
			assert.NotContains(t, rendered, pdbFilterPlaceholder)
			conditionAt := strings.Index(rendered, condition)
			require.Positive(t, conditionAt)
			assert.Less(t, conditionAt, strings.Index(rendered, "FETCH FIRST"))
			if groupBy := strings.Index(rendered, "\nGROUP BY"); groupBy >= 0 {
				assert.Less(t, conditionAt, groupBy, "the filter must apply to rows before they are grouped")
			}
		})
	}
}

func TestPDBFilterBuildsFilteredEventQueries(t *testing.T) {
	for _, useCDB := range []bool{false, true} {
		s := &oracleScraper{
			useCDBProceduresView:  useCDB,
			useCDBDictionaryViews: useCDB,
			pdbFilter:             newPDBFilter(&Config{PDBs: []string{"PDB1"}}),
		}
		for _, query := range []string{s.buildTopQuerySQL(), s.buildProcedureMetricsSQL(), s.buildQuerySampleSQL()} {
			assert.Contains(t, query, ` AND (UPPER(C.NAME) LIKE 'PDB1' ESCAPE '\')`)
		}
	}
}

// pdbFilterTestRows answers the per-PDB queries of a CDB-root scrape with rows
// for PDB1, PDB2 and, where the query has them, the whole CDB.
var pdbFilterTestRows = map[string][]metricRow{
	statsCDBSQL: {
		{"NAME": executeCount, "VALUE": "10", "PDB_NAME": "PDB1"},
		{"NAME": executeCount, "VALUE": "20", "PDB_NAME": "PDB2"},
	},
	sessionCountCDBSQL: {
		{"VALUE": "1", "STATUS": "ACTIVE", "TYPE": "USER", "PDB_NAME": "PDB1"},
		{"VALUE": "2", "STATUS": "ACTIVE", "TYPE": "USER", "PDB_NAME": "PDB2"},
		{"VALUE": "3", "STATUS": "ACTIVE", "TYPE": "BACKGROUND", "PDB_NAME": ""},
	},
	tablespaceUsageCDBSQL: {
		{"PDB_NAME": "PDB1", "TABLESPACE_NAME": "USERS", "USED_SPACE": "1", "TABLESPACE_SIZE": "10", "BLOCK_SIZE": "8192", "STATUS": "ONLINE"},
		{"PDB_NAME": "PDB2", "TABLESPACE_NAME": "USERS", "USED_SPACE": "2", "TABLESPACE_SIZE": "10", "BLOCK_SIZE": "8192", "STATUS": "ONLINE"},
	},
	sysmetricCDBSQL: {
		{"METRIC_NAME": sysmetricBufferCacheHitRatio, "VALUE": "91", "PDB_NAME": "PDB1"},
		{"METRIC_NAME": sysmetricBufferCacheHitRatio, "VALUE": "92", "PDB_NAME": "PDB2"},
	},
	sysmetricSQL: {
		{"METRIC_NAME": sysmetricBufferCacheHitRatio, "VALUE": "99"},
	},
}

// reportedPDBs returns, per metric name, the sorted oracle.db.pdb values of its
// data points, with "" for a data point without the attribute.
func reportedPDBs(md pmetric.Metrics) map[string][]string {
	pdbs := map[string][]string{}
	add := func(name string, attrs pcommon.Map) {
		pdb := ""
		if v, ok := attrs.Get("oracle.db.pdb"); ok {
			pdb = v.Str()
		}
		pdbs[name] = append(pdbs[name], pdb)
	}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		scopeMetrics := md.ResourceMetrics().At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metrics := scopeMetrics.At(j).Metrics()
			for k := 0; k < metrics.Len(); k++ {
				m := metrics.At(k)
				switch m.Type() {
				case pmetric.MetricTypeGauge:
					for l := 0; l < m.Gauge().DataPoints().Len(); l++ {
						add(m.Name(), m.Gauge().DataPoints().At(l).Attributes())
					}
				case pmetric.MetricTypeSum:
					for l := 0; l < m.Sum().DataPoints().Len(); l++ {
						add(m.Name(), m.Sum().DataPoints().At(l).Attributes())
					}
				}
			}
		}
	}
	for name := range pdbs {
		slices.Sort(pdbs[name])
	}
	return pdbs
}

func TestPDBFilterCDBRootMetrics(t *testing.T) {
	tests := []struct {
		name     string
		include  []string
		exclude  []string
		expected map[string][]string
	}{
		{
			name: "no filter",
			expected: map[string][]string{
				"oracledb.executions":               {"PDB1", "PDB2"},
				"oracledb.sessions.usage":           {"", "PDB1", "PDB2"},
				"oracledb.tablespace_size.usage":    {"PDB1", "PDB2"},
				"oracledb.buffer_cache.utilization": {"PDB1", "PDB2"},
			},
		},
		{
			name:    "include",
			include: []string{"pdb1"},
			expected: map[string][]string{
				"oracledb.executions":               {"PDB1"},
				"oracledb.sessions.usage":           {"", "PDB1"},
				"oracledb.tablespace_size.usage":    {"PDB1"},
				"oracledb.buffer_cache.utilization": {"PDB1"},
			},
		},
		{
			name:    "patterns",
			include: []string{"pdb*"},
			exclude: []string{"*2"},
			expected: map[string][]string{
				"oracledb.executions":               {"PDB1"},
				"oracledb.sessions.usage":           {"", "PDB1"},
				"oracledb.tablespace_size.usage":    {"PDB1"},
				"oracledb.buffer_cache.utilization": {"PDB1"},
			},
		},
		{
			// Every per-PDB buffer cache row is excluded: the instance-wide
			// V$SYSMETRIC value must not take their place.
			name:    "exclude every PDB",
			exclude: []string{"PDB1", "PDB2"},
			expected: map[string][]string{
				"oracledb.sessions.usage": {""},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := metadata.NewDefaultMetricsBuilderConfig()
			cfg.Metrics = metadata.MetricsConfig{}
			cfg.Metrics.OracledbExecutions.Enabled = true
			cfg.Metrics.OracledbExecutions.EnabledAttributes = []metadata.OracledbExecutionsMetricAttributeKey{
				metadata.OracledbExecutionsMetricAttributeKeyOracleDbPdb,
			}
			cfg.Metrics.OracledbSessionsUsage.Enabled = true
			cfg.Metrics.OracledbSessionsUsage.EnabledAttributes = append(cfg.Metrics.OracledbSessionsUsage.EnabledAttributes,
				metadata.OracledbSessionsUsageMetricAttributeKeyOracleDbPdb)
			cfg.Metrics.OracledbTablespaceSizeUsage.Enabled = true
			cfg.Metrics.OracledbTablespaceSizeUsage.EnabledAttributes = append(cfg.Metrics.OracledbTablespaceSizeUsage.EnabledAttributes,
				metadata.OracledbTablespaceSizeUsageMetricAttributeKeyOracleDbPdb)
			cfg.Metrics.OracledbBufferCacheUtilization.Enabled = true
			cfg.Metrics.OracledbBufferCacheUtilization.EnabledAttributes = []metadata.OracledbBufferCacheUtilizationMetricAttributeKey{
				metadata.OracledbBufferCacheUtilizationMetricAttributeKeyOracleDbPdb,
			}

			s := oracleScraper{
				logger:         zap.NewNop(),
				mb:             metadata.NewMetricsBuilder(cfg, receivertest.NewNopSettings(metadata.Type)),
				dbProviderFunc: func() (*sql.DB, error) { return nil, nil },
				clientProviderFunc: func(_ *sql.DB, query string, _ *zap.Logger) dbClient {
					return &fakeDbClient{Responses: [][]metricRow{pdbFilterTestRows[query]}}
				},
				id:                   component.ID{},
				metricsBuilderConfig: cfg,
				instanceInfo:         oracleInstanceInfo{isCDB: true},
				pdbFilter:            newPDBFilter(&Config{PDBs: tt.include, ExcludePDBs: tt.exclude}),
			}
			require.NoError(t, s.start(t.Context(), componenttest.NewNopHost()))
			defer func() { assert.NoError(t, s.shutdown(t.Context())) }()
			require.True(t, s.isCDBRoot)

			md, err := s.scrape(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tt.expected, reportedPDBs(md))
		})
	}
}

func TestPDBFilterKeepsDirectPDBMetrics(t *testing.T) {
	s := &oracleScraper{
		instanceInfo: oracleInstanceInfo{isCDB: true, connectedToPDB: true, pdbName: "PDB1"},
		pdbFilter:    newPDBFilter(&Config{ExcludePDBs: []string{"PDB1"}}),
	}
	// Every row of a direct-PDB connection describes the database the receiver
	// is connected to, including the V$CON_SYSMETRIC rows that carry its name.
	assert.False(t, s.excludesPDBRow(metricRow{"NAME": executeCount, "VALUE": "1"}))
	assert.False(t, s.excludesPDBRow(metricRow{"PDB_NAME": "pdb1"}))

	s.isCDBRoot = true
	assert.True(t, s.excludesPDBRow(metricRow{"PDB_NAME": "pdb1"}))
}
