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
			name:     "include only",
			filter:   newPDBFilter(&Config{PDBs: []string{"pdb1", "PDB2"}}),
			expected: "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER' AND UPPER(C.NAME) IN ('PDB1', 'PDB2')\nFETCH FIRST :1 ROWS ONLY",
		},
		{
			name:     "exclude keeps rows outside any container",
			filter:   newPDBFilter(&Config{ExcludePDBs: []string{"PDB$SEED"}}),
			expected: "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER' AND (C.NAME IS NULL OR UPPER(C.NAME) NOT IN ('PDB$SEED'))\nFETCH FIRST :1 ROWS ONLY",
		},
		{
			name:   "include and exclude, with a quote in a name",
			filter: newPDBFilter(&Config{PDBs: []string{"PDB1"}, ExcludePDBs: []string{"it's"}}),
			expected: "SELECT C.NAME FROM V$SESSION S LEFT JOIN V$CONTAINERS C ON C.CON_ID = S.CON_ID WHERE S.TYPE = 'USER'" +
				" AND UPPER(C.NAME) IN ('PDB1') AND (C.NAME IS NULL OR UPPER(C.NAME) NOT IN ('IT''S'))\nFETCH FIRST :1 ROWS ONLY",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.filter.apply(query))
		})
	}
}

// TestPDBFilteredEventQueries checks that every event query puts the filter at
// the end of its WHERE clause, before FETCH FIRST limits the rows.
func TestPDBFilteredEventQueries(t *testing.T) {
	filter := newPDBFilter(&Config{ExcludePDBs: []string{"PDB2"}})
	const condition = " AND (C.NAME IS NULL OR UPPER(C.NAME) NOT IN ('PDB2'))"
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
			assert.Contains(t, query, "AND UPPER(C.NAME) IN ('PDB1')")
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
	// Rows of a direct-PDB connection carry no PDB_NAME: they describe the
	// database the receiver is connected to.
	assert.False(t, s.excludesPDBRow(metricRow{"NAME": executeCount, "VALUE": "1"}))
	assert.True(t, s.excludesPDBRow(metricRow{"PDB_NAME": "pdb1"}))
}
