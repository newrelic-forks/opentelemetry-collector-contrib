// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mysqlreceiver

import (
	"database/sql/driver"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver/internal/metadata"
)

func TestDatabaseFilterAllows(t *testing.T) {
	tests := []struct {
		name     string
		include  []string
		exclude  []string
		allowed  []string
		rejected []string
	}{
		{
			name:    "no filter allows every database",
			allowed: []string{"mysql", "sales", ""},
		},
		{
			name:     "include keeps only the listed databases",
			include:  []string{"sales", "hr"},
			allowed:  []string{"sales", "hr"},
			rejected: []string{"mysql", ""},
		},
		{
			name:     "exclude drops the listed databases",
			exclude:  []string{"sys"},
			allowed:  []string{"mysql", "sales", ""},
			rejected: []string{"sys"},
		},
		{
			name:     "exclude wins over include",
			include:  []string{"sales", "hr"},
			exclude:  []string{"hr"},
			allowed:  []string{"sales"},
			rejected: []string{"hr", "mysql"},
		},
		{
			name:     "names match case-insensitively",
			include:  []string{"Sales"},
			exclude:  []string{"HR"},
			allowed:  []string{"sales", "SALES"},
			rejected: []string{"hr"},
		},
		{
			name:     "trailing star matches a prefix",
			include:  []string{"sales*"},
			allowed:  []string{"sales", "sales_eu", "SalesUS"},
			rejected: []string{"presales", "sale", ""},
		},
		{
			name:     "leading star matches a suffix",
			include:  []string{"*sales"},
			allowed:  []string{"sales", "presales", "EU-Sales"},
			rejected: []string{"sales_eu", "sale"},
		},
		{
			name:     "stars on both sides match a substring",
			include:  []string{"*sales*"},
			allowed:  []string{"sales", "presales", "sales_eu", "eu_sales_2"},
			rejected: []string{"sale", "s_ales"},
		},
		{
			name:     "question mark matches exactly one character",
			include:  []string{"sales_??"},
			allowed:  []string{"sales_eu", "sales_US", "sales_%\\", "sales_éü"},
			rejected: []string{"sales_e", "sales_eur", "sales-eu", "salesxeu"},
		},
		{
			name:    "star alone matches every database",
			include: []string{"*"},
			allowed: []string{"mysql", "sales", ""},
		},
		{
			name:     "underscore matches only itself",
			include:  []string{"sales_eu"},
			allowed:  []string{"sales_eu", "SALES_EU"},
			rejected: []string{"salesxeu", "sales_euro"},
		},
		{
			name:     "percent matches only itself",
			include:  []string{"100%"},
			allowed:  []string{"100%"},
			rejected: []string{"100", "1000", "100%x"},
		},
		{
			name:     "backslash matches only itself",
			include:  []string{`a\b*`},
			allowed:  []string{`a\b`, `a\bc`},
			rejected: []string{"ab", `a\\b`},
		},
		{
			name:     "regular expression characters match only themselves",
			include:  []string{"a.b+(c)[d]"},
			allowed:  []string{"a.b+(c)[d]"},
			rejected: []string{"axbb(c)d", "a.bb(c)[d]"},
		},
		{
			name:     "accents are not ignored",
			include:  []string{"café"},
			allowed:  []string{"café", "CAFÉ"},
			rejected: []string{"cafe"},
		},
		{
			name:     "exclude wins over include with patterns",
			include:  []string{"sales*", "hr"},
			exclude:  []string{"*_test", "sales_??"},
			allowed:  []string{"sales", "sales_prod", "hr"},
			rejected: []string{"sales_test", "sales_eu", "hr_test", "mysql"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := newDatabaseFilter(&Config{Databases: tt.include, ExcludeDatabases: tt.exclude})
			for _, db := range tt.allowed {
				assert.True(t, filter.allows(db), "database %q should be allowed", db)
			}
			for _, db := range tt.rejected {
				assert.False(t, filter.allows(db), "database %q should be rejected", db)
			}
		})
	}
}

func TestLikePattern(t *testing.T) {
	tests := map[string]string{
		"sales":    "sales",
		"Sales*":   "sales%",
		"*sales*":  "%sales%",
		"sales_??": `sales\___`,
		"100%":     `100\%`,
		`a\b`:      `a\\b`,
		`*\?_%*`:   `%\\_\_\%%`,
	}
	for pattern, expected := range tests {
		assert.Equal(t, expected, likePattern(pattern), "pattern %q", pattern)
	}
}

// likeMatches evaluates a LIKE pattern declared with ESCAPE '\', as MySQL does
// under a binary collation: % and _ are the only wildcards and _ matches one
// character, not one byte.
func likeMatches(t *testing.T, pattern, name string) bool {
	p, s := []rune(pattern), []rune(name)
	if len(p) == 0 {
		return len(s) == 0
	}
	switch p[0] {
	case '%':
		for i := 0; i <= len(s); i++ {
			if likeMatches(t, string(p[1:]), string(s[i:])) {
				return true
			}
		}
		return false
	case '_':
		return len(s) > 0 && likeMatches(t, string(p[1:]), string(s[1:]))
	case '\\':
		require.Greater(t, len(p), 1, "LIKE pattern %q ends with the escape character", pattern)
		p = p[1:]
	}
	return len(s) > 0 && s[0] == p[0] && likeMatches(t, string(p[1:]), string(s[1:]))
}

// TestDatabaseFilterAgreesWithLike checks that the rows filtered in Go and the
// rows filtered by the LIKE conditions of the queries agree on every name.
func TestDatabaseFilterAgreesWithLike(t *testing.T) {
	patterns := []string{
		"sales", "Sales*", "*sales", "*sales*", "sales_??", "?", "*", "100%", "[ab]db",
		`a\b`, `a\*`, "a.b", "a*b*c", "%", "_", `\`, "*_*", "x?y", "café", "caf?",
		"istanbul", "sales", "σ",
	}
	names := []string{
		"", "sales", "SALES", "presales", "sales_eu", "sales_e", "salesxeu", "sales_eur", "s",
		"100%", "1000", "[ab]db", "adb", `a\b`, `a\bc`, "ab", "a.b", "axb", "abc", "aXbYc",
		"%", "_", `\`, "x_y", "xy", "x%y", "mysql", "café", "CAFÉ", "cafe",
		"İstanbul", "ſales", "ς", "Σ",
	}
	for _, pattern := range patterns {
		filter := newDatabaseFilter(&Config{Databases: []string{pattern}})
		args := filter.args()
		require.Equal(t, []any{likePattern(pattern), likeEscape}, args)
		for _, name := range names {
			assert.Equal(t, likeMatches(t, args[0].(string), strings.ToLower(name)), filter.allows(name),
				"pattern %q (LIKE %q), database %q", pattern, args[0], name)
		}
	}
}

func TestDatabaseFilterCondition(t *testing.T) {
	const name = "LOWER(CONVERT(COALESCE(t.db, '') USING utf8mb4)) COLLATE utf8mb4_bin"
	tests := []struct {
		name      string
		filter    databaseFilter
		condition string
		args      []any
	}{
		{
			name: "no filter",
			args: []any{},
		},
		{
			name:      "include only",
			filter:    newDatabaseFilter(&Config{Databases: []string{"Sales", "hr"}}),
			condition: "(" + name + " LIKE ? ESCAPE ? OR " + name + " LIKE ? ESCAPE ?)",
			args:      []any{"sales", `\`, "hr", `\`},
		},
		{
			name:      "exclude only",
			filter:    newDatabaseFilter(&Config{ExcludeDatabases: []string{"sys"}}),
			condition: "NOT (" + name + " LIKE ? ESCAPE ?)",
			args:      []any{"sys", `\`},
		},
		{
			name:      "include and exclude",
			filter:    newDatabaseFilter(&Config{Databases: []string{"Sales*"}, ExcludeDatabases: []string{"it's_?"}}),
			condition: "(" + name + " LIKE ? ESCAPE ?) AND NOT (" + name + " LIKE ? ESCAPE ?)",
			args:      []any{"sales%", `\`, `it's\__`, `\`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.condition, tt.filter.condition("t.db"))
			assert.Equal(t, tt.args, tt.filter.args())
		})
	}
}

// capturingMock returns a client whose queries are recorded in query and
// answered with an empty result, after checking that they were given args.
func capturingMock(t *testing.T, filter databaseFilter, columns []string, query *string) *mySQLClient {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherFunc(func(_, actual string) error {
		*query = actual
		return nil
	})))
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, mock.ExpectationsWereMet())
		db.Close()
	})
	args := make([]driver.Value, 0, len(filter.args()))
	for _, arg := range filter.args() {
		args = append(args, arg)
	}
	mock.ExpectQuery("").WithArgs(args...).WillReturnRows(sqlmock.NewRows(columns))
	return newMySQLClientFromDB(db, StatementEventsConfig{DigestTextLimit: 120, Limit: 250, TimeLimit: time.Hour}, filter)
}

func TestDatabaseFilteredQueries(t *testing.T) {
	filter := newDatabaseFilter(&Config{Databases: []string{"sales*"}, ExcludeDatabases: []string{"sales_test"}})
	tests := []struct {
		name       string
		expression string
		run        func(*mySQLClient) error
		// before is the text the condition must directly follow, and after the
		// text that must directly follow it.
		before, after string
	}{
		{
			name:       "top queries",
			expression: "`schema_name`",
			run: func(c *mySQLClient) error {
				_, err := c.getTopQueries(10, 60, true)
				return err
			},
			before: "OR `digest_text` IS NULL)\n    AND ",
			after:  "\nORDER BY `count_star` DESC\nLIMIT 10",
		},
		{
			name:       "top queries without sample text",
			expression: "`schema_name`",
			run: func(c *mySQLClient) error {
				_, err := c.getTopQueries(10, 60, false)
				return err
			},
			before: "OR `digest_text` IS NULL)\n    AND ",
			after:  "\nORDER BY `count_star` DESC\nLIMIT 10",
		},
		{
			name:       "query samples",
			expression: "thread.processlist_db",
			run: func(c *mySQLClient) error {
				_, err := c.getQuerySamples(20, true, true)
				return err
			},
			before: "NOT LIKE '/* otel-collector-ignore */%'\n    AND ",
			after:  "\nLIMIT 20",
		},
		{
			name:       "statement events",
			expression: "SCHEMA_NAME",
			run: func(c *mySQLClient) error {
				_, err := c.getStatementEventsStats()
				return err
			},
			before: "INTERVAL 3600 SECOND) AND ",
			after:  " ORDER BY SUM_TIMER_WAIT DESC LIMIT 250",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var query string
			require.NoError(t, tt.run(capturingMock(t, filter, nil, &query)))
			assert.Contains(t, query, tt.before+filter.condition(tt.expression)+tt.after)
			assert.Equal(t, len(filter.args()), strings.Count(query, "?"), "one placeholder per bound argument")

			var unfiltered string
			require.NoError(t, tt.run(capturingMock(t, databaseFilter{}, nil, &unfiltered)))
			assert.NotContains(t, unfiltered, "LIKE ? ESCAPE ?")
			assert.NotContains(t, unfiltered, "?")
		})
	}
}

// schemaRowsClient answers the queries of the table and index metrics with a
// row for each of schemas.
type schemaRowsClient struct {
	mockClient
	schemas []string
}

func (c *schemaRowsClient) getTableStats() ([]tableStats, error) {
	var stats []tableStats
	for _, schema := range c.schemas {
		stats = append(stats, tableStats{schema: schema, name: "t", rows: 1})
	}
	return stats, nil
}

func (c *schemaRowsClient) getAutoIncrementStats() ([]autoIncrementStats, error) {
	var stats []autoIncrementStats
	for _, schema := range c.schemas {
		stats = append(stats, autoIncrementStats{schema: schema, table: "t", column: "id", currentValue: 1, maxValue: 2, utilizationRatio: 0.5})
	}
	return stats, nil
}

func (c *schemaRowsClient) getTableIoWaitsStats() ([]tableIoWaitsStats, error) {
	var stats []tableIoWaitsStats
	for _, schema := range c.schemas {
		stats = append(stats, tableIoWaitsStats{ioWaitsStats{schema: schema, name: "t", countFetch: 1}})
	}
	return stats, nil
}

func (c *schemaRowsClient) getIndexIoWaitsStats() ([]indexIoWaitsStats, error) {
	var stats []indexIoWaitsStats
	for _, schema := range c.schemas {
		stats = append(stats, indexIoWaitsStats{ioWaitsStats{schema: schema, name: "t", countFetch: 1}, "PRIMARY"})
	}
	return stats, nil
}

func (c *schemaRowsClient) getTableLockWaitEventStats() ([]tableLockWaitEventStats, error) {
	var stats []tableLockWaitEventStats
	for _, schema := range c.schemas {
		stats = append(stats, tableLockWaitEventStats{schema: schema, name: "t", countReadNormal: 1})
	}
	return stats, nil
}

// schemaMetrics returns, for each metric with a schema attribute, the sorted
// distinct schemas it reports, and the names of the other metrics.
func schemaMetrics(md pmetric.Metrics) (map[string][]string, []string) {
	schemas := map[string][]string{}
	var others []string
	ms := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	for i := 0; i < ms.Len(); i++ {
		m := ms.At(i)
		var dps pmetric.NumberDataPointSlice
		switch m.Type() {
		case pmetric.MetricTypeGauge:
			dps = m.Gauge().DataPoints()
		case pmetric.MetricTypeSum:
			dps = m.Sum().DataPoints()
		default:
			continue
		}
		for j := 0; j < dps.Len(); j++ {
			schema, ok := dps.At(j).Attributes().Get("schema")
			if !ok {
				others = append(others, m.Name())
				break
			}
			if !slices.Contains(schemas[m.Name()], schema.Str()) {
				schemas[m.Name()] = append(schemas[m.Name()], schema.Str())
			}
		}
		slices.Sort(schemas[m.Name()])
	}
	return schemas, others
}

func TestDatabaseFilterMetrics(t *testing.T) {
	filteredMetrics := []string{
		"mysql.index.io.wait.count",
		"mysql.index.io.wait.time",
		"mysql.table.auto_increment.limit",
		"mysql.table.auto_increment.usage",
		"mysql.table.auto_increment.utilization",
		"mysql.table.average_row_length",
		"mysql.table.io.wait.count",
		"mysql.table.io.wait.time",
		"mysql.table.lock_wait.read.count",
		"mysql.table.lock_wait.read.time",
		"mysql.table.lock_wait.write.count",
		"mysql.table.lock_wait.write.time",
		"mysql.table.rows",
		"mysql.table.size",
	}
	tests := []struct {
		name     string
		include  []string
		exclude  []string
		expected []string
	}{
		{
			name:     "no filter",
			expected: []string{"Sales_EU", "hr", "sales_test", "sys"},
		},
		{
			name:     "include and exclude",
			include:  []string{"sales*", "HR"},
			exclude:  []string{"*_test"},
			expected: []string{"Sales_EU", "hr"},
		},
		{
			name:     "exclude only",
			exclude:  []string{"s?s"},
			expected: []string{"Sales_EU", "hr", "sales_test"},
		},
		{
			name:    "nothing allowed",
			include: []string{"no_such_database"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			cfg.Username = "otel"
			cfg.AddrConfig = confignet.AddrConfig{Endpoint: "localhost:3306"}
			cfg.Databases = tt.include
			cfg.ExcludeDatabases = tt.exclude
			cfg.MetricsBuilderConfig.Metrics.MysqlTableRows.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableAverageRowLength.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableSize.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableAutoIncrementLimit.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableAutoIncrementUsage.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableAutoIncrementUtilization.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableLockWaitReadCount.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableLockWaitReadTime.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableLockWaitWriteCount.Enabled = true
			cfg.MetricsBuilderConfig.Metrics.MysqlTableLockWaitWriteTime.Enabled = true

			scraper, err := newMySQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, nil, newCache[int64](100), newTTLCache[string](0, 0))
			require.NoError(t, err)
			scraper.sqlclient = &schemaRowsClient{
				mockClient: mockClient{
					globalStatsFile: "global_stats",
					innodbStatsFile: "innodb_stats",
				},
				schemas: []string{"Sales_EU", "hr", "sales_test", "sys"},
			}

			md, err := scraper.scrape(t.Context())
			require.NoError(t, err)
			schemas, others := schemaMetrics(md)
			for _, metric := range filteredMetrics {
				assert.Equal(t, tt.expected, schemas[metric], "metric %s", metric)
			}
			assert.Len(t, schemas, len(filteredMetrics)*min(1, len(tt.expected)), "only the table and index metrics carry a schema")
			assert.Contains(t, others, "mysql.buffer_pool.pages", "instance metrics are reported whatever the filter")
		})
	}
}
