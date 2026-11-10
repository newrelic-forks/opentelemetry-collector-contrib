// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrpostgresqlreceiver

import (
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/lib/pq/pqerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuoteExplainFunctionName(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "unqualified", input: "explain_statement", expected: `"explain_statement"`},
		{name: "schema qualified", input: "otel.explain_statement", expected: `"otel"."explain_statement"`},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := quoteExplainFunctionName(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestProbeExplainFunction(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}
		mock.ExpectQuery(`SELECT "otel"."explain_statement"('SELECT 1')`).
			WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(`[{"Plan":{}}]`))

		err = client.probeExplainFunction(t.Context(), `"otel"."explain_statement"`)
		require.NoError(t, err)
	})

	t.Run("function does not exist", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}
		mock.ExpectQuery(`SELECT "otel"."explain_statement"('SELECT 1')`).
			WillReturnError(&pq.Error{Code: pqerror.UndefinedFunction, Message: "function otel.explain_statement(text) does not exist"})

		err = client.probeExplainFunction(t.Context(), `"otel"."explain_statement"`)
		require.Error(t, err)
		var pqErr *pq.Error
		require.ErrorAs(t, err, &pqErr)
		assert.Equal(t, pqerror.UndefinedFunction, pqErr.Code)
	})
}

func TestGetDatabaseConflicts(t *testing.T) {
	conflictColumns := []string{"datname", "confl_tablespace", "confl_lock", "confl_snapshot", "confl_bufferpin", "confl_deadlock"}

	tests := []struct {
		name        string
		databases   []string
		expectedSQL string
		rows        *sqlmock.Rows
		expected    map[databaseName]databaseConflictStats
	}{
		{
			name:        "all databases",
			databases:   nil,
			expectedSQL: "SELECT datname, confl_tablespace, confl_lock, confl_snapshot, confl_bufferpin, confl_deadlock FROM pg_stat_database_conflicts;",
			rows: sqlmock.NewRows(conflictColumns).
				AddRow("otel", 1, 2, 3, 4, 5).
				AddRow("telemetry", 6, 7, 8, 9, 10),
			expected: map[databaseName]databaseConflictStats{
				"otel":      {conflTablespace: 1, conflLock: 2, conflSnapshot: 3, conflBufferpin: 4, conflDeadlock: 5},
				"telemetry": {conflTablespace: 6, conflLock: 7, conflSnapshot: 8, conflBufferpin: 9, conflDeadlock: 10},
			},
		},
		{
			name:        "filtered by database",
			databases:   []string{"otel"},
			expectedSQL: "SELECT datname, confl_tablespace, confl_lock, confl_snapshot, confl_bufferpin, confl_deadlock FROM pg_stat_database_conflicts WHERE datname IN ('otel');",
			rows: sqlmock.NewRows(conflictColumns).
				AddRow("otel", 0, 0, 0, 0, 0),
			expected: map[databaseName]databaseConflictStats{
				"otel": {},
			},
		},
		{
			name:        "rows with empty datname are skipped",
			databases:   nil,
			expectedSQL: "SELECT datname, confl_tablespace, confl_lock, confl_snapshot, confl_bufferpin, confl_deadlock FROM pg_stat_database_conflicts;",
			rows: sqlmock.NewRows(conflictColumns).
				AddRow("", 1, 1, 1, 1, 1).
				AddRow("otel", 2, 2, 2, 2, 2),
			expected: map[databaseName]databaseConflictStats{
				"otel": {conflTablespace: 2, conflLock: 2, conflSnapshot: 2, conflBufferpin: 2, conflDeadlock: 2},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

			mock.ExpectQuery(tc.expectedSQL).WillReturnRows(tc.rows)

			conflicts, err := client.getDatabaseConflicts(t.Context(), tc.databases)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, conflicts)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGetExecutionTimeStats(t *testing.T) {
	const baseSQL = "SELECT pd.datname AS datname, SUM(pss.total_exec_time) / 1000.0 AS execution_time_seconds FROM pg_stat_statements pss JOIN pg_database pd ON pss.dbid = pd.oid"
	columns := []string{"datname", "execution_time_seconds"}

	tests := []struct {
		name        string
		databases   []string
		expectedSQL string
		rows        *sqlmock.Rows
		queryErr    error
		expected    map[databaseName]float64
		wantErr     bool
	}{
		{
			name:        "all databases",
			databases:   nil,
			expectedSQL: baseSQL + " GROUP BY datname;",
			// total_exec_time is reported in milliseconds; the query divides by 1000 to return seconds.
			rows: sqlmock.NewRows(columns).
				AddRow("otel", 1.5).
				AddRow("telemetry", 42.25),
			expected: map[databaseName]float64{
				"otel":      1.5,
				"telemetry": 42.25,
			},
		},
		{
			name:        "filtered by database",
			databases:   []string{"otel"},
			expectedSQL: baseSQL + " WHERE datname IN ('otel') GROUP BY datname;",
			rows: sqlmock.NewRows(columns).
				AddRow("otel", 0.0),
			expected: map[databaseName]float64{
				"otel": 0.0,
			},
		},
		{
			name:        "rows with empty datname are skipped",
			databases:   nil,
			expectedSQL: baseSQL + " GROUP BY datname;",
			rows: sqlmock.NewRows(columns).
				AddRow("", 9.9).
				AddRow("otel", 2.5),
			expected: map[databaseName]float64{
				"otel": 2.5,
			},
		},
		{
			name:        "query error when pg_stat_statements is unavailable",
			databases:   nil,
			expectedSQL: baseSQL + " GROUP BY datname;",
			queryErr:    errors.New(`relation "pg_stat_statements" does not exist`),
			expected:    nil,
			wantErr:     true,
		},
		{
			name:        "row scan error on non-numeric value",
			databases:   nil,
			expectedSQL: baseSQL + " GROUP BY datname;",
			rows: sqlmock.NewRows(columns).
				AddRow("otel", "not-a-number"),
			expected: map[databaseName]float64{},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

			if tc.queryErr != nil {
				mock.ExpectQuery(tc.expectedSQL).WillReturnError(tc.queryErr)
			} else {
				mock.ExpectQuery(tc.expectedSQL).WillReturnRows(tc.rows)
			}

			stats, err := client.getExecutionTimeStats(t.Context(), tc.databases)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.expected, stats)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGetTableCount(t *testing.T) {
	const countSQLPre14 = `SELECT count(*) FROM pg_class
WHERE relkind IN ('r', 'm')
AND relnamespace NOT IN (
    SELECT oid FROM pg_namespace
    WHERE nspname = 'pg_catalog' OR nspname = 'information_schema' OR nspname ~ '^pg_toast'
);`
	const countSQLPost14 = `SELECT count(*) FROM pg_class
WHERE relkind IN ('r', 'm', 'p')
AND relnamespace NOT IN (
    SELECT oid FROM pg_namespace
    WHERE nspname = 'pg_catalog' OR nspname = 'information_schema' OR nspname ~ '^pg_toast'
);`

	tests := []struct {
		name          string
		serverVersion string
		expectedSQL   string
		count         int64
		versionErr    error
		queryErr      error
		wantErr       bool
	}{
		{
			name:          "PostgreSQL 13 excludes partitioned parents",
			serverVersion: "13.4",
			expectedSQL:   countSQLPre14,
			count:         5,
		},
		{
			name:          "PostgreSQL 14 includes partitioned parents",
			serverVersion: "14.0",
			expectedSQL:   countSQLPost14,
			count:         6,
		},
		{
			name:          "PostgreSQL 17 includes partitioned parents",
			serverVersion: "17.2",
			expectedSQL:   countSQLPost14,
			count:         6,
		},
		{
			name:          "error resolving server version",
			serverVersion: "",
			versionErr:    errors.New("connection reset"),
			wantErr:       true,
		},
		{
			name:          "unparsable server version",
			serverVersion: "not-a-version",
			wantErr:       true,
		},
		{
			name:          "count query fails",
			serverVersion: "16.0",
			expectedSQL:   countSQLPost14,
			queryErr:      errors.New("statement timeout"),
			wantErr:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

			if tc.versionErr != nil {
				mock.ExpectQuery("SHOW server_version;").WillReturnError(tc.versionErr)
			} else {
				mock.ExpectQuery("SHOW server_version;").
					WillReturnRows(sqlmock.NewRows([]string{"server_version"}).AddRow(tc.serverVersion))
			}

			// No count query when the version fails to resolve or parse.
			if tc.versionErr == nil && tc.serverVersion != "not-a-version" {
				if tc.queryErr != nil {
					mock.ExpectQuery(tc.expectedSQL).WillReturnError(tc.queryErr)
				} else {
					mock.ExpectQuery(tc.expectedSQL).
						WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(tc.count))
				}
			}

			count, err := client.getTableCount(t.Context())
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.count, count)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGetVersion(t *testing.T) {
	tests := []struct {
		name        string
		serverValue string
		want        string
		wantErr     bool
	}{
		{
			name:        "plain version",
			serverValue: "17.2",
			want:        "17.2",
		},
		{
			name:        "debian packaging suffix stripped",
			serverValue: "17.2 (Debian 17.2-1.pgdg120+1)",
			want:        "17.2",
		},
		{
			name:        "alpine/minimal build no suffix",
			serverValue: "16.1",
			want:        "16.1",
		},
		{
			name:        "empty response is an error",
			serverValue: "",
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

			mock.ExpectQuery("SHOW server_version;").
				WillReturnRows(sqlmock.NewRows([]string{"server_version"}).AddRow(tc.serverValue))

			got, err := client.getVersion(t.Context())
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGetDatabaseTableMetricsUnavailableSize(t *testing.T) {
	columns := []string{"schema", "table", "live", "dead", "ins", "upd", "del", "hot_upd", "seq_scans", "table_size", "vacuum_count"}

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

	// The size function returns NULL for a relation dropped mid-query; the
	// query must coalesce it so the scan never sees NULL.
	mock.ExpectQuery(`coalesce\(pg_total_relation_size\(s\.relid\), -1\) AS table_size`).
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow("public", "kept", 10, 1, 2, 3, 4, 5, 6, 8192, 7).
			AddRow("public", "dropped", 11, 0, 1, 0, 0, 0, 2, -1, 0))

	tables, err := client.getDatabaseTableMetrics(t.Context(), "otel")
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())

	assert.Equal(t, tableStats{
		database: "otel", schema: "public", table: "kept",
		live: 10, dead: 1, inserts: 2, upd: 3, del: 4, hotUpd: 5, seqScans: 6, size: 8192, vacuumCount: 7,
	}, tables[tableKey("otel", "public", "kept")])
	assert.Equal(t, tableStats{
		database: "otel", schema: "public", table: "dropped",
		live: 11, inserts: 1, seqScans: 2, size: -1,
	}, tables[tableKey("otel", "public", "dropped")])
}

func TestGetDatabaseTableMetricsRowsErr(t *testing.T) {
	columns := []string{"schema", "table", "live", "dead", "ins", "upd", "del", "hot_upd", "seq_scans", "table_size", "vacuum_count"}

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

	iterErr := errors.New("connection reset mid-result")
	mock.ExpectQuery("pg_stat_user_tables").
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow("public", "first", 1, 0, 0, 0, 0, 0, 0, 8192, 0).
			AddRow("public", "second", 1, 0, 0, 0, 0, 0, 0, 8192, 0).
			RowError(1, iterErr))

	tables, err := client.getDatabaseTableMetrics(t.Context(), "otel")
	require.ErrorIs(t, err, iterErr)
	assert.Len(t, tables, 1)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetBlocksReadByTableRowsErr(t *testing.T) {
	columns := []string{"schema", "table", "heap_read", "heap_hit", "idx_read", "idx_hit", "toast_read", "toast_hit", "tidx_read", "tidx_hit"}

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

	iterErr := errors.New("connection reset mid-result")
	mock.ExpectQuery("pg_statio_user_tables").
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow("public", "first", 1, 2, 3, 4, 5, 6, 7, 8).
			AddRow("public", "second", 1, 2, 3, 4, 5, 6, 7, 8).
			RowError(1, iterErr))

	stats, err := client.getBlocksReadByTable(t.Context(), "otel")
	require.ErrorIs(t, err, iterErr)
	assert.Len(t, stats, 1)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetIndexStatsUnavailableSize(t *testing.T) {
	columns := []string{"schemaname", "relname", "indexrelname", "index_size", "idx_scan"}

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

	mock.ExpectQuery(`coalesce\(pg_relation_size\(indexrelid\), -1\) AS index_size`).
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow("public", "t", "kept_idx", 16384, 9).
			AddRow("public", "t", "dropped_idx", -1, 3))

	stats, err := client.getIndexStats(t.Context(), "otel")
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())

	assert.Equal(t, indexStat{index: "kept_idx", table: "t", schema: "public", database: "otel", size: 16384, scans: 9},
		stats[indexKey("otel", "public", "t", "kept_idx")])
	assert.Equal(t, indexStat{index: "dropped_idx", table: "t", schema: "public", database: "otel", size: -1, scans: 3},
		stats[indexKey("otel", "public", "t", "dropped_idx")])
}

func TestGetIndexStatsRowsErr(t *testing.T) {
	columns := []string{"schemaname", "relname", "indexrelname", "index_size", "idx_scan"}

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

	iterErr := errors.New("connection reset mid-result")
	mock.ExpectQuery("pg_stat_user_indexes").
		WillReturnRows(sqlmock.NewRows(columns).
			AddRow("public", "t", "first_idx", 16384, 1).
			AddRow("public", "t", "second_idx", 16384, 1).
			RowError(1, iterErr))

	stats, err := client.getIndexStats(t.Context(), "otel")
	require.ErrorIs(t, err, iterErr)
	assert.Len(t, stats, 1)
	require.NoError(t, mock.ExpectationsWereMet())
}
