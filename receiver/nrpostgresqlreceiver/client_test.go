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
