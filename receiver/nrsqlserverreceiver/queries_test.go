// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver

import (
	"database/sql"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrcommon/sqlcomments"
	"github.com/stretchr/testify/require"
)

func TestQueryContents(t *testing.T) {
	queryTests := []struct {
		name                     string
		instanceName             string
		getQuery                 func(string) string
		expectedQueryValFilename string
	}{
		{
			name:                     "Test database IO query without instance name",
			instanceName:             "",
			getQuery:                 getSQLServerDatabaseIOQuery,
			expectedQueryValFilename: "databaseIOQueryWithoutInstanceName.txt",
		},
		{
			name:                     "Test database IO query with instance name",
			instanceName:             "instanceName",
			getQuery:                 getSQLServerDatabaseIOQuery,
			expectedQueryValFilename: "databaseIOQueryWithInstanceName.txt",
		},
		{
			name:                     "Test perf counter query without instance name",
			instanceName:             "",
			getQuery:                 getSQLServerPerformanceCounterQuery,
			expectedQueryValFilename: "perfCounterQueryWithoutInstanceName.txt",
		},
		{
			name:                     "Test perf counter query with instance name",
			instanceName:             "instanceName",
			getQuery:                 getSQLServerPerformanceCounterQuery,
			expectedQueryValFilename: "perfCounterQueryWithInstanceName.txt",
		},
		{
			name:                     "Test properties query without instance name",
			instanceName:             "",
			getQuery:                 getSQLServerPropertiesQuery,
			expectedQueryValFilename: "propertyQueryWithoutInstanceName.txt",
		},
		{
			name:                     "Test properties query with instance name",
			instanceName:             "instanceName",
			getQuery:                 getSQLServerPropertiesQuery,
			expectedQueryValFilename: "propertyQueryWithInstanceName.txt",
		},
		{
			name:                     "Test wait stats query without instance name",
			instanceName:             "",
			getQuery:                 getSQLServerWaitStatsQuery,
			expectedQueryValFilename: "waitStatsQueryWithoutInstanceName.txt",
		},
		{
			name:                     "Test wait stats query with instance name",
			instanceName:             "instanceName",
			getQuery:                 getSQLServerWaitStatsQuery,
			expectedQueryValFilename: "waitStatsQueryWithInstanceName.txt",
		},
	}

	for _, tt := range queryTests {
		t.Run(tt.name, func(t *testing.T) {
			expectedBytes, err := os.ReadFile(path.Join("./testdata", tt.expectedQueryValFilename))
			require.NoError(t, err)
			// Replace all will fix newlines when testing on Windows
			expected := strings.ReplaceAll(string(expectedBytes), "\r\n", "\n")

			// Without a database filter the placeholders render to nothing.
			actual := databaseFilter{}.apply(tt.getQuery(tt.instanceName))
			require.Equal(t, expected, actual)
		})
	}
}

func TestQueryTextAndPlanQueryContents(t *testing.T) {
	queryTests := []struct {
		name                     string
		instanceName             string
		maxQuerySampleCount      uint
		lookbackTime             uint
		getQuery                 func() string
		expectedQueryValFilename string
	}{
		{
			name:                     "Test query text and query plan",
			instanceName:             "",
			maxQuerySampleCount:      1000,
			lookbackTime:             60,
			getQuery:                 getSQLServerQueryTextAndPlanQuery,
			expectedQueryValFilename: "databaseTopQueryWithoutInstanceName.txt",
		},
	}

	for _, tt := range queryTests {
		t.Run(tt.name, func(t *testing.T) {
			expected, err := os.ReadFile(path.Join("./testdata", tt.expectedQueryValFilename))
			require.NoError(t, err)
			actual := databaseFilter{}.apply(tt.getQuery())
			require.Equal(t, strings.TrimSpace(string(expected)), strings.TrimSpace(actual))
		})
	}
}

func TestGetSQLServerQuerySamplesQuery(t *testing.T) {
	queryTests := []struct {
		name                     string
		instanceName             string
		getQuery                 func() string
		expectedQueryValFilename string
		maxRowsPerQuery          uint64
	}{
		{
			name:                     "Test query sample query",
			instanceName:             "",
			maxRowsPerQuery:          1000,
			getQuery:                 getSQLServerQuerySamplesQuery,
			expectedQueryValFilename: "testQuerySampleQuery.txt",
		},
	}

	for _, tt := range queryTests {
		t.Run(tt.name, func(t *testing.T) {
			expectedBytes, err := os.ReadFile(path.Join("./testdata", tt.expectedQueryValFilename))
			require.NoError(t, err)
			// Replace all will fix newlines when testing on Windows
			expected := strings.ReplaceAll(string(expectedBytes), "\r\n", "\n")
			actual := strings.ReplaceAll(databaseFilter{}.apply(tt.getQuery()), "\r\n", "\n")
			require.Equal(t, expected, actual)
		})
	}
}

func TestGetSQLServerIdleBlockingSessionsQuery(t *testing.T) {
	expectedBytes, err := os.ReadFile(path.Join(".", "testdata", "testIdleBlockerQuerySampleQuery.txt"))
	require.NoError(t, err)

	expected := strings.ReplaceAll(string(expectedBytes), "\r\n", "\n")
	actual := strings.ReplaceAll(getSQLServerIdleBlockingSessionsQuery(), "\r\n", "\n")
	require.Equal(t, expected, actual)
}

// TestDirectConnectionQueriesIgnoreInstanceName guards against reintroducing the
// @@SERVERNAME filter: for a named instance (e.g. "SQL04\DB13"), @@SERVERNAME never
// equals the configured instance_name, so the predicate silently filtered out every
// row on a direct connection. A direct connection is already scoped to one instance,
// so instance_name must not filter these queries at all.
func TestDirectConnectionQueriesIgnoreInstanceName(t *testing.T) {
	queryFuncs := map[string]func(string) string{
		"getSQLServerDatabaseIOQuery":                     getSQLServerDatabaseIOQuery,
		"getSQLServerPerformanceCounterQuery":             getSQLServerPerformanceCounterQuery,
		"getSQLServerPropertiesQuery":                     getSQLServerPropertiesQuery,
		"getSQLServerTopProcedureQuery":                   getSQLServerTopProcedureQuery,
		"getSQLServerWaitStatsQuery":                      getSQLServerWaitStatsQuery,
		"getSQLServerDatabaseSizeQuery":                   getSQLServerDatabaseSizeQuery,
		"getSQLServerOSMemoryQuery":                       getSQLServerOSMemoryQuery,
		"getSQLServerOSDiskQuery":                         getSQLServerOSDiskQuery,
		"getSQLServerOSSchedulerRunnableTasksQuery":       getSQLServerOSSchedulerRunnableTasksQuery,
		"getSQLServerProcessCountQuery":                   getSQLServerProcessCountQuery,
		"getSQLServerThreadPoolQuery":                     getSQLServerThreadPoolQuery,
		"getSQLServerWorkerThreadsQuery":                  getSQLServerWorkerThreadsQuery,
		"getSQLServerTempDBQuery":                         getSQLServerTempDBQuery,
		"getSQLServerTempDBFileQuery":                     getSQLServerTempDBFileQuery,
		"getSQLServerFailoverClusterAGQuery":              getSQLServerFailoverClusterAGQuery,
		"getSQLServerFailoverClusterReplicaQuery":         getSQLServerFailoverClusterReplicaQuery,
		"getSQLServerFailoverClusterReplicaDatabaseQuery": getSQLServerFailoverClusterReplicaDatabaseQuery,
		"getSQLServerLongestRunningTransactionQuery":      getSQLServerLongestRunningTransactionQuery,
		"getSQLServerIndexPhysicalStatsQuery":             getSQLServerIndexPhysicalStatsQuery,
		"getSQLServerAvailabilityGroupQuery":              getSQLServerAvailabilityGroupQuery,
		"getSQLServerCPUMemoryQuery":                      getSQLServerCPUMemoryQuery,
		"getSQLServerDiskIOQuery":                         getSQLServerDiskIOQuery,
	}

	for name, fn := range queryFuncs {
		t.Run(name, func(t *testing.T) {
			withInstance := fn(`SQL04\DB13`)
			withoutInstance := fn("")
			require.Equal(t, withoutInstance, withInstance,
				"instance_name must not change the generated SQL for a direct connection")
			require.NotContains(t, withInstance, "@@SERVERNAME =",
				"a named instance's @@SERVERNAME never matches instance_name, so this predicate would silently filter out every row")
		})
	}
}

func TestFormatSQLServerSessionIDsParam(t *testing.T) {
	actual := formatSQLServerSessionIDsParam(map[int64]struct{}{
		91: {},
		60: {},
		77: {},
	})
	require.Equal(t, "60,77,91", actual)
}

func TestFullQueryTextArgs(t *testing.T) {
	tests := []struct {
		name            string
		collect         bool
		wantCollectFlag int
	}{
		{name: "collect", collect: true, wantCollectFlag: 1},
		{name: "text not collected", collect: false, wantCollectFlag: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]any{}
			for _, arg := range fullQueryTextArgs(tt.collect) {
				named, ok := arg.(sql.NamedArg)
				require.True(t, ok)
				got[named.Name] = named.Value
			}
			require.Equal(t, map[string]any{
				"collectFullText": tt.wantCollectFlag,
				"windowChars":     int64(fullQueryTextWindowChars),
				"headChars":       int64(fullQueryTextHeadChars),
			}, got)
		})
	}
}

// TestQueryTemplatesBoundFullQueryText guards the contract between the SQL templates and the Go
// parameters: every named parameter the templates read must be one fullQueryTextArgs supplies.
func TestQueryTemplatesBoundFullQueryText(t *testing.T) {
	for name, query := range map[string]string{
		"top query":    getSQLServerQueryTextAndPlanQuery(),
		"query sample": getSQLServerQuerySamplesQuery(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, param := range []string{"@collectFullText", "@windowChars", "@headChars"} {
				require.Contains(t, query, param)
			}
		})
	}
}

// windowFullQueryText mirrors the window the SQL templates return for a statement after offset 0.
func windowFullQueryText(text string, startOffset, endOffset int) (window string, newStart, newEnd int) {
	if startOffset <= 0 {
		return text, startOffset, endOffset
	}
	winStart := 0
	if startOffset/2 > fullQueryTextWindowChars {
		winStart = startOffset/2 - fullQueryTextWindowChars
	}
	return text[winStart : endOffset/2+1], startOffset - winStart*2, endOffset - winStart*2
}

func TestWindowedFullQueryTextKeepsCleanText(t *testing.T) {
	const statement = "SELECT a, b FROM orders WHERE id = 42"
	build := func(filler string) (text string, start, end int) {
		preamble := "/* nr_service_guid=GUID-1 */ " + filler
		trailing := "; " + strings.Repeat("y", 4096)
		text = preamble + statement + trailing
		start = len(preamble) * 2
		end = start + (len(statement)-1)*2
		return text, start, end
	}
	t.Run("comment directly before the statement", func(t *testing.T) {
		text, start, end := build(strings.Repeat("x", 3*fullQueryTextWindowChars))
		// The comment sits at the very start; place a second one right before the statement.
		text = strings.Replace(text, statement, "/* nr_service_guid=GUID-2 */ "+statement, 1)
		start += len("/* nr_service_guid=GUID-2 */ ") * 2
		end += len("/* nr_service_guid=GUID-2 */ ") * 2
		window, ws, we := windowFullQueryText(text, start, end)
		require.Less(t, len(window), len(text))
		require.Equal(t, extractCleanText(text, start, end), extractCleanText(window, ws, we))
		require.Contains(t, extractCleanText(window, ws, we), "GUID-2")
	})
	t.Run("batch within the window is unchanged", func(t *testing.T) {
		text, start, end := build(strings.Repeat("x", 100))
		window, ws, we := windowFullQueryText(text, start, end)
		require.Equal(t, extractCleanText(text, start, end), extractCleanText(window, ws, we))
	})
	t.Run("statement at offset 0 keeps the whole text", func(t *testing.T) {
		text := statement + "; " + strings.Repeat("y", 3*fullQueryTextWindowChars)
		window, ws, we := windowFullQueryText(text, 0, (len(statement)-1)*2)
		require.Equal(t, text, window)
		require.Equal(t, extractCleanText(text, 0, (len(statement)-1)*2), extractCleanText(window, ws, we))
	})
	t.Run("last comment beyond the window is not carried", func(t *testing.T) {
		text, start, end := build(strings.Repeat("x", 3*fullQueryTextWindowChars))
		window, ws, we := windowFullQueryText(text, start, end)
		require.Contains(t, extractCleanText(text, start, end), "GUID-1")
		require.NotContains(t, extractCleanText(window, ws, we), "GUID-1")
	})
}

func TestCommentSourceTextKeepsTagsForWindowedBatch(t *testing.T) {
	keys := []string{"nr_service_guid"}
	const statement = "SELECT total FROM orders WHERE id = 7"
	// A batch with the APM comment at its very start, a long first statement, then the statement of interest.
	preamble := "/* nr_service_guid=GUID-9 */ SELECT 1; " + strings.Repeat("x", 3*fullQueryTextWindowChars) + " /* other */ "
	text := preamble + statement + "; " + strings.Repeat("y", 4096)
	start := len(preamble) * 2
	end := start + (len(statement)-1)*2

	whole := sqlcomments.ExtractAndFilterComments(commentSourceText(text, "", start), keys)
	require.Equal(t, "nr_service_guid=GUID-9", whole)

	window, ws, _ := windowFullQueryText(text, start, end)
	require.Positive(t, ws)
	head := text[:fullQueryTextHeadChars]

	t.Run("without the head the tag is lost", func(t *testing.T) {
		require.Empty(t, sqlcomments.ExtractAndFilterComments(commentSourceText(window, "", ws), keys))
	})
	t.Run("with the head the tag is kept", func(t *testing.T) {
		require.Equal(t, whole, sqlcomments.ExtractAndFilterComments(commentSourceText(window, head, ws), keys))
	})
	t.Run("a batch that is not windowed", func(t *testing.T) {
		require.Equal(t, whole, sqlcomments.ExtractAndFilterComments(commentSourceText(text, "", start), keys))
	})
}

// TestTopQueryGroupingStepDoesNotReadBatchText guards the first step of the top-query SQL: it runs for every
// cached statement before the lookback filter, so it must take the database and object id from the plan
// attributes and not call dm_exec_sql_text, which materializes the whole batch text of each statement.
func TestTopQueryGroupingStepDoesNotReadBatchText(t *testing.T) {
	query := getSQLServerQueryTextAndPlanQuery()
	end := strings.Index(query, "proc_stats AS")
	require.Positive(t, end)
	grouping := regexp.MustCompile(`--[^\n]*`).ReplaceAllString(query[:end], "")
	require.NotContains(t, grouping, "dm_exec_sql_text")
	require.Contains(t, grouping, "dm_exec_plan_attributes")
}
