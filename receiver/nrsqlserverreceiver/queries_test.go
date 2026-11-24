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
	"github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrcommon/sqlnormalizer"
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
				"headChars":       int64(fullQueryTextHeadChars),
				"prefixChars":     int64(fullQueryTextPrefixChars),
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
			for _, param := range []string{"@collectFullText", "@headChars", "@prefixChars"} {
				require.Contains(t, query, param)
			}
		})
	}
}

// TestQueryTemplatesStatementTextArithmetic pins the text and offsets the templates return for a statement
// after offset 0: its own text, the head of the batch, and offsets relative to the returned text.
func TestQueryTemplatesStatementTextArithmetic(t *testing.T) {
	for name, tc := range map[string]struct {
		query string
		parts []string
	}{
		"top query": {getSQLServerQueryTextAndPlanQuery(), []string{
			"WHEN stats.statement_start_offset > 0",
			"THEN SUBSTRING(st.text, (stats.statement_start_offset / 2) + 1,",
			"ELSE st.text",
			"ISNULL(SUBSTRING(st.text, 1, @headChars), N'')",
			"ISNULL(SUBSTRING(st.text, (stats.statement_start_offset / 2) - @prefixChars + 1, @prefixChars), N'') ELSE N'' END AS full_query_text_prefix",
			"0 AS statement_start_offset",
			"- stats.statement_start_offset AS statement_end_offset",
		}},
		"query sample": {getSQLServerQuerySamplesQuery(), []string{
			"CASE WHEN o.TEXT IS NOT NULL AND r.statement_start_offset > 0 THEN 1 ELSE 0 END AS cut",
			"THEN SUBSTRING(o.TEXT, (r.statement_start_offset / 2) + 1,",
			"ELSE COALESCE(o.TEXT, ib.event_info, '')",
			"ISNULL(SUBSTRING(o.TEXT, 1, @headChars), N'')",
			"ISNULL(SUBSTRING(o.TEXT, (r.statement_start_offset / 2) - @prefixChars + 1, @prefixChars), N'') ELSE N'' END AS full_query_text_prefix",
			"CASE WHEN w.cut = 1 THEN 0 ELSE r.statement_start_offset END AS statement_start_offset",
			"- CASE WHEN w.cut = 1 THEN r.statement_start_offset ELSE 0 END AS statement_end_offset",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, part := range tc.parts {
				require.Contains(t, tc.query, part)
			}
			require.NotContains(t, tc.query, "@windowChars")
		})
	}
}

// statementOnlyText mirrors the text and offsets the templates return for a statement after offset 0.
func statementOnlyText(text string, startOffset, endOffset int) (statement string, newStart, newEnd int) {
	return text[startOffset/2 : endOffset/2+1], 0, endOffset - startOffset
}

// precedingText mirrors the characters the templates return right before a statement after offset 0.
func precedingText(text string, startOffset int) string {
	statementStart := startOffset / 2
	return text[max(0, statementStart-fullQueryTextPrefixChars):statementStart]
}

func TestStatementOnlyTextKeepsHashAndTags(t *testing.T) {
	const statement = "SELECT a, b FROM orders WHERE id = 42"
	preamble := "/* nr_service_guid=GUID-1 */ SELECT 1; " + strings.Repeat("x", 100000) + " /* other */ "
	text := preamble + statement + "; " + strings.Repeat("y", 4096)
	start := len(preamble) * 2
	end := start + (len(statement)-1)*2
	obf := newObfuscator()

	whole, err := obf.obfuscateFullSQLString(text, start, end)
	require.NoError(t, err)
	only, ws, we := statementOnlyText(text, start, end)
	require.Equal(t, statement, only)
	got, err := obf.obfuscateFullSQLString(only, ws, we)
	require.NoError(t, err)

	t.Run("the full text is the whole-batch text once the placeholder is restored", func(t *testing.T) {
		require.Equal(t, whole, withBlockCommentPlaceholder(got, precedingText(text, start)))
	})
	t.Run("the hash is the same without the preceding comment", func(t *testing.T) {
		require.Contains(t, whole, "?")
		_, wholeHash := sqlnormalizer.NormalizeSQLAndHash(whole)
		_, gotHash := sqlnormalizer.NormalizeSQLAndHash(got)
		require.Equal(t, wholeHash, gotHash)
	})
	t.Run("the tags come from the head", func(t *testing.T) {
		keys := []string{"nr_service_guid"}
		head := text[:fullQueryTextHeadChars]
		require.Equal(t, "nr_service_guid=GUID-1", sqlcomments.ExtractAndFilterComments(commentSourceText(only, head, ws), keys))
		require.Empty(t, sqlcomments.ExtractAndFilterComments(commentSourceText(only, "", ws), keys))
	})
	t.Run("a leading comment longer than the head is not read", func(t *testing.T) {
		long := "/* nr_service_guid=GUID-2,filler=" + strings.Repeat("z", 2*fullQueryTextHeadChars) + " */ SELECT 1; "
		longText := long + statement
		head := longText[:fullQueryTextHeadChars]
		require.Empty(t, sqlcomments.ExtractAndFilterComments(commentSourceText(statement, head, 0), []string{"nr_service_guid"}))
		require.Equal(t, "nr_service_guid=GUID-2", sqlcomments.ExtractAndFilterComments(commentSourceText(longText, "", len(long)*2), []string{"nr_service_guid"}))
	})
	t.Run("a statement at offset 0 keeps the whole text", func(t *testing.T) {
		batch := statement + "; " + strings.Repeat("y", 4096)
		kept, err := obf.obfuscateFullSQLString(batch, 0, (len(statement)-1)*2)
		require.NoError(t, err)
		require.Contains(t, kept, "yyyy")
	})
}

func TestWithBlockCommentPlaceholder(t *testing.T) {
	for name, tc := range map[string]struct {
		prefix string
		want   string
	}{
		"no text before the statement":          {"", "S"},
		"a statement before it":                 {"SELECT 1; ", "S"},
		"a comment directly before":             {"/* tag */", "? S"},
		"a comment and a space":                 {"/* tag */ ", "? S"},
		"a comment and newlines and tabs":       {"/* tag */\r\n\t\n ", "? S"},
		"only the end of a comment":             {strings.Repeat("p", 200) + " */ ", "? S"},
		"a comment followed by text":            {"/* tag */ SELECT 1; ", "S"},
		"a comment that is not closed":          {"/* tag ", "S"},
		"a closed comment and an open one":      {"/* a */ /* b ", "S"},
		"two comments":                          {"/* a */ /* b */ ", "? S"},
		"a line comment":                        {"-- note\n", "S"},
		"a star and a slash apart":              {"* /", "S"},
		"a multiplication before the statement": {"SELECT 2 * 3; ", "S"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, withBlockCommentPlaceholder("S", tc.prefix))
		})
	}
}

// TestPlaceholderMatchesWholeBatchOutput checks that the statement text, the characters before it and the
// placeholder rule give the text that obfuscating the whole batch gives, and that the hash never depends on it.
func TestPlaceholderMatchesWholeBatchOutput(t *testing.T) {
	const statement = "SELECT a, b FROM orders WHERE id = 42"
	trailing := "; " + strings.Repeat("y", 1024)
	obf := newObfuscator()

	for name, tc := range map[string]struct {
		preamble string
		// sameAsWholeBatch is false where the comment is not directly before the statement.
		sameAsWholeBatch bool
	}{
		"a comment directly before":                {"/* nr_service_guid=A */ ", true},
		"a comment and no space":                   {"/* nr_service_guid=A */", true},
		"newlines after the comment":               {"/* nr_service_guid=A */\r\n\r\n\t ", true},
		"no comment":                               {"SELECT 1; ", true},
		"nothing before the statement text":        {"BEGIN ", true},
		"a 100000 character comment":               {"/* " + strings.Repeat("p", 100000) + " */ ", true},
		"two comments":                             {"/* a */ /* b */ ", true},
		"parameters and a comment":                 {"(@p1 int)/* a */ ", true},
		"a comment inside a procedure":             {"CREATE PROCEDURE p AS BEGIN SET NOCOUNT ON; /* a */ SELECT 1; /* nr_service_guid=B */ ", true},
		"the comment and the statement are close":  {"/* c */ ", true},
		"whitespace up to the limit":               {"/* a */" + strings.Repeat(" ", fullQueryTextPrefixChars-len("*/")), true},
		"a comment far before the statement":       {"/* a */ SELECT 1; " + strings.Repeat("y", 1024) + " ", false},
		"whitespace beyond the limit":              {"/* a */" + strings.Repeat(" ", fullQueryTextPrefixChars+1), false},
		"a comment at the start of a longer batch": {"/* a */ SELECT 1; SELECT 2; ", false},
	} {
		t.Run(name, func(t *testing.T) {
			text := tc.preamble + statement + trailing
			start := len(tc.preamble) * 2
			end := start + (len(statement)-1)*2
			whole, err := obf.obfuscateFullSQLString(text, start, end)
			require.NoError(t, err)
			only, ws, we := statementOnlyText(text, start, end)
			stmtOut, err := obf.obfuscateFullSQLString(only, ws, we)
			require.NoError(t, err)
			got := withBlockCommentPlaceholder(stmtOut, precedingText(text, start))

			if tc.sameAsWholeBatch {
				require.Equal(t, whole, got)
			} else {
				require.NotEqual(t, whole, got)
				require.Equal(t, blockCommentPlaceholder+got, whole)
			}
			_, wholeHash := sqlnormalizer.NormalizeSQLAndHash(whole)
			_, gotHash := sqlnormalizer.NormalizeSQLAndHash(got)
			_, bareHash := sqlnormalizer.NormalizeSQLAndHash(stmtOut)
			require.Equal(t, wholeHash, gotHash)
			require.Equal(t, wholeHash, bareHash)
		})
	}
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
