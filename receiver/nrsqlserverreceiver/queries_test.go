// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver

import (
	"database/sql"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"

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

// TestQueryTemplatesWindowArithmetic pins the offset arithmetic that windowFullQueryText mirrors. A change to
// the window or the offset shift in either template fails here until the mirror and its tests are updated.
func TestQueryTemplatesWindowArithmetic(t *testing.T) {
	for name, tc := range map[string]struct {
		query string
		parts []string
	}{
		"top query": {getSQLServerQueryTextAndPlanQuery(), []string{
			"WHEN stats.statement_start_offset > 0",
			"CAST(stats.statement_start_offset AS BIGINT) / 2 > @windowChars",
			"CAST(stats.statement_start_offset AS BIGINT) / 2 - @windowChars ELSE 0 END",
			"SUBSTRING(st.text, w.win_start + 1,",
			"- w.win_start * 2) / 2) + 1)",
			"SUBSTRING(st.text, 1, @headChars)",
			"stats.statement_start_offset - CASE WHEN w.win_start > 0 THEN w.win_start * 2 ELSE 0 END",
		}},
		"query sample": {getSQLServerQuerySamplesQuery(), []string{
			"WHEN o.TEXT IS NOT NULL AND r.statement_start_offset > 0",
			"CAST(r.statement_start_offset AS BIGINT) / 2 > @windowChars",
			"CAST(r.statement_start_offset AS BIGINT) / 2 - @windowChars ELSE 0 END",
			"SUBSTRING(o.TEXT, w.win_start + 1,",
			"- w.win_start * 2) / 2) + 1)",
			"SUBSTRING(o.TEXT, 1, @headChars)",
			"r.statement_start_offset - CASE WHEN w.win_start > 0 THEN w.win_start * 2 ELSE 0 END",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, part := range tc.parts {
				require.Contains(t, tc.query, part)
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
	return text[winStart:min(endOffset/2+1, len(text))], startOffset - winStart*2, endOffset - winStart*2
}

// windowFullQueryTextUTF16 is windowFullQueryText for text that is not ASCII: SQL Server counts characters and
// offsets in UTF-16 code units, and a character outside the basic plane takes two.
func windowFullQueryTextUTF16(text string, startOffset, endOffset int) (window string, newStart, newEnd int) {
	units := utf16.Encode([]rune(text))
	winStart := 0
	if startOffset/2 > fullQueryTextWindowChars {
		winStart = startOffset/2 - fullQueryTextWindowChars
	}
	return string(utf16.Decode(units[winStart:min(endOffset/2+1, len(units))])), startOffset - winStart*2, endOffset - winStart*2
}

// utf16Bytes is how many bytes SQL Server uses for text, which is what statement offsets count.
func utf16Bytes(text string) int {
	return len(utf16.Encode([]rune(text))) * 2
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

// TestQueryTemplatesStatementOffsetsPlanAndFallback pins the parts of the two templates that the arithmetic
// test does not reach: an end offset of -1, the plan of the statement, the plan attribute rule of the
// grouping step, and the text returned when there is no batch text to window.
func TestQueryTemplatesStatementOffsetsPlanAndFallback(t *testing.T) {
	for name, tc := range map[string]struct {
		query    string
		parts    []string
		notParts []string
	}{
		"top query": {
			query: getSQLServerQueryTextAndPlanQuery(),
			parts: []string{
				// an end offset of -1 is the end of the batch, in the window length and in the returned offset
				"WHEN -1 THEN DATALENGTH(st.text) ELSE stats.statement_end_offset END - w.win_start * 2) / 2) + 1)",
				"stats.statement_end_offset END) - CASE WHEN w.win_start > 0 THEN w.win_start * 2 ELSE 0 END AS statement_end_offset",
				// the plan of the statement
				"OUTER APPLY sys.dm_exec_text_query_plan(qs.query_plan_handle, stats.statement_start_offset, stats.statement_end_offset)",
				// the object id is only the object id for plans of objects
				"CASE WHEN cp.objtype IS NULL OR cp.objtype IN ('Adhoc', 'Prepared') THEN NULL ELSE pa.objectid END",
				"WHERE a.attribute IN ('objectid', 'dbid')",
				"DB_NAME(st1.dbid)",
				"WHERE st.text IS NOT NULL",
				// nothing is returned unless the text is collected
				"WHEN @collectFullText = 0 THEN N''",
				"CASE WHEN @collectFullText = 1 AND w.win_start > 0 THEN SUBSTRING(st.text, 1, @headChars) ELSE N'' END",
			},
			notParts: []string{"dm_exec_query_plan("},
		},
		"query sample": {
			query: getSQLServerQuerySamplesQuery(),
			parts: []string{
				"WHEN @collectFullText = 0 THEN N''",
				"CASE WHEN @collectFullText = 1 AND w.win_start > 0 THEN SUBSTRING(o.TEXT, 1, @headChars) ELSE N'' END",
				// without batch text the input buffer is returned whole, with the offsets as they are
				"ELSE CAST(-1 AS BIGINT)",
				"WHEN w.win_start < 0 THEN COALESCE(o.TEXT, ib.event_info, '')",
				"WHEN -1 THEN DATALENGTH(o.TEXT) ELSE r.statement_end_offset END - w.win_start * 2) / 2) + 1)",
				"ISNULL(CASE r.statement_end_offset WHEN -1 THEN DATALENGTH(o.TEXT) ELSE r.statement_end_offset END, 0) - CASE WHEN w.win_start > 0 THEN w.win_start * 2 ELSE 0 END",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, part := range tc.parts {
				require.Contains(t, tc.query, part)
			}
			for _, part := range tc.notParts {
				require.NotContains(t, tc.query, part)
			}
		})
	}
}

func TestWindowedFullQueryTextBoundaries(t *testing.T) {
	const statement = "SELECT a FROM orders WHERE id = 42"
	trailing := "; " + strings.Repeat("y", 64)
	build := func(preambleChars int) (text string, start, end int) {
		preamble := "/* c */" + strings.Repeat("x", preambleChars-len("/* c */"))
		text = preamble + statement + trailing
		return text, len(preamble) * 2, len(preamble)*2 + (len(statement)-1)*2
	}
	for name, tc := range map[string]struct {
		preambleChars int
		wantWinStart  int
	}{
		"the statement starts inside the window":      {fullQueryTextWindowChars - 1, 0},
		"the statement starts at the window size":     {fullQueryTextWindowChars, 0},
		"the statement starts one past the window":    {fullQueryTextWindowChars + 1, 1},
		"the statement starts two past the window":    {fullQueryTextWindowChars + 2, 2},
		"the statement starts far past the window":    {10 * fullQueryTextWindowChars, 9 * fullQueryTextWindowChars},
		"the statement starts right after one letter": {len("/* c */") + 1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			text, start, end := build(tc.preambleChars)
			window, ws, we := windowFullQueryText(text, start, end)
			require.Len(t, window, tc.preambleChars-tc.wantWinStart+len(statement))
			require.Equal(t, start-tc.wantWinStart*2, ws)
			require.Equal(t, end-tc.wantWinStart*2, we)
			require.True(t, strings.HasSuffix(window, statement))
			require.Equal(t, statement, window[ws/2:we/2+1])
		})
	}

	t.Run("an end offset of -1 resolved to the length of the text", func(t *testing.T) {
		preamble := "/* c */" + strings.Repeat("x", 3*fullQueryTextWindowChars) + "/* near */ "
		text := preamble + statement
		start := len(preamble) * 2
		end := len(text) * 2 // DATALENGTH, what the query returns in place of -1
		window, ws, we := windowFullQueryText(text, start, end)
		require.Len(t, window, fullQueryTextWindowChars+len(statement))
		require.Equal(t, extractCleanText(text, start, end), extractCleanText(window, ws, we))
		require.True(t, strings.HasPrefix(extractCleanText(window, ws, we), "/* near */"))
	})
}

func TestWindowedFullQueryTextWithNonASCIIText(t *testing.T) {
	const statement = "SELECT n FROM orders WHERE note = N'caf\u00e9 \U0001F600' AND id = 42"
	emoji := "\U0001F600"
	keys := []string{"nr_service_guid"}

	for name, tc := range map[string]struct {
		before string
		// commentInWindow is false when the only comment before the statement is too far back for the window.
		commentInWindow bool
	}{
		"a comment with accents and Japanese text": {"/* nr_service_guid=A, note=caf\u00e9 \u65e5\u672c\u8a9e */ ", true},
		"a comment with an emoji":                  {"/* nr_service_guid=A " + emoji + " */ ", true},
		"emoji before the comment":                 {strings.Repeat(emoji, 200) + "; /* c */ ", true},
		"emoji and no comment in the window":       {strings.Repeat(emoji, 300) + "; ", false},
	} {
		t.Run(name, func(t *testing.T) {
			// Enough text before the statement that the window starts after the start of the batch.
			filler := strings.Repeat("\u00e9", fullQueryTextWindowChars+500)
			preamble := "/* nr_service_guid=GUID-1 */ " + filler + "; " + tc.before
			text := preamble + statement + "; " + strings.Repeat("y", 128)
			start := utf16Bytes(preamble)
			end := start + utf16Bytes(statement) - 2

			window, ws, we := windowFullQueryTextUTF16(text, start, end)
			require.Positive(t, start/2-ws/2, "the window must start after the start of the batch")
			require.Less(t, len(window), len(text))
			require.Equal(t, statement, string(utf16.Decode(utf16.Encode([]rune(window))[ws/2:we/2+1])))

			whole := extractCleanText(text, start, end)
			got := extractCleanText(window, ws, we)
			if tc.commentInWindow {
				require.Equal(t, whole, got)
				require.True(t, strings.HasPrefix(got, "/*"))
			} else {
				// The comment at the start of the batch is out of the window, so the text is the statement alone.
				require.NotEqual(t, whole, got)
				require.Equal(t, statement, got)
			}

			// The tag comes from the head, which holds characters from the start of the batch.
			head := string(utf16.Decode(utf16.Encode([]rune(text))[:fullQueryTextHeadChars]))
			require.Equal(t, "nr_service_guid=GUID-1", sqlcomments.ExtractAndFilterComments(commentSourceText(window, head, ws), keys))
		})
	}
}

func TestCommentSourceTextCases(t *testing.T) {
	keys := []string{"nr_service_guid"}
	const statement = "SELECT 1"
	tag := func(g string) string { return "/* nr_service_guid=" + g + " */ " }

	for name, tc := range map[string]struct {
		fullText, head string
		startOffset    int
		wantTag        string
	}{
		"the head holds the tag":                           {fullText: "x; " + statement, head: tag("H") + "SELECT 0; ", startOffset: 6, wantTag: "nr_service_guid=H"},
		"the head wins over the text before the statement": {fullText: tag("W") + statement, head: tag("H") + "SELECT 0; ", startOffset: 2 * len(tag("W")), wantTag: "nr_service_guid=H"},
		"parameter declarations before the head tag":       {fullText: "x; " + statement, head: "(@p1 int)" + tag("P") + "SELECT 0; ", startOffset: 6, wantTag: "nr_service_guid=P"},
		"no head and a tag before the statement":           {fullText: tag("T") + "SELECT 0; " + statement, startOffset: 2 * len(tag("T")+"SELECT 0; "), wantTag: "nr_service_guid=T"},
		"no head and parameter declarations":               {fullText: "(@p1 int)" + tag("Q") + "SELECT 0; " + statement, startOffset: 2 * len("(@p1 int)"+tag("Q")+"SELECT 0; "), wantTag: "nr_service_guid=Q"},
		"no head and no comment":                           {fullText: "SELECT 0; " + statement, startOffset: 2 * len("SELECT 0; "), wantTag: ""},
		"no head and a start offset of 0":                  {fullText: tag("Z") + statement, startOffset: 0, wantTag: "nr_service_guid=Z"},
		"a start offset past the end of the text":          {fullText: tag("E") + statement, startOffset: 10000, wantTag: "nr_service_guid=E"},
		"the head has no tag":                              {fullText: "x; " + statement, head: "SELECT 0; ", startOffset: 6, wantTag: ""},
		"a head that is only a comment":                    {fullText: "x; " + statement, head: tag("O"), startOffset: 6, wantTag: "nr_service_guid=O"},
		"an empty text":                                    {fullText: "", head: "", startOffset: 0, wantTag: ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := sqlcomments.ExtractAndFilterComments(commentSourceText(tc.fullText, tc.head, tc.startOffset), keys)
			require.Equal(t, tc.wantTag, got)
		})
	}

	t.Run("a leading comment longer than the head is not read", func(t *testing.T) {
		long := "/* nr_service_guid=L,filler=" + strings.Repeat("z", 2*fullQueryTextHeadChars) + " */ SELECT 0; "
		text := long + statement
		head := text[:fullQueryTextHeadChars]
		require.Empty(t, sqlcomments.ExtractAndFilterComments(commentSourceText(statement, head, 0), keys))
		require.Equal(t, "nr_service_guid=L", sqlcomments.ExtractAndFilterComments(commentSourceText(text, "", 2*len(long)), keys))
	})
	t.Run("a leading comment that ends exactly at the end of the head is read", func(t *testing.T) {
		comment := "/* nr_service_guid=X,filler="
		comment += strings.Repeat("z", fullQueryTextHeadChars-len(comment)-len(" */")) + " */"
		require.Len(t, comment, fullQueryTextHeadChars)
		head := (comment + "SELECT 0; " + statement)[:fullQueryTextHeadChars]
		require.Equal(t, "nr_service_guid=X", sqlcomments.ExtractAndFilterComments(commentSourceText("", head, 0), keys))
	})
}

// TestREADMEDocumentsTheWindowAndHeadSizes keeps the sizes in the README the sizes the receiver uses.
func TestREADMEDocumentsTheWindowAndHeadSizes(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	require.NoError(t, err)
	withComma := func(n int) string { return fmt.Sprintf("%d,%03d", n/1000, n%1000) }
	require.Equal(t, 65536, fullQueryTextWindowChars)
	require.Equal(t, 16384, fullQueryTextHeadChars)
	require.Contains(t, string(readme), withComma(fullQueryTextWindowChars)+" characters before the statement")
	require.Contains(t, string(readme), withComma(fullQueryTextHeadChars)+" characters of the batch")
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
