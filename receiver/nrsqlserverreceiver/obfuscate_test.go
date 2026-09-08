// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver"

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestObfuscateSQL(t *testing.T) {
	expected, err := os.ReadFile(filepath.Join("testdata", "expectedSQL.sql"))
	assert.NoError(t, err)
	expectedSQL := strings.TrimSpace(string(expected))

	input, err := os.ReadFile(filepath.Join("testdata", "inputSQL.sql"))
	assert.NoError(t, err)

	result, err := newObfuscator().obfuscateSQLString(string(input))
	assert.NoError(t, err)
	assert.Equal(t, expectedSQL, result)
}

func TestObfuscateInvalidSQL(t *testing.T) {
	obf := newObfuscator()

	// The go-sqllexer engine (ObfuscateAndNormalize) is tolerant of malformed
	// SQL: instead of failing, it obfuscates what it can. An unclosed bracket
	// identifier no longer produces an error (it did with the legacy tokenizer),
	// so the statement is passed through rather than dropped.
	sql := "SELECT cpu_time AS [CPU Usage (time)"
	result, err := obf.obfuscateSQLString(sql)
	assert.NoError(t, err)
	assert.Equal(t, "SELECT cpu_time AS [CPU Usage (time)", result)

	// Aliases are stripped during normalization.
	sql = "SELECT cpu_time AS [CPU Usage Time]"
	expected := "SELECT cpu_time"
	result, err = obf.obfuscateSQLString(sql)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestObfuscateCommentOnlyStatement(t *testing.T) {
	obf := newObfuscator()

	// Comment-only statements (e.g. Blue Prism banners captured in
	// sys.dm_exec_sql_text) have no obfuscatable content. The legacy tokenizer
	// returned a "result is empty" error for these, which the scraper logged at
	// error level every scrape interval. The ObfuscateAndNormalize engine
	// returns an empty string with no error, which is the correct benign outcome.
	for _, sql := range []string{
		"--*INSERT-----------",
		"--*SELECT-----------",
		"--*UPDATE-----------",
		"/* banner only */",
		"-- a line comment",
	} {
		result, err := obf.obfuscateSQLString(sql)
		assert.NoError(t, err, "comment-only statement should not error: %q", sql)
		assert.Empty(t, result, "comment-only statement should obfuscate to empty: %q", sql)
	}
}

func TestObfuscateQueryPlan(t *testing.T) {
	expected, err := os.ReadFile(filepath.Join("testdata", "expectedQueryPlan.xml"))
	assert.NoError(t, err)
	expectedQueryPlan := strings.TrimSpace(string(expected))

	input, err := os.ReadFile(filepath.Join("testdata", "inputQueryPlan.xml"))
	assert.NoError(t, err)

	result, err := newObfuscator().obfuscateXMLPlan(string(input), zap.NewNop(), "a1b2c3d4e5f60708")
	assert.NoError(t, err)
	assert.Equal(t, expectedQueryPlan, result)
}

func TestInvalidQueryPlans(t *testing.T) {
	obf := newObfuscator()

	plan := `<ShowPlanXml</ShowPlanXML>`
	result, err := obf.obfuscateXMLPlan(plan, zap.NewNop(), "a1b2c3d4e5f60708")
	assert.Empty(t, result)
	assert.Error(t, err)

	plan = `<ShowPlanXML></ShowPlanXML`
	result, err = obf.obfuscateXMLPlan(plan, zap.NewNop(), "a1b2c3d4e5f60708")
	assert.Empty(t, result)
	assert.Error(t, err)

	plan = `<ShowPlanXML></ShowPlan>`
	result, err = obf.obfuscateXMLPlan(plan, zap.NewNop(), "a1b2c3d4e5f60708")
	assert.Empty(t, result)
	assert.Error(t, err)

	// A StatementText that the legacy tokenizer could not obfuscate (and would be
	// redacted to "?" by the #50070 fallback) is now obfuscated successfully by
	// the go-sqllexer engine, so the plan retains the useful normalized statement
	// with its literals redacted rather than losing the attribute entirely.
	plan = `<ShowPlanXML StatementText="[msdb].[dbo].[sysjobhistory].[run_duration] as [sjh].[run_duration]/(10000)*(3600)+[msdb].[dbo].[sysjobhistory].[run_duration] as [sjh].[run_duration]%(10000)/(100)*(60)+[msdb].[dbo].[sysjobhistory].[run_duration] as [sjh].[run_duration]%(100)"></ShowPlanXML>`
	result, err = obf.obfuscateXMLPlan(plan, zap.NewNop(), "a1b2c3d4e5f60708")
	assert.NoError(t, err)
	assert.Equal(t, `<ShowPlanXML StatementText="msdb.dbo.sysjobhistory.run_duration / ( ? ) * ( ? ) + msdb.dbo.sysjobhistory.run_duration % ( ? ) / ( ? ) * ( ? ) + msdb.dbo.sysjobhistory.run_duration % ( ? )"></ShowPlanXML>`, result)
}

func TestValidQueryPlans(t *testing.T) {
	obf := newObfuscator()

	plan := `<ShowPlanXML value="abc"></ShowPlanXML>`
	_, err := obf.obfuscateXMLPlan(plan, zap.NewNop(), "a1b2c3d4e5f60708")
	assert.NoError(t, err)

	plan = `<ShowPlanXML StatementText=""></ShowPlanXML>`
	_, err = obf.obfuscateXMLPlan(plan, zap.NewNop(), "a1b2c3d4e5f60708")
	assert.NoError(t, err)

	plan = `<ShowPlanXML StatementText="SELECT * FROM table"><!-- comment --></ShowPlanXML>`
	_, err = obf.obfuscateXMLPlan(plan, zap.NewNop(), "a1b2c3d4e5f60708")
	assert.NoError(t, err)
}

func TestSanitizeSQL(t *testing.T) {
	obf := newObfuscator()

	tests := []struct {
		name     string
		sql      string
		expected string
	}{
		{
			name:     "no zero width characters",
			sql:      "SELECT * FROM table",
			expected: "SELECT * FROM table",
		},
		{
			name:     "zero width space",
			sql:      "SELECT \u200b* FROM table",
			expected: "SELECT * FROM table",
		},
		{
			name:     "zero width non-joiner",
			sql:      "SELECT \u200c* FROM table",
			expected: "SELECT * FROM table",
		},
		{
			name:     "zero width joiner",
			sql:      "SELECT \u200d* FROM table",
			expected: "SELECT * FROM table",
		},
		{
			name:     "byte order mark",
			sql:      "\ufeffSELECT * FROM table",
			expected: "SELECT * FROM table",
		},
		{
			name:     "word joiner",
			sql:      "SELECT \u2060* FROM table",
			expected: "SELECT * FROM table",
		},
		{
			name:     "right to left override",
			sql:      "SELECT \u202e* FROM table",
			expected: "SELECT * FROM table",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, sanitizeSQL(tt.sql))
		})
	}

	// A statement containing a zero-width space (as seen in Blue Prism work-queue
	// statements from sys.dm_exec_sql_text) should obfuscate successfully after
	// sanitization instead of failing.
	statement := "SELECT \u200b[WQ_Definition] FROM [BluePrism].[WorkQueue]"
	result, err := obf.obfuscateSQLString(statement)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestObfuscateQueryPlanWithZeroWidthSpace(t *testing.T) {
	obf := newObfuscator()

	plan := "<ShowPlanXML StatementText=\"SELECT \u200b* FROM table\"></ShowPlanXML>"
	result, err := obf.obfuscateXMLPlan(plan, zap.NewNop(), "a1b2c3d4e5f60708")
	assert.NoError(t, err)
	assert.Equal(t, `<ShowPlanXML StatementText="SELECT * FROM table"></ShowPlanXML>`, result)
}

func TestUTF16OffsetToBytePos(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		utf16Offset     int
		expectedBytePos int
	}{
		{
			name:            "zero offset",
			input:           "SELECT * FROM users",
			utf16Offset:     0,
			expectedBytePos: 0,
		},
		{
			name:            "negative offset",
			input:           "SELECT * FROM users",
			utf16Offset:     -1,
			expectedBytePos: 0,
		},
		{
			name:            "ASCII only - offset 10 bytes (5 chars)",
			input:           "(@P0 int)SELECT * FROM users",
			utf16Offset:     18, // 9 chars * 2 bytes = 18
			expectedBytePos: 9,
		},
		{
			name:            "param declaration with comment",
			input:           "(@P0 int,@P1 bigint)/*nr_service_guid=\"abc\"*/UPDATE orders SET x = 1",
			utf16Offset:     90, // 45 chars * 2 = 90 -> points to 'U' of UPDATE
			expectedBytePos: 45,
		},
		{
			name:            "offset beyond string length",
			input:           "short",
			utf16Offset:     100,
			expectedBytePos: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf16OffsetToBytePos(tt.input, tt.utf16Offset)
			assert.Equal(t, tt.expectedBytePos, result)
		})
	}
}

func TestExtractLastBlockComment(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no comment",
			input:    "SELECT * FROM users",
			expected: "",
		},
		{
			name:     "single block comment",
			input:    `(@P0 int)/*nr_service_guid="abc123"*/UPDATE orders`,
			expected: `/*nr_service_guid="abc123"*/`,
		},
		{
			name:     "multiple comments returns last",
			input:    `/* first */ more text /* second */`,
			expected: `/* second */`,
		},
		{
			name:     "unclosed comment",
			input:    `/* unclosed comment`,
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLastBlockComment(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractCleanText(t *testing.T) {
	tests := []struct {
		name                 string
		fullText             string
		statementStartOffset int
		statementEndOffset   int
		expected             string
	}{
		{
			name:                 "zero offset falls back to stripParameterDeclarations",
			fullText:             "(@P0 int)SELECT * FROM users",
			statementStartOffset: 0,
			statementEndOffset:   0,
			expected:             "SELECT * FROM users",
		},
		{
			name:                 "instrumented JDBC with params and comment",
			fullText:             `(@P0 int,@P1 bigint)/*nr_service_guid="MTM5MDcxMjd8QVBN"*/UPDATE orders SET total = 100`,
			statementStartOffset: 116, // 58 chars * 2 = 116, points to 'U' of UPDATE
			statementEndOffset:   174, // 87 chars * 2 = 174, end of text
			expected:             `/*nr_service_guid="MTM5MDcxMjd8QVBN"*/UPDATE orders SET total = 100`,
		},
		{
			name:                 "uninstrumented with params only",
			fullText:             "(@P0 int,@P1 bigint)UPDATE orders SET total = 100",
			statementStartOffset: 40,  // 20 chars * 2 = 40
			statementEndOffset:   100, // 50 chars * 2 = 100
			expected:             "UPDATE orders SET total = 100",
		},
		{
			name:                 "no params no comment",
			fullText:             "SELECT * FROM users WHERE id = 1",
			statementStartOffset: 0,
			statementEndOffset:   64,
			expected:             "SELECT * FROM users WHERE id = 1",
		},
		{
			name:                 "comment only no params",
			fullText:             `/*nr_service_guid="abc"*/SELECT * FROM users`,
			statementStartOffset: 50, // 25 chars * 2 = 50
			statementEndOffset:   90, // 45 chars * 2 = 90
			expected:             `/*nr_service_guid="abc"*/SELECT * FROM users`,
		},
		{
			name:                 "offset beyond text length falls back",
			fullText:             "(@P0 int)SELECT * FROM users",
			statementStartOffset: 9999,
			statementEndOffset:   9999,
			expected:             "SELECT * FROM users",
		},
		{
			name:                 "batch with multiple statements uses end offset to bound",
			fullText:             "(@P0 int)/*nr_service_guid=\"x\"*/UPDATE t1 SET a=1;SELECT * FROM t2",
			statementStartOffset: 64, // 32 chars * 2 = 64, 'U' of UPDATE
			statementEndOffset:   96, // 48 chars * 2 = 96, inclusive offset of last char '1'
			expected:             `/*nr_service_guid="x"*/UPDATE t1 SET a=1`,
		},
		{
			name:                 "zero end offset means take to end of string",
			fullText:             "(@P0 int)SELECT * FROM users",
			statementStartOffset: 18, // 9 chars * 2 = 18
			statementEndOffset:   0,
			expected:             "SELECT * FROM users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCleanText(tt.fullText, tt.statementStartOffset, tt.statementEndOffset)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestObfuscateSQLServerBackslashLiteral(t *testing.T) {
	obf := newObfuscator()

	result, err := obf.obfuscateSQLString(
		`SELECT REPLACE(@@SERVERNAME, '\', ':'), HOST_NAME(), 42`,
	)

	require.NoError(t, err)
	assert.Equal(
		t,
		"SELECT REPLACE ( @@SERVERNAME, ?, ? ), HOST_NAME ( ), ?",
		result,
	)
}
