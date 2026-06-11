// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlserverreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver"

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
	sql := "SELECT cpu_time AS [CPU Usage (time)"
	result, err := obf.obfuscateSQLString(sql)

	assert.Error(t, err)
	assert.Empty(t, result)

	sql = "SELECT cpu_time AS [CPU Usage Time]"
	expected := "SELECT cpu_time"
	result, err = obf.obfuscateSQLString(sql)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestObfuscateQueryPlan(t *testing.T) {
	expected, err := os.ReadFile(filepath.Join("testdata", "expectedQueryPlan.xml"))
	assert.NoError(t, err)
	expectedQueryPlan := strings.TrimSpace(string(expected))

	input, err := os.ReadFile(filepath.Join("testdata", "inputQueryPlan.xml"))
	assert.NoError(t, err)

	result, err := newObfuscator().obfuscateXMLPlan(string(input))
	assert.NoError(t, err)
	assert.Equal(t, expectedQueryPlan, result)
}

func TestInvalidQueryPlans(t *testing.T) {
	obf := newObfuscator()

	plan := `<ShowPlanXml</ShowPlanXML>`
	result, err := obf.obfuscateXMLPlan(plan)
	assert.Empty(t, result)
	assert.Error(t, err)

	plan = `<ShowPlanXML></ShowPlanXML`
	result, err = obf.obfuscateXMLPlan(plan)
	assert.Empty(t, result)
	assert.Error(t, err)

	plan = `<ShowPlanXML></ShowPlan>`
	result, err = obf.obfuscateXMLPlan(plan)
	assert.Empty(t, result)
	assert.Error(t, err)

	// obfuscate failure, return empty string
	plan = `<ShowPlanXML StatementText="[msdb].[dbo].[sysjobhistory].[run_duration] as [sjh].[run_duration]/(10000)*(3600)+[msdb].[dbo].[sysjobhistory].[run_duration] as [sjh].[run_duration]%(10000)/(100)*(60)+[msdb].[dbo].[sysjobhistory].[run_duration] as [sjh].[run_duration]%(100)"></ShowPlanXML>`
	result, err = obf.obfuscateXMLPlan(plan)
	assert.Empty(t, result)
	assert.NoError(t, err)
}

func TestValidQueryPlans(t *testing.T) {
	obf := newObfuscator()

	plan := `<ShowPlanXML value="abc"></ShowPlanXML>`
	_, err := obf.obfuscateXMLPlan(plan)
	assert.NoError(t, err)

	plan = `<ShowPlanXML StatementText=""></ShowPlanXML>`
	_, err = obf.obfuscateXMLPlan(plan)
	assert.NoError(t, err)

	plan = `<ShowPlanXML StatementText="SELECT * FROM table"><!-- comment --></ShowPlanXML>`
	_, err = obf.obfuscateXMLPlan(plan)
	assert.NoError(t, err)
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
			statementEndOffset:   98, // 49 chars * 2 = 98, up to ';'
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
