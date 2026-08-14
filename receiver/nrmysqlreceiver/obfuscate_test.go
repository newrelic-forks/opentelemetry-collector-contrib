// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrmysqlreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrmysqlreceiver"

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObfuscateSQLMalformedInput(t *testing.T) {
	// obfuscate_and_normalize (matching nroracledbreceiver/nrsqlserverreceiver) tolerates
	// malformed SQL rather than erroring — an unterminated string literal is obfuscated
	// away instead of surfacing a parse error.
	result, err := newObfuscator().obfuscateSQLString("SELECT 'unterminated")
	assert.NoError(t, err)
	assert.Equal(t, "SELECT ?", result)
}

func TestObfuscatePlanError(t *testing.T) {
	// Malformed JSON causes ObfuscateSQLExecPlan to return an error.
	_, err := newObfuscator().obfuscatePlan("{invalid json")
	assert.Error(t, err)
}

func TestObfuscateSQLWithComments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "APM correlation comment tag at start",
			input:    `/*nr_service_guid='abc123',traceparent='00-abcd-1234-01'*/ SELECT * FROM orders WHERE id = 5 AND status = 'shipped'`,
			expected: `? SELECT * FROM orders WHERE id = ? AND status = ?`,
		},
		{
			// obfuscate_and_normalize collapses newlines/whitespace to single spaces,
			// unlike Oracle's normalizer which preserves line breaks.
			name: "multiline comment at start",
			input: `/* Fetching active admin profiles */
SELECT * FROM profiles
WHERE role = 'admin' AND structural_id = 9954`,
			expected: `? SELECT * FROM profiles WHERE role = ? AND structural_id = ?`,
		},
		{
			name: "inline comment at end",
			input: `SELECT * FROM profiles
WHERE role = 'admin' AND structural_id = 9954 -- Verification filter`,
			expected: `SELECT * FROM profiles WHERE role = ? AND structural_id = ? ?`,
		},
		{
			name: "comment in middle of query",
			input: `SELECT * FROM employees
/* Get high earners */
WHERE salary > 100000`,
			expected: `SELECT * FROM employees ? WHERE salary > ?`,
		},
		{
			// Unlike Oracle, MySQL's obfuscator DOES collect "#" hash comments.
			name: "hash comment style",
			input: `SELECT * FROM orders
WHERE order_date > '2024-01-01' # Recent orders only`,
			expected: `SELECT * FROM orders WHERE order_date > ? ?`,
		},
		{
			name:     "comment with optimizer hint",
			input:    `SELECT /*+ INDEX(orders idx_orders_status) */ * FROM orders WHERE status = 'pending'`,
			expected: `SELECT ? * FROM orders WHERE status = ?`,
		},
	}

	obf := newObfuscator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := obf.obfuscateSQLString(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result, "Comments should be replaced with ? during obfuscation")
		})
	}
}

func TestObfuscateSQLStringWithComment(t *testing.T) {
	tests := []struct {
		name       string
		digestText string
		rawSQLText string
		expected   string
	}{
		{
			// The common, real-world case: MySQL's own server-side digesting
			// (performance_schema DIGEST_TEXT / events_statements_summary_by_digest's
			// digest_text) has already stripped the leading APM comment tag before the
			// receiver ever sees digestText, but the raw *_TEXT column (SQL_TEXT /
			// QUERY_SAMPLE_TEXT) still has it — so the marker has to come from there.
			name:       "digest already comment-free, raw text has the comment",
			digestText: `SELECT id FROM orders WHERE id = ?`,
			rawSQLText: `/*nr_service_guid="abc123"*/SELECT id FROM orders WHERE id = 5`,
			expected:   `? SELECT id FROM orders WHERE id = ?`,
		},
		{
			// Multi-line leading APM comment in the raw text. The (?s) dotall fix in
			// sqlcomments must detect it so the marker is still added (some agents/
			// drivers pretty-print the correlation tag across several lines).
			name:       "multi-line leading comment in raw text",
			digestText: `SELECT id FROM orders WHERE id = ?`,
			rawSQLText: "/*\n nr_service_guid=\"abc123\",\n traceparent=\"xyz\" \n*/ SELECT id FROM orders WHERE id = 5",
			expected:   `? SELECT id FROM orders WHERE id = ?`,
		},
		{
			name:       "no comment anywhere",
			digestText: `SELECT id FROM orders WHERE id = ?`,
			rawSQLText: `SELECT id FROM orders WHERE id = 5`,
			expected:   `SELECT id FROM orders WHERE id = ?`,
		},
		{
			// Rare fallback case: DIGEST_TEXT itself carries the comment (e.g. a
			// raw-text fallback was used upstream because DIGEST_TEXT was
			// unavailable). obfuscateSQLString's own comment-collection pass already
			// redacts it — must not double up to "? ? SELECT ...".
			name:       "digest text itself still has the comment (no double marker)",
			digestText: `/*nr_service_guid="abc123"*/SELECT id FROM orders WHERE id = 5`,
			rawSQLText: `/*nr_service_guid="abc123"*/SELECT id FROM orders WHERE id = 5`,
			expected:   `? SELECT id FROM orders WHERE id = ?`,
		},
		{
			// MySQL <8 / MariaDB fallback template path: querySampleText/sqlText is "".
			name:       "empty raw text (no sample available)",
			digestText: `SELECT id FROM orders WHERE id = ?`,
			rawSQLText: ``,
			expected:   `SELECT id FROM orders WHERE id = ?`,
		},
	}

	obf := newObfuscator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := obf.obfuscateSQLStringWithComment(tt.digestText, tt.rawSQLText)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestObfuscateSQL(t *testing.T) {
	expected, err := os.ReadFile(filepath.Join("testdata", "obfuscate", "expectedSQL.sql"))
	assert.NoError(t, err)
	expectedSQL := strings.TrimSpace(string(expected))

	input, err := os.ReadFile(filepath.Join("testdata", "obfuscate", "inputSQL.sql"))
	assert.NoError(t, err)

	result, err := newObfuscator().obfuscateSQLString(string(input))
	assert.NoError(t, err)
	assert.Equal(t, expectedSQL, result)
}

// runPlanTests is a helper that drives table-driven tests for plan obfuscation.
// planFunc is the method under test.
func runPlanTests(t *testing.T, planFunc func(string) (string, error), tests []struct {
	name         string
	inputFile    string
	expectedFile string
},
) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("testdata", "obfuscate", tc.inputFile))
			require.NoError(t, err)

			result, err := planFunc(string(input))
			require.NoError(t, err)

			expected, err := os.ReadFile(filepath.Join("testdata", "obfuscate", tc.expectedFile))
			require.NoError(t, err)

			// Normalize JSON for comparison to ignore formatting differences
			var resultJSON, expectedJSON any
			require.NoError(t, json.Unmarshal([]byte(result), &resultJSON))
			require.NoError(t, json.Unmarshal(expected, &expectedJSON))

			assert.Equal(t, expectedJSON, resultJSON)
		})
	}
}

func TestObfuscatePlan(t *testing.T) {
	// MySQL 8.4 EXPLAIN FORMAT=JSON produces two formats:
	//   Version 1 (default, explain_json_format_version=1): query_block → ordering_operation → table → attached_condition
	//   Version 2 (explain_json_format_version=2):          query + inputs array, each node has condition/operation/access_type
	// Fixtures in testdata/obfuscate/ were captured from a MySQL 8.4 instance using EXPLAIN FORMAT=JSON.
	runPlanTests(t, newObfuscator().obfuscatePlan, []struct {
		name         string
		inputFile    string
		expectedFile string
	}{
		{
			name:         "version1_query_block",
			inputFile:    "inputQueryPlan.json",
			expectedFile: "expectedQueryPlan.json",
		},
		{
			name:         "version2_inputs_array",
			inputFile:    "inputQueryPlanV2.json",
			expectedFile: "expectedQueryPlanV2.json",
		},
	})
}
