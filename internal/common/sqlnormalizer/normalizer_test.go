// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlnormalizer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeSQL_BasicUppercase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple select",
			input:    "select * from users",
			expected: "SELECT * FROM USERS",
		},
		{
			name:     "already uppercase",
			input:    "SELECT * FROM USERS",
			expected: "SELECT * FROM USERS",
		},
		{
			name:     "mixed case",
			input:    "SeLeCt * FrOm UsErS",
			expected: "SELECT * FROM USERS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSQL_StringLiterals(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single string literal",
			input:    "SELECT * FROM users WHERE name = 'John'",
			expected: "SELECT * FROM USERS WHERE NAME = ?",
		},
		{
			name:     "multiple string literals",
			input:    "SELECT * FROM users WHERE name = 'John' AND email = 'john@example.com'",
			expected: "SELECT * FROM USERS WHERE NAME = ? AND EMAIL = ?",
		},
		{
			name:     "string with escaped quote",
			input:    "SELECT * FROM users WHERE name = 'O''Brien'",
			expected: "SELECT * FROM USERS WHERE NAME = ?",
		},
		{
			name:     "empty string",
			input:    "SELECT * FROM users WHERE name = ''",
			expected: "SELECT * FROM USERS WHERE NAME = ?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSQL_NumericLiterals(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "integer literal",
			input:    "SELECT * FROM users WHERE id = 123",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "decimal literal",
			input:    "SELECT * FROM data WHERE value = 45.67",
			expected: "SELECT * FROM DATA WHERE VALUE = ?",
		},
		{
			name:     "negative number",
			input:    "SELECT * FROM data WHERE value = -123.45",
			expected: "SELECT * FROM DATA WHERE VALUE = ?",
		},
		{
			name:     "scientific notation",
			input:    "SELECT * FROM data WHERE value = 1.5E-10",
			expected: "SELECT * FROM DATA WHERE VALUE = ?",
		},
		{
			name:     "number in column name not replaced",
			input:    "SELECT column1 FROM table WHERE column1 = 123",
			expected: "SELECT COLUMN1 FROM TABLE WHERE COLUMN1 = ?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSQL_Placeholders(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "JDBC placeholder already normalized",
			input:    "SELECT * FROM users WHERE id = ?",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "Oracle named bind variable",
			input:    "SELECT * FROM users WHERE id = :userId",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "Oracle numeric bind variable",
			input:    "SELECT * FROM users WHERE id = :1",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "PostgreSQL placeholder",
			input:    "SELECT * FROM users WHERE id = $1 AND age = $2",
			expected: "SELECT * FROM USERS WHERE ID = ? AND AGE = ?",
		},
		{
			name:     "SQL Server placeholder",
			input:    "SELECT * FROM users WHERE id = @userId",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "Python placeholder",
			input:    "SELECT * FROM users WHERE id = %(userId)s",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "multiple different placeholders",
			input:    "SELECT * FROM users WHERE id = :id AND age = @age",
			expected: "SELECT * FROM USERS WHERE ID = ? AND AGE = ?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSQL_InClause(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "IN with multiple numeric literals",
			input:    "SELECT * FROM users WHERE id IN (1, 2, 3)",
			expected: "SELECT * FROM USERS WHERE ID IN (?)",
		},
		{
			name:     "IN with multiple string literals",
			input:    "SELECT * FROM users WHERE name IN ('Alice', 'Bob', 'Charlie')",
			expected: "SELECT * FROM USERS WHERE NAME IN (?)",
		},
		{
			name:     "IN with placeholders",
			input:    "SELECT * FROM users WHERE id IN (?, ?, ?)",
			expected: "SELECT * FROM USERS WHERE ID IN (?)",
		},
		{
			name:     "IN with mixed literals",
			input:    "SELECT * FROM data WHERE value IN (1, 'text', 3.14)",
			expected: "SELECT * FROM DATA WHERE VALUE IN (?)",
		},
		{
			name:     "IN with single value not normalized",
			input:    "SELECT * FROM users WHERE id IN (1)",
			expected: "SELECT * FROM USERS WHERE ID IN (?)",
		},
		{
			name:     "IN with subquery not normalized",
			input:    "SELECT * FROM users WHERE id IN (SELECT id FROM admins)",
			expected: "SELECT * FROM USERS WHERE ID IN (SELECT ID FROM ADMINS)",
		},
		{
			name:     "parentheses not preceded by IN",
			input:    "SELECT (a + b) FROM users WHERE id = 1",
			expected: "SELECT (A + B) FROM USERS WHERE ID = ?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSQL_Comments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "multi-line comment",
			input:    "SELECT * /* comment */ FROM users",
			expected: "SELECT * FROM USERS",
		},
		{
			name:     "single-line comment with --",
			input:    "SELECT * FROM users -- this is a comment\nWHERE id = 1",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "hash comment",
			input:    "SELECT * FROM users # comment\nWHERE id = 1",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "leading comment",
			input:    "/* leading comment */ SELECT * FROM users",
			expected: "SELECT * FROM USERS",
		},
		{
			name:     "comment with nr_service_guid",
			input:    "/* nr_service_guid=abc-123 */ SELECT * FROM users WHERE id = 1",
			expected: "SELECT * FROM USERS WHERE ID = ?",
		},
		{
			name:     "multiple comments",
			input:    "SELECT /* comment1 */ * FROM /* comment2 */ users",
			expected: "SELECT * FROM USERS",
		},
		{
			name:     "unclosed comment",
			input:    "SELECT * FROM users /* unclosed",
			expected: "SELECT * FROM USERS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSQL_Whitespace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "multiple spaces collapsed",
			input:    "SELECT  *    FROM     users",
			expected: "SELECT * FROM USERS",
		},
		{
			name:     "leading whitespace trimmed",
			input:    "   SELECT * FROM users",
			expected: "SELECT * FROM USERS",
		},
		{
			name:     "trailing whitespace trimmed",
			input:    "SELECT * FROM users   ",
			expected: "SELECT * FROM USERS",
		},
		{
			name:     "tabs and newlines normalized",
			input:    "SELECT\t*\nFROM\r\nusers",
			expected: "SELECT * FROM USERS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateMD5Hash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple query",
			input:    "SELECT * FROM USERS",
			expected: "06c445f7ade97a964f7c466575f8b508",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:     "query with parameters",
			input:    "SELECT * FROM USERS WHERE ID = ?",
			expected: "d1c08094cf228a33039e9ee0387ab83c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateMD5Hash(tt.input)
			assert.Equal(t, tt.expected, result)
			// Verify it's a valid MD5 hex string (32 characters, lowercase hex)
			assert.Len(t, result, 32)
			assert.Regexp(t, "^[a-f0-9]{32}$", result)
		})
	}
}

func TestNormalizeSQLAndHash(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		expectedNormalized string
		expectedHash       string
	}{
		{
			name:              "complete normalization and hash",
			input:             "SELECT * FROM users WHERE id = 123 AND name = 'John'",
			expectedNormalized: "SELECT * FROM USERS WHERE ID = ? AND NAME = ?",
			expectedHash:       "7f51338aa6d5fa3a27d698eb2f3fd166",
		},
		{
			name:              "with comments",
			input:             "/* comment */ SELECT * FROM users WHERE id = 1",
			expectedNormalized: "SELECT * FROM USERS WHERE ID = ?",
			expectedHash:       "d1c08094cf228a33039e9ee0387ab83c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, hash := NormalizeSQLAndHash(tt.input)
			assert.Equal(t, tt.expectedNormalized, normalized)
			assert.Equal(t, tt.expectedHash, hash)
		})
	}
}

func TestNormalizeSQL_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace only",
			input:    "   \t\n  ",
			expected: "",
		},
		{
			name:     "only comments",
			input:    "/* comment */ -- another comment",
			expected: "",
		},
		{
			name:     "string with escaped quotes",
			input:    "SELECT * FROM users WHERE name = 'O''Brien'",
			expected: "SELECT * FROM USERS WHERE NAME = ?",
		},
		{
			name:     "string with backslash escape",
			input:    "SELECT * FROM users WHERE path = 'C:\\\\Users\\\\John'",
			expected: "SELECT * FROM USERS WHERE PATH = ?",
		},
		{
			name:     "negative numbers",
			input:    "SELECT * FROM data WHERE value = -123.45",
			expected: "SELECT * FROM DATA WHERE VALUE = ?",
		},
		{
			name:     "positive sign",
			input:    "SELECT * FROM data WHERE value = +123.45",
			expected: "SELECT * FROM DATA WHERE VALUE = ?",
		},
		{
			name:     "scientific notation variations",
			input:    "SELECT * FROM data WHERE a = 1.5E-10 AND b = 2E+5 AND c = 3E10",
			expected: "SELECT * FROM DATA WHERE A = ? AND B = ? AND C = ?",
		},
		{
			name:     "decimal without leading digit",
			input:    "SELECT * FROM data WHERE value = .5",
			expected: "SELECT * FROM DATA WHERE VALUE = ?",
		},
		{
			name:     "number in column name not replaced",
			input:    "SELECT column1, table2.field3 FROM table2 WHERE column1 = 123",
			expected: "SELECT COLUMN1, TABLE2.FIELD3 FROM TABLE2 WHERE COLUMN1 = ?",
		},
		{
			name:     "complex query with everything",
			input:    "/* comment */ SELECT u.id, u.name FROM users u WHERE u.id IN (1,2,3) AND u.age > 25 -- inline comment\nAND u.name = 'John'",
			expected: "SELECT U.ID, U.NAME FROM USERS U WHERE U.ID IN (?) AND U.AGE > ? AND U.NAME = ?",
		},
		{
			name:     "nested parentheses",
			input:    "SELECT ((a + b) * c) FROM data WHERE x = 1",
			expected: "SELECT ((A + B) * C) FROM DATA WHERE X = ?",
		},
		{
			name:     "unclosed string literal",
			input:    "SELECT * FROM users WHERE name = 'unclosed",
			expected: "SELECT * FROM USERS WHERE NAME = ?",
		},
		{
			name:     "multiple consecutive placeholders",
			input:    "SELECT * FROM users WHERE a = ? AND b = :param AND c = $1 AND d = @var",
			expected: "SELECT * FROM USERS WHERE A = ? AND B = ? AND C = ? AND D = ?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSQL_EmptyAndNil(t *testing.T) {
	assert.Equal(t, "", NormalizeSQL(""))
	assert.Equal(t, "", NormalizeSQL("   "))
	assert.Equal(t, "", NormalizeSQL("\t\n\r"))
}
