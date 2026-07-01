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
			expected: "SELECT*FROMUSERS",
		},
		{
			name:     "already uppercase",
			input:    "SELECT * FROM USERS",
			expected: "SELECT*FROMUSERS",
		},
		{
			name:     "mixed case",
			input:    "SeLeCt * FrOm UsErS",
			expected: "SELECT*FROMUSERS",
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
			expected: "SELECT*FROMUSERSWHERENAME=?",
		},
		{
			name:     "multiple string literals",
			input:    "SELECT * FROM users WHERE name = 'John' AND email = 'john@example.com'",
			expected: "SELECT*FROMUSERSWHERENAME=?ANDEMAIL=?",
		},
		{
			name:     "string with escaped quote",
			input:    "SELECT * FROM users WHERE name = 'O''Brien'",
			expected: "SELECT*FROMUSERSWHERENAME=?",
		},
		{
			name:     "empty string",
			input:    "SELECT * FROM users WHERE name = ''",
			expected: "SELECT*FROMUSERSWHERENAME=?",
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
			expected: "SELECT*FROMUSERSWHEREID=?",
		},
		{
			name:     "decimal literal",
			input:    "SELECT * FROM data WHERE value = 45.67",
			expected: "SELECT*FROMDATAWHEREVALUE=?",
		},
		{
			name:     "negative number",
			input:    "SELECT * FROM data WHERE value = -123.45",
			expected: "SELECT*FROMDATAWHEREVALUE=?",
		},
		{
			name:     "scientific notation",
			input:    "SELECT * FROM data WHERE value = 1.5E-10",
			expected: "SELECT*FROMDATAWHEREVALUE=?",
		},
		{
			name:     "number in column name not replaced",
			input:    "SELECT column1 FROM table WHERE column1 = 123",
			expected: "SELECTCOLUMN1FROMTABLEWHERECOLUMN1=?",
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
			expected: "SELECT*FROMUSERSWHEREID=?",
		},
		{
			name:     "Oracle named bind variable",
			input:    "SELECT * FROM users WHERE id = :userId",
			expected: "SELECT*FROMUSERSWHEREID=?",
		},
		{
			name:     "Oracle numeric bind variable",
			input:    "SELECT * FROM users WHERE id = :1",
			expected: "SELECT*FROMUSERSWHEREID=?",
		},
		{
			name:     "PostgreSQL placeholder",
			input:    "SELECT * FROM users WHERE id = $1 AND age = $2",
			expected: "SELECT*FROMUSERSWHEREID=?ANDAGE=?",
		},
		{
			name:     "SQL Server placeholder",
			input:    "SELECT * FROM users WHERE id = @userId",
			expected: "SELECT*FROMUSERSWHEREID=?",
		},
		{
			name:     "Python placeholder",
			input:    "SELECT * FROM users WHERE id = %(userId)s",
			expected: "SELECT*FROMUSERSWHEREID=?",
		},
		{
			name:     "multiple different placeholders",
			input:    "SELECT * FROM users WHERE id = :id AND age = @age",
			expected: "SELECT*FROMUSERSWHEREID=?ANDAGE=?",
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
			expected: "SELECT*FROMUSERSWHEREIDIN(?)",
		},
		{
			name:     "IN with multiple string literals",
			input:    "SELECT * FROM users WHERE name IN ('Alice', 'Bob', 'Charlie')",
			expected: "SELECT*FROMUSERSWHERENAMEIN(?)",
		},
		{
			name:     "IN with placeholders",
			input:    "SELECT * FROM users WHERE id IN (?, ?, ?)",
			expected: "SELECT*FROMUSERSWHEREIDIN(?)",
		},
		{
			name:     "IN with mixed literals",
			input:    "SELECT * FROM data WHERE value IN (1, 'text', 3.14)",
			expected: "SELECT*FROMDATAWHEREVALUEIN(?)",
		},
		{
			name:     "IN with single value not normalized",
			input:    "SELECT * FROM users WHERE id IN (1)",
			expected: "SELECT*FROMUSERSWHEREIDIN(?)",
		},
		{
			name:     "IN with subquery not normalized",
			input:    "SELECT * FROM users WHERE id IN (SELECT id FROM admins)",
			expected: "SELECT*FROMUSERSWHEREIDIN(SELECTIDFROMADMINS)",
		},
		{
			name:     "parentheses not preceded by IN",
			input:    "SELECT (a + b) FROM users WHERE id = 1",
			expected: "SELECT(A+B)FROMUSERSWHEREID=?",
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
			expected: "SELECT*?FROMUSERS",
		},
		{
			name:     "single-line comment with --",
			input:    "SELECT * FROM users -- this is a comment\nWHERE id = 1",
			expected: "SELECT*FROMUSERS?WHEREID=?",
		},
		{
			name:     "hash comment",
			input:    "SELECT * FROM users # comment\nWHERE id = 1",
			expected: "SELECT*FROMUSERS?WHEREID=?",
		},
		{
			name:     "leading comment",
			input:    "/* leading comment */ SELECT * FROM users",
			expected: "?SELECT*FROMUSERS",
		},
		{
			name:     "comment with nr_service_guid",
			input:    "/* nr_service_guid=abc-123 */ SELECT * FROM users WHERE id = 1",
			expected: "?SELECT*FROMUSERSWHEREID=?",
		},
		{
			name:     "multiple comments",
			input:    "SELECT /* comment1 */ * FROM /* comment2 */ users",
			expected: "SELECT?*FROM?USERS",
		},
		{
			name:     "unclosed comment",
			input:    "SELECT * FROM users /* unclosed",
			expected: "SELECT*FROMUSERS?",
		},
		{
			// '#' inside an identifier (Oracle obj#/con#) must NOT be treated as a comment
			name:     "hash inside Oracle identifiers preserved",
			input:    "SELECT obj#, con# FROM RecycleBin$",
			expected: "SELECTOBJ#,CON#FROMRECYCLEBIN$",
		},
		{
			name:     "Oracle RecycleBin$ query not swallowed by #",
			input:    "select obj#, type#, flags, related, bo, purgeobj, con#    from RecycleBin$    where ts#=:? and to_number(bitand(flags, ?)) = ?    order by dropscn",
			expected: "SELECTOBJ#,TYPE#,FLAGS,RELATED,BO,PURGEOBJ,CON#FROMRECYCLEBIN$WHERETS#=:?ANDTO_NUMBER(BITAND(FLAGS,?))=?ORDERBYDROPSCN",
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
			expected: "SELECT*FROMUSERS",
		},
		{
			name:     "leading whitespace trimmed",
			input:    "   SELECT * FROM users",
			expected: "SELECT*FROMUSERS",
		},
		{
			name:     "trailing whitespace trimmed",
			input:    "SELECT * FROM users   ",
			expected: "SELECT*FROMUSERS",
		},
		{
			name:     "tabs and newlines normalized",
			input:    "SELECT\t*\nFROM\r\nusers",
			expected: "SELECT*FROMUSERS",
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
		name               string
		input              string
		expectedNormalized string
		expectedHash       string
	}{
		{
			name:               "complete normalization and hash",
			input:              "SELECT * FROM users WHERE id = 123 AND name = 'John'",
			expectedNormalized: "SELECT*FROMUSERSWHEREID=?ANDNAME=?",
			expectedHash:       "e78f13a21009ebcb6fdef9e996a24c9d",
		},
		{
			name:               "with comments",
			input:              "/* comment */ SELECT * FROM users WHERE id = 1",
			expectedNormalized: "?SELECT*FROMUSERSWHEREID=?",
			expectedHash:       "690b61bb71c40c8825f7206e7d9c63ec",
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

func TestNormalizeSQLAndHash_EmptyReturnsEmptyHash(t *testing.T) {
	// Matches Java SqlHashUtil.normalizeAndHash: input that is empty or
	// normalizes to empty yields an empty hash, not the MD5 of "".
	for _, input := range []string{"", "   ", "\t\n\r"} {
		t.Run(input, func(t *testing.T) {
			normalized, hash := NormalizeSQLAndHash(input)
			assert.Empty(t, normalized)
			assert.Empty(t, hash)
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
			expected: "??",
		},
		{
			name:     "string with escaped quotes",
			input:    "SELECT * FROM users WHERE name = 'O''Brien'",
			expected: "SELECT*FROMUSERSWHERENAME=?",
		},
		{
			name:     "string with backslash escape",
			input:    "SELECT * FROM users WHERE path = 'C:\\\\Users\\\\John'",
			expected: "SELECT*FROMUSERSWHEREPATH=?",
		},
		{
			name:     "negative numbers",
			input:    "SELECT * FROM data WHERE value = -123.45",
			expected: "SELECT*FROMDATAWHEREVALUE=?",
		},
		{
			name:     "positive sign",
			input:    "SELECT * FROM data WHERE value = +123.45",
			expected: "SELECT*FROMDATAWHEREVALUE=?",
		},
		{
			name:     "scientific notation variations",
			input:    "SELECT * FROM data WHERE a = 1.5E-10 AND b = 2E+5 AND c = 3E10",
			expected: "SELECT*FROMDATAWHEREA=?ANDB=?ANDC=?",
		},
		{
			name:     "decimal without leading digit",
			input:    "SELECT * FROM data WHERE value = .5",
			expected: "SELECT*FROMDATAWHEREVALUE=?",
		},
		{
			name:     "number in column name not replaced",
			input:    "SELECT column1, table2.field3 FROM table2 WHERE column1 = 123",
			expected: "SELECTCOLUMN1,TABLE2.FIELD3FROMTABLE2WHERECOLUMN1=?",
		},
		{
			name:     "complex query with everything",
			input:    "/* comment */ SELECT u.id, u.name FROM users u WHERE u.id IN (1,2,3) AND u.age > 25 -- inline comment\nAND u.name = 'John'",
			expected: "?SELECTU.ID,U.NAMEFROMUSERSUWHEREU.IDIN(?)ANDU.AGE>??ANDU.NAME=?",
		},
		{
			name:     "nested parentheses",
			input:    "SELECT ((a + b) * c) FROM data WHERE x = 1",
			expected: "SELECT((A+B)*C)FROMDATAWHEREX=?",
		},
		{
			name:     "unclosed string literal",
			input:    "SELECT * FROM users WHERE name = 'unclosed",
			expected: "SELECT*FROMUSERSWHERENAME=?",
		},
		{
			name:     "multiple consecutive placeholders",
			input:    "SELECT * FROM users WHERE a = ? AND b = :param AND c = $1 AND dcol = @var",
			expected: "SELECT*FROMUSERSWHEREA=?ANDB=?ANDC=?ANDDCOL=?",
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
	assert.Empty(t, NormalizeSQL(""))
	assert.Empty(t, NormalizeSQL("   "))
	assert.Empty(t, NormalizeSQL("\t\n\r"))
}

func TestNormalizeSQL_SpaceBeforeComma(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Oracle bind variable with space before comma",
			input:    "UPDATE ORDERS SET status = :1 , updated_at = CURRENT_TIMESTAMP WHERE order_id = :2",
			expected: "UPDATEORDERSSETSTATUS=?,UPDATED_AT=CURRENT_TIMESTAMPWHEREORDER_ID=?",
		},
		{
			name:     "Multiple spaces before comma",
			input:    "SELECT col1   , col2  , col3 FROM table",
			expected: "SELECTCOL1,COL2,COL3FROMTABLE",
		},
		{
			name:     "No space before comma (should not change)",
			input:    "SELECT col1, col2, col3 FROM table",
			expected: "SELECTCOL1,COL2,COL3FROMTABLE",
		},
		{
			name:     "Tab before comma",
			input:    "SELECT col1\t, col2 FROM table",
			expected: "SELECTCOL1,COL2FROMTABLE",
		},
		{
			name:     "Space before comma in IN clause",
			input:    "SELECT * FROM users WHERE id IN (1 , 2 , 3)",
			expected: "SELECT*FROMUSERSWHEREIDIN(?)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeSQL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeSQL_SpaceBeforeCommaHash(t *testing.T) {
	// The key test: Oracle SQL with space before comma should generate same hash as without
	oracleSQL := "UPDATE ORDERS SET status = :1 , updated_at = CURRENT_TIMESTAMP WHERE order_id = :2"
	normalSQL := "UPDATE ORDERS SET status = :1, updated_at = CURRENT_TIMESTAMP WHERE order_id = :2"

	_, oracleHash := NormalizeSQLAndHash(oracleSQL)
	_, normalHash := NormalizeSQLAndHash(normalSQL)

	assert.Equal(t, normalHash, oracleHash, "Hashes should match when only difference is space before comma")
}
