// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package sqlnormalizer provides SQL normalization and MD5 hashing for APM-to-database query correlation.
//
// This package implements the exact same normalization logic as New Relic's Java APM agent
// (SqlStatementNormalizer.java), ensuring that both APM and database receivers generate
// identical MD5 hashes for the same SQL queries.
//
// Reference implementation:
// - apm-trace-consumer: SqlStatementNormalizer.java
// - apm-trace-consumer: SqlHashUtil.java
package sqlnormalizer // import "go.opentelemetry.io/collector/contrib/internal/common/sqlnormalizer"

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// sqlNormalizerState holds state during SQL normalization.
// This matches the SqlNormalizerState inner class in the Java reference implementation.
type sqlNormalizerState struct {
	sql               string
	length            int
	idx               int
	lastWasWhitespace bool
}

// newSQLNormalizerState creates a new state machine for SQL normalization.
func newSQLNormalizerState(sql string) *sqlNormalizerState {
	return &sqlNormalizerState{
		sql:               sql,
		length:            len(sql),
		idx:               0,
		lastWasWhitespace: true, // Start as true to trim leading whitespace
	}
}

// hasMore returns true if there are more characters to process.
func (s *sqlNormalizerState) hasMore() bool {
	return s.idx < s.length
}

// hasNext returns true if there is at least one more character after current.
func (s *sqlNormalizerState) hasNext() bool {
	return s.idx+1 < s.length
}

// current returns the current character.
func (s *sqlNormalizerState) current() byte {
	return s.sql[s.idx]
}

// peek returns the next character without advancing.
func (s *sqlNormalizerState) peek() byte {
	return s.sql[s.idx+1]
}

// advance moves to the next character.
func (s *sqlNormalizerState) advance() {
	s.idx++
}

// advanceBy moves forward by count characters.
func (s *sqlNormalizerState) advanceBy(count int) {
	s.idx += count
}

// isIdentifierChar checks if a character is valid in an identifier.
// Matches Java: Character.isLetterOrDigit(c) || c == '_'
func isIdentifierChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// isNumericLiteral checks if current position is a numeric literal.
// Matches Java implementation logic.
func isNumericLiteral(state *sqlNormalizerState) bool {
	c := state.current()

	// Check for digit, minus, plus, or decimal point
	if !((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.') {
		return false
	}

	// Make sure it's not part of an identifier
	if state.idx > 0 {
		prev := state.sql[state.idx-1]
		// If preceded by letter, underscore, or backtick, it's part of identifier
		if (prev >= 'A' && prev <= 'Z') || prev == '_' || prev == '`' {
			return false
		}
	}

	// Look ahead to confirm it's a complete number
	savedIdx := state.idx

	// Handle optional sign
	if c == '-' || c == '+' {
		state.advance()
		if !state.hasMore() {
			state.idx = savedIdx
			return false
		}
		c = state.current()
	}

	// Numbers starting with decimal point
	if c == '.' {
		state.advance()
		if !state.hasMore() || !(state.current() >= '0' && state.current() <= '9') {
			state.idx = savedIdx
			return false
		}
		// Looks like an actual decimal number
		state.idx = savedIdx
		return true
	}

	// Must have at least one digit before optional decimal point
	if !(c >= '0' && c <= '9') {
		state.idx = savedIdx
		return false
	}

	state.idx = savedIdx
	return true
}

// skipNumericLiteral skips over a numeric literal.
// Matches Java implementation.
func skipNumericLiteral(state *sqlNormalizerState) {
	// + or - sign
	c := state.current()
	if c == '-' || c == '+' {
		state.advance()
	}

	// Skip any digits
	for state.hasMore() && (state.current() >= '0' && state.current() <= '9') {
		state.advance()
	}

	// Decimal point
	if state.hasMore() && state.current() == '.' {
		state.advance()
		for state.hasMore() && (state.current() >= '0' && state.current() <= '9') {
			state.advance()
		}
	}

	// Scientific notation (1E10, 1E-5)
	if state.hasMore() && state.current() == 'E' {
		state.advance()
		if state.hasMore() && (state.current() == '+' || state.current() == '-') {
			state.advance()
		}
		for state.hasMore() && (state.current() >= '0' && state.current() <= '9') {
			state.advance()
		}
	}
}

// skipStringLiteral skips over a string literal, handling escaped quotes.
// Matches Java implementation.
func skipStringLiteral(state *sqlNormalizerState) {
	state.advance() // Skip the opening quote

	for state.hasMore() {
		c := state.current()

		if c == '\'' {
			// Check for escaped quote ''
			if state.hasNext() && state.peek() == '\'' {
				state.advanceBy(2) // Skip both quotes
			} else {
				state.advance() // Skip closing quote
				return
			}
		} else if c == '\\' {
			// Handle backslash escaping (MySQL, PostgreSQL)
			state.advance()
			if state.hasMore() {
				state.advance()
			}
		} else {
			state.advance()
		}
	}
}

// isPlaceholder checks if current position is a parameter placeholder.
// Supports: ? (JDBC), :name/:1 (Oracle), $1 (PostgreSQL), @name (SQL Server), %(name)s (Python)
// Matches Java implementation.
func isPlaceholder(state *sqlNormalizerState) bool {
	c := state.current()

	// JDBC style: ?
	if c == '?' {
		return true
	}

	// PostgreSQL style: $1, $2...
	if c == '$' && state.hasNext() && (state.peek() >= '0' && state.peek() <= '9') {
		return true
	}

	// Oracle/Python style: :name or :1
	if c == ':' && state.hasNext() && isIdentifierChar(state.peek()) {
		return true
	}

	// SQL Server style: @name or @p1
	if c == '@' && state.hasNext() && isIdentifierChar(state.peek()) {
		return true
	}

	// Python style: %(name)s
	if c == '%' && state.hasNext() && state.peek() == '(' {
		return true
	}

	return false
}

// skipPlaceholder skips over any type of prepared statement placeholder.
// Matches Java implementation.
func skipPlaceholder(state *sqlNormalizerState) {
	c := state.current()

	if c == '?' {
		// JDBC placeholder
		state.advance()
	} else if c == '$' {
		// PostgreSQL: $1, $2...
		state.advance() // Skip $
		for state.hasMore() && (state.current() >= '0' && state.current() <= '9') {
			state.advance()
		}
	} else if c == ':' || c == '@' {
		// Oracle/Python/SQL Server: :NAME, @NAME
		state.advance() // Skip : or @
		for state.hasMore() && isIdentifierChar(state.current()) {
			state.advance()
		}
	} else if c == '%' && state.hasNext() && state.peek() == '(' {
		// Python: %(NAME)S
		state.advanceBy(2) // Skip %(
		for state.hasMore() && state.current() != ')' {
			state.advance()
		}
		if state.hasMore() {
			state.advance() // Skip )
		}
		if state.hasMore() && state.current() == 'S' {
			state.advance() // Skip S (uppercased)
		}
	}
}

// NormalizeSQL normalizes a SQL statement based on New Relic Java agent rules.
//
// Normalization rules:
// - Converts to uppercase
// - Normalizes all parameter placeholders to '?'
// - Replaces string and numeric literals with '?'
// - Removes comments (/* */, --, #)
// - Normalizes whitespace
// - Normalizes IN clauses: IN (1,2,3) → IN (?)
//
// This function implements the exact same algorithm as SqlStatementNormalizer.normalizeSql()
// in the apm-trace-consumer repository.
func NormalizeSQL(sql string) string {
	if sql == "" {
		return ""
	}

	// Log original SQL
	originalSQL := sql
	fmt.Printf("[SQL Normalizer] BEFORE normalization:\n%s\n", originalSQL)

	// Phase 1: Convert to uppercase (matches Java: sql.toUpperCase(Locale.ROOT))
	sql = strings.ToUpper(sql)

	// Phase 2: Normalize parameters and literals
	sql = normalizeParametersAndLiterals(sql)

	// Phase 3: Remove comments and normalize whitespace
	normalizedSQL := removeCommentsAndNormalizeWhitespace(sql)

	// Log normalized SQL
	fmt.Printf("[SQL Normalizer] AFTER normalization:\n%s\n\n", normalizedSQL)

	return normalizedSQL
}

// isPrecededByIn checks if the result is preceded by "IN".
// Handles whitespace between "IN" and the current position.
// Matches Java implementation.
func isPrecededByIn(result *strings.Builder) bool {
	str := result.String()
	if len(str) < 2 {
		return false
	}

	// Scan backwards, skipping whitespace
	idx := len(str) - 1
	for idx >= 0 && (str[idx] == ' ' || str[idx] == '\t' || str[idx] == '\n' || str[idx] == '\r') {
		idx--
	}

	// Check if we have at least "IN" (2 characters)
	if idx < 1 {
		return false
	}

	// Check for "IN" - scanning backwards we see 'N' first, then 'I'
	if str[idx] == 'N' && str[idx-1] == 'I' {
		// Make sure "IN" is a complete token, not part of a larger word like "WITHIN"
		return idx < 2 || !isIdentifierChar(str[idx-2])
	}

	return false
}

// tryNormalizeInClause tries to normalize an IN clause like IN (1,2,3) or IN (?,?,?) to IN (?).
// If it's not a simple IN clause, returns the opening paren as-is.
// Matches Java implementation.
func tryNormalizeInClause(state *sqlNormalizerState) string {
	// Save position in case we need to backtrack
	saveIdx := state.idx

	state.advance() // Opening (

	itemCount := 0
	allParametersOrLiterals := true
	foundNonWhitespace := false

	// Scan the contents of the parentheses
	for state.hasMore() && state.current() != ')' {
		c := state.current()

		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			state.advance()
		} else if c == ',' {
			state.advance()
		} else if isPlaceholder(state) {
			foundNonWhitespace = true
			itemCount++
			skipPlaceholder(state)
		} else if isNumericLiteral(state) {
			foundNonWhitespace = true
			itemCount++
			skipNumericLiteral(state)
		} else if c == '\'' {
			foundNonWhitespace = true
			itemCount++
			skipStringLiteral(state)
		} else {
			// Not a list, bail
			allParametersOrLiterals = false
			break
		}
	}

	// Check if we found a closing paren and have multiple items
	if allParametersOrLiterals && foundNonWhitespace && itemCount > 1 &&
		state.hasMore() && state.current() == ')' {
		state.advance() // Skip closing )
		return "(?)"
	}

	// Not a normalizable IN clause, restore position
	state.idx = saveIdx
	state.advance()
	return "("
}

// normalizeParametersAndLiterals normalizes all parameter placeholders and literals.
// This is phase 1 of the normalization process.
// Matches Java: normalizeParametersAndLiterals()
func normalizeParametersAndLiterals(sql string) string {
	if sql == "" {
		return ""
	}

	var result strings.Builder
	result.Grow(len(sql))
	state := newSQLNormalizerState(sql)

	for state.hasMore() {
		current := state.current()

		if current == '\'' {
			// Replace string literals with ?
			skipStringLiteral(state)
			result.WriteByte('?')
		} else if current == '(' {
			// Check for IN clause with multiple values/placeholders
			if isPrecededByIn(&result) {
				inClause := tryNormalizeInClause(state)
				result.WriteString(inClause)
			} else {
				result.WriteByte('(')
				state.advance()
			}
		} else if isNumericLiteral(state) {
			// Numeric literals
			skipNumericLiteral(state)
			result.WriteByte('?')
		} else if isPlaceholder(state) {
			// Any placeholder type --> ?
			skipPlaceholder(state)
			result.WriteByte('?')
		} else {
			// Just append anything else
			result.WriteByte(current)
			state.advance()
		}
	}

	return result.String()
}

// isMultilineCommentStart checks if current position is start of /* comment.
// Matches Java implementation.
func isMultilineCommentStart(state *sqlNormalizerState) bool {
	return state.current() == '/' && state.hasNext() && state.peek() == '*'
}

// isSingleLineCommentStart checks if current position is start of -- comment.
// Matches Java implementation.
func isSingleLineCommentStart(state *sqlNormalizerState) bool {
	return state.current() == '-' && state.hasNext() && state.peek() == '-'
}

// skipMultilineComment skips over /* */ comment.
// Matches Java implementation.
func skipMultilineComment(state *sqlNormalizerState) {
	state.advanceBy(2) // Skip /*

	for state.idx < state.length-1 {
		if state.current() == '*' && state.peek() == '/' {
			state.advanceBy(2) // Skip */
			return
		}
		state.advance()
	}

	// Handle unclosed comment
	if state.hasMore() {
		state.advance()
	}
}

// skipToEndOfLine skips to end of line for -- and # comments.
// Matches Java implementation.
func skipToEndOfLine(state *sqlNormalizerState) {
	// Skip until newline
	for state.hasMore() && state.current() != '\n' && state.current() != '\r' {
		state.advance()
	}
	// Skip the newline character(s)
	for state.hasMore() && (state.current() == '\n' || state.current() == '\r') {
		state.advance()
	}
}

// processWhitespace handles whitespace normalization.
// Matches Java implementation.
func processWhitespace(result *strings.Builder, state *sqlNormalizerState) {
	if !state.lastWasWhitespace && result.Len() > 0 {
		result.WriteByte(' ')
		state.lastWasWhitespace = true
	}
	state.advance()
}

// processRegularCharacter handles regular character output.
// Matches Java implementation.
func processRegularCharacter(result *strings.Builder, state *sqlNormalizerState) {
	result.WriteByte(state.current())
	state.lastWasWhitespace = false
	state.advance()
}

// processStringLiteral handles string literal in comment removal phase.
// This is defensive code - literals should already be replaced in phase 1.
// Matches Java implementation.
func processStringLiteral(result *strings.Builder, state *sqlNormalizerState) {
	result.WriteByte(state.current())
	state.lastWasWhitespace = false
	state.advance()

	for state.hasMore() {
		c := state.current()
		result.WriteByte(c)

		if c == '\'' {
			// Escaped quote '' check
			if state.hasNext() && state.peek() == '\'' {
				result.WriteByte('\'')
				state.advanceBy(2)
			} else {
				state.advance()
				break
			}
		} else {
			state.advance()
		}
	}
	state.lastWasWhitespace = false
}

// removeCommentsAndNormalizeWhitespace strips all comments and normalizes whitespace.
// This is phase 2 of the normalization process.
// Matches Java: removeCommentsAndNormalizeWhitespace()
func removeCommentsAndNormalizeWhitespace(sql string) string {
	var result strings.Builder
	result.Grow(len(sql))
	state := newSQLNormalizerState(sql)

	for state.hasMore() {
		current := state.current()

		if current == '\'' {
			// String literals (defensive - should already be replaced in phase 1)
			processStringLiteral(&result, state)
		} else if isMultilineCommentStart(state) {
			// Multi-line comment /* */
			skipMultilineComment(state)
		} else if isSingleLineCommentStart(state) {
			// Single-line comment --
			state.advanceBy(2) // Skip --
			skipToEndOfLine(state)
		} else if current == '#' {
			// Hash comment
			state.advance() // Skip #
			skipToEndOfLine(state)
		} else if current == ' ' || current == '\t' || current == '\n' || current == '\r' {
			// Whitespace
			processWhitespace(&result, state)
		} else {
			// Regular character
			processRegularCharacter(&result, state)
		}
	}

	return strings.TrimSpace(result.String())
}

// GenerateMD5Hash generates an MD5 hash of the normalized SQL.
// Returns lowercase hex string (32 characters).
//
// This matches the behavior of SqlHashUtil.md5HashValueFor() in apm-trace-consumer.
//
// Security note: MD5 is used for SQL fingerprinting/identification, not cryptographic security.
// This is an acceptable use case despite MD5's known collision vulnerabilities.
//
// Parameters:
//   normalizedSQL: The normalized SQL query text
//
// Returns:
//   Lowercase hex string of MD5 hash (32 characters)
func GenerateMD5Hash(normalizedSQL string) string {
	// #nosec G401 - MD5 is used for SQL fingerprinting, not cryptographic security
	hash := md5.Sum([]byte(normalizedSQL))
	return hex.EncodeToString(hash[:])
}

// NormalizeSQLAndHash normalizes a SQL statement and returns both the normalized SQL and its MD5 hash.
//
// This is the primary entry point for APM-to-database query correlation.
// It combines NormalizeSQL and GenerateMD5Hash in a single call.
//
// See NormalizeSQL for detailed normalization rules.
//
// Parameters:
//   sql: The raw SQL query text
//
// Returns:
//   normalizedSQL: The normalized SQL query text
//   md5Hash: Lowercase hex string of MD5 hash (32 characters)
//
// Example:
//   input := "SELECT * FROM users WHERE id = 123 AND name = 'John'"
//   normalized, hash := NormalizeSQLAndHash(input)
//   // normalized: "SELECT * FROM USERS WHERE ID = ? AND NAME = ?"
//   // hash: "62c441c38800ff82bffa5c57dd4f4059"
func NormalizeSQLAndHash(sql string) (normalizedSQL, md5Hash string) {
	normalizedSQL = NormalizeSQL(sql)
	md5Hash = GenerateMD5Hash(normalizedSQL)

	// Log the generated hash
	fmt.Printf("[SQL Normalizer] Generated MD5 hash: %s\n\n", md5Hash)

	return normalizedSQL, md5Hash
}
