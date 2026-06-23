// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlserverreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver"

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/DataDog/datadog-agent/pkg/obfuscate"
)

var collectCommentsConfig = obfuscate.SQLConfig{
	DBMS:            "mssql",
	ObfuscationMode: "obfuscate_and_normalize",
	CollectComments: true,
	KeepSQLAlias:    true,
	KeepBoolean:     true,
	KeepNull:        true,
}

var fullQueryTextObfuscateConfig = obfuscate.SQLConfig{
	DBMS:            "mssql",
	ObfuscationMode: "obfuscate_and_normalize",
	KeepSQLAlias:    true,
	KeepBoolean:     true,
	KeepNull:        true,
}

var xmlPlanObfuscationAttrs = []string{
	"StatementText",
	"ConstValue",
	"ScalarString",
	"ParameterCompiledValue",
}

// stripParameterDeclarations removes the leading parameter declaration block
// from sp_executesql-style queries. SQL Server returns prepared statements with
// declarations like "(@P0 varchar(8000))SELECT ..." — strip to get the actual query.
func stripParameterDeclarations(sql string) string {
	if !strings.HasPrefix(sql, "(@") {
		return sql
	}
	depth := 0
	for i, ch := range sql {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return sql[i+1:]
			}
		}
	}
	return sql
}

// utf16OffsetToBytePos converts a SQL Server UTF-16LE byte offset into a Go
// string byte position. SQL Server's statement_start_offset is in bytes of
// NVARCHAR (UTF-16LE, 2 bytes per BMP character, 4 bytes for supplementary).
func utf16OffsetToBytePos(s string, utf16ByteOffset int) int {
	if utf16ByteOffset <= 0 {
		return 0
	}
	targetUTF16Units := utf16ByteOffset / 2
	utf16Count := 0
	bytePos := 0
	for _, r := range s {
		if utf16Count >= targetUTF16Units {
			break
		}
		if r > 0xFFFF {
			utf16Count += 2
		} else {
			utf16Count++
		}
		bytePos += utf8.RuneLen(r)
	}
	if bytePos > len(s) {
		return len(s)
	}
	return bytePos
}

// extractLastBlockComment finds the last /* ... */ block comment in a string.
func extractLastBlockComment(s string) string {
	lastOpen := strings.LastIndex(s, "/*")
	if lastOpen < 0 {
		return ""
	}
	closeIdx := strings.Index(s[lastOpen:], "*/")
	if closeIdx < 0 {
		return ""
	}
	return s[lastOpen : lastOpen+closeIdx+2]
}

// extractCleanText uses statement_start_offset and statement_end_offset to
// split the full SQL text into a preamble (parameter declarations + comments)
// and the actual statement, then reconstructs the text as: comment + statement.
// This produces a string that matches what APM agents hash against.
// Both offsets are SQL Server UTF-16LE byte offsets. statement_end_offset should
// already be resolved (i.e. -1 replaced with DATALENGTH) by the SQL query.
func extractCleanText(fullText string, statementStartOffset, statementEndOffset int) string {
	if statementStartOffset <= 0 {
		return stripParameterDeclarations(fullText)
	}

	startPos := utf16OffsetToBytePos(fullText, statementStartOffset)
	if startPos >= len(fullText) {
		return stripParameterDeclarations(fullText)
	}

	endPos := len(fullText)
	if statementEndOffset > 0 {
		// statement_end_offset is inclusive (points to first byte of last char),
		// add 2 to make it exclusive for the Go slice (1 UTF-16 code unit = 2 bytes)
		endPos = min(utf16OffsetToBytePos(fullText, statementEndOffset+2), len(fullText))
	}

	preamble := fullText[:startPos]
	statement := fullText[startPos:endPos]

	comment := extractLastBlockComment(preamble)
	if comment != "" {
		return comment + statement
	}
	return statement
}

var obfuscateSQLConfig = obfuscate.SQLConfig{DBMS: "mssql"}

type obfuscator obfuscate.Obfuscator

func newObfuscator() *obfuscator {
	return (*obfuscator)(obfuscate.NewObfuscator(obfuscate.Config{}))
}

func (o *obfuscator) obfuscateSQLString(sql string) (string, error) {
	obfuscatedQuery, err := (*obfuscate.Obfuscator)(o).ObfuscateSQLStringWithOptions(sql, &obfuscateSQLConfig, "")
	if err != nil {
		return "", err
	}
	return obfuscatedQuery.Query, nil
}

// obfuscateFullSQLString obfuscates a full SQL batch text using a two-step approach:
// Step 1: collect comments and replace them with ? placeholders
// Step 2: obfuscate literals using obfuscate_only mode
// statementStartOffset/statementEndOffset are SQL Server UTF-16 byte offsets
// used to correctly split preamble (params+comment) from the actual statement.
func (o *obfuscator) obfuscateFullSQLString(sql string, statementStartOffset, statementEndOffset int) (string, error) {
	sql = extractCleanText(sql, statementStartOffset, statementEndOffset)
	collectResult, err := (*obfuscate.Obfuscator)(o).ObfuscateSQLStringWithOptions(sql, &collectCommentsConfig, "")
	if err != nil {
		return "", err
	}

	sqlWithAnonymizedComments := sql
	for _, comment := range collectResult.Metadata.Comments {
		sqlWithAnonymizedComments = strings.Replace(sqlWithAnonymizedComments, comment, "?", 1)
	}

	obfuscatedQuery, err := (*obfuscate.Obfuscator)(o).ObfuscateSQLStringWithOptions(sqlWithAnonymizedComments, &fullQueryTextObfuscateConfig, "")
	if err != nil {
		return "", err
	}

	return obfuscatedQuery.Query, nil
}

// obfuscateXMLPlan obfuscates SQL text & parameters from the provided SQL Server XML Plan
func (o *obfuscator) obfuscateXMLPlan(rawPlan string) (string, error) {
	decoder := xml.NewDecoder(strings.NewReader(rawPlan))
	var buffer bytes.Buffer
	encoder := xml.NewEncoder(&buffer)

	for {
		token, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return "", err
		}

		switch elem := token.(type) {
		case xml.StartElement:
			for i := range elem.Attr {
				for _, attrName := range xmlPlanObfuscationAttrs {
					if elem.Attr[i].Name.Local == attrName {
						if elem.Attr[i].Value == "" {
							continue
						}
						val, err := o.obfuscateSQLString(elem.Attr[i].Value)
						if err != nil {
							fmt.Println("Unable to obfuscate SQL statement in query plan, skipping: " + elem.Attr[i].Value)
							return "", nil
						}
						elem.Attr[i].Value = val
					}
				}
			}
			err := encoder.EncodeToken(elem)
			if err != nil {
				return "", err
			}
		case xml.CharData:
			elem = bytes.TrimSpace(elem)
			err := encoder.EncodeToken(elem)
			if err != nil {
				return "", err
			}
		case xml.EndElement:
			err := encoder.EncodeToken(elem)
			if err != nil {
				return "", err
			}
		default:
			err := encoder.EncodeToken(token)
			if err != nil {
				return "", err
			}
		}
	}

	err := encoder.Flush()
	if err != nil {
		return "", err
	}

	return buffer.String(), nil
}
