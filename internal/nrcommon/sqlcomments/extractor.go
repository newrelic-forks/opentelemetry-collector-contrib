// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlcomments // import "github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrcommon/sqlcomments"

import (
	"regexp"
	"strings"
)

var (
	commentContentRegex      = regexp.MustCompile(`/\*(.*?)\*/`)
	leadingBlockCommentRegex = regexp.MustCompile(`^\s*(/\*.*?\*/\s*)+`)
)

// ExtractAndFilterComments returns the comma-separated key=value pairs found in
// the leading /* */ block comments of sqlText whose keys are in allowedKeys.
// Extraction is disabled (returns "") when allowedKeys is empty.
func ExtractAndFilterComments(sqlText string, allowedKeys []string) string {
	if len(allowedKeys) == 0 {
		return ""
	}

	values := parseLeadingComments(sqlText)

	var filteredPairs []string
	for _, key := range allowedKeys {
		if value, ok := values[key]; ok {
			filteredPairs = append(filteredPairs, key+"="+value)
		}
	}

	return strings.Join(filteredPairs, ",")
}

// ExtractValueForKey returns the value associated with key in a comma-separated
// key=value string such as the output of ExtractAndFilterComments
// (e.g. "nr_service_guid=abc-123,app_id=xyz"). It returns "" when the key is not
// present or comments is empty. A single pair of surrounding single or double
// quotes is stripped from the returned value.
func ExtractValueForKey(comments, key string) string {
	if comments == "" || key == "" {
		return ""
	}

	for pair := range strings.SplitSeq(comments, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		keyValue := strings.SplitN(pair, "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		if strings.TrimSpace(keyValue[0]) == key {
			return trimSurroundingQuotes(strings.TrimSpace(keyValue[1]))
		}
	}

	return ""
}

// trimSurroundingQuotes removes a single matching pair of surrounding single or
// double quotes from value, if present.
func trimSurroundingQuotes(value string) string {
	if len(value) >= 2 {
		first := value[0]
		last := value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func parseLeadingComments(sqlText string) map[string]string {
	values := make(map[string]string)

	leading := leadingBlockCommentRegex.FindString(sqlText)
	if leading == "" {
		return values
	}

	for _, commentMatch := range commentContentRegex.FindAllStringSubmatch(leading, -1) {
		if len(commentMatch) > 1 {
			addPairs(values, commentMatch[1])
		}
	}
	return values
}

func addPairs(values map[string]string, content string) {
	for pair := range strings.SplitSeq(content, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		keyValue := strings.SplitN(pair, "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		key := strings.TrimSpace(keyValue[0])
		if _, ok := values[key]; !ok {
			values[key] = strings.TrimSpace(keyValue[1])
		}
	}
}
