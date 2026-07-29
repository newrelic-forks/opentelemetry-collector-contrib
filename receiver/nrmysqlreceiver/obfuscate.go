// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrmysqlreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrmysqlreceiver"

import (
	"strings"

	"github.com/DataDog/datadog-agent/pkg/obfuscate"
)

var (
	// collectCommentsConfig extracts comments into metadata so they can be located
	// in the original SQL. Matches nroracledbreceiver/nrsqlserverreceiver.
	collectCommentsConfig = obfuscate.SQLConfig{
		DBMS:            "mysql",
		ObfuscationMode: "obfuscate_and_normalize",
		CollectComments: true,
		KeepSQLAlias:    true,
		KeepBoolean:     true,
		KeepNull:        true,
	}

	// obfuscateSQLConfig replaces literals with ? while preserving the query structure.
	obfuscateSQLConfig = obfuscate.SQLConfig{
		DBMS:            "mysql",
		ObfuscationMode: "obfuscate_and_normalize",
		KeepSQLAlias:    true,
		KeepBoolean:     true,
		KeepNull:        true,
	}

	obfuscatorConfig = obfuscate.Config{
		SQL:         obfuscateSQLConfig,
		SQLExecPlan: defaultSQLPlanObfuscateSettings,
	}
)

type obfuscator obfuscate.Obfuscator

func newObfuscator() *obfuscator {
	return (*obfuscator)(obfuscate.NewObfuscator(obfuscatorConfig))
}

// obfuscateSQLString obfuscates a SQL string in two passes, matching
// nroracledbreceiver/nrsqlserverreceiver:
//  1. Collect leading/embedded SQL comments (e.g. APM correlation tags like
//     /*nr_service_guid='...'*/) and replace each one with a single "?" placeholder
//     in the raw text, so the comment's contents never reach the obfuscated output.
//  2. Obfuscate literals in the now comment-redacted text.
func (o *obfuscator) obfuscateSQLString(sql string) (string, error) {
	collectResult, err := (*obfuscate.Obfuscator)(o).ObfuscateSQLStringWithOptions(sql, &collectCommentsConfig, "")
	if err != nil {
		return "", err
	}

	sqlWithAnonymizedComments := sql
	for _, comment := range collectResult.Metadata.Comments {
		sqlWithAnonymizedComments = strings.Replace(sqlWithAnonymizedComments, comment, "?", 1)
	}

	obfuscatedQuery, err := (*obfuscate.Obfuscator)(o).ObfuscateSQLStringWithOptions(sqlWithAnonymizedComments, &obfuscateSQLConfig, "")
	if err != nil {
		return "", err
	}
	return obfuscatedQuery.Query, nil
}

func (o *obfuscator) obfuscatePlan(plan string) (string, error) {
	obfuscated, err := (*obfuscate.Obfuscator)(o).ObfuscateSQLExecPlan(plan, false)
	if err != nil {
		return "", err
	}
	return obfuscated, nil
}

// For further information, see https://dev.mysql.com/doc/refman/8.4/en/explain.html
// MySQL 8.4 EXPLAIN FORMAT=JSON produces two formats depending on explain_json_format_version:
//   - Version 1 (default): query_block → ordering_operation → table → attached_condition
//   - Version 2: top-level query + inputs array, each node has condition/operation/access_type etc.
var defaultSQLPlanObfuscateSettings = obfuscate.JSONConfig{
	Enabled: true,
	ObfuscateSQLValues: []string{
		// v2: the full query text
		"query",
		// v2: SQL condition expression on a filter node
		"condition",
		// v2: human-readable description of a plan node (e.g. "Filter: (...)", "Table scan on ...")
		"operation",
		// v1: SQL condition expression attached to a table scan
		"attached_condition",
	},
	KeepValues: []string{
		// v1 structural fields
		"cost_info",
		"ordering_operation",
		"query_block",
		"query_plan",
		"query_type",
		"select_id",
		"table",
		"used_columns",
		"using_filesort",
		// v2 structural fields
		"access_type",
		"covering",
		"estimated_rows",
		"estimated_total_cost",
		"filter_columns",
		"index_access_type",
		"index_name",
		"inputs",
		"json_schema_version",
		"limit",
		"limit_offset",
		"per_chunk_limit",
		"ranges",
		"row_ids",
		"schema_name",
		"sort_fields",
		"table_name",
	},
}
