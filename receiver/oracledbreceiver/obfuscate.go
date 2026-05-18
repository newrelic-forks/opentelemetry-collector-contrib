// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oracledbreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver"

import (
	"github.com/DataDog/datadog-agent/pkg/obfuscate"
)

var (
	obfuscateSQLConfig = obfuscate.SQLConfig{
		DBMS:            "oracle",
		ObfuscationMode: "obfuscate_only", // Obfuscate literals while preserving structure, comments, and formatting
		KeepSQLAlias:    true,             // Preserve AS aliases
		KeepBoolean:     true,             // Preserve TRUE/FALSE literals
		KeepNull:        true,             // Preserve NULL literals
	}
)

type obfuscator obfuscate.Obfuscator

func newObfuscator() *obfuscator {
	return (*obfuscator)(obfuscate.NewObfuscator(obfuscate.Config{
		SQL: obfuscateSQLConfig,
	}))
}

func (o *obfuscator) obfuscateSQLString(sql string) (string, error) {
	// Use ObfuscateSQLStringWithOptions with "obfuscate_only" mode
	// This preserves: comments, aliases, formatting, and query structure
	// While replacing: string and numeric literals with ?
	obfuscatedQuery, err := (*obfuscate.Obfuscator)(o).ObfuscateSQLStringWithOptions(sql, &obfuscateSQLConfig, "")
	if err != nil {
		return "", err
	}
	return obfuscatedQuery.Query, nil
}
