// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oracledbreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver"

import (
	"context"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// oracleInstanceInfo holds Oracle deployment metadata detected once at scraper
// start time. All fields are best-effort: if a detection query fails (e.g.
// insufficient privileges, older Oracle version), the field stays at its zero
// value and the receiver continues with reduced metadata.
type oracleInstanceInfo struct {
	// dbVersion is the Oracle version string returned by v$instance, e.g.
	// "19.0.0.0.0". Empty if version detection failed.
	dbVersion string

	// isCDB is true when the database is a Container Database (Oracle 12c+).
	// false for non-CDB (traditional) instances or when detection failed.
	isCDB bool

	// connectedToPDB is true when the monitoring user is connected to a
	// specific Pluggable Database rather than the CDB root.
	connectedToPDB bool

	// pdbName is the name of the PDB when connectedToPDB is true.
	// Empty otherwise.
	pdbName string
}

// isVersionGTE reports whether the detected Oracle major version is greater
// than or equal to minMajor. Returns false if version detection failed.
func (info oracleInstanceInfo) isVersionGTE(minMajor int) bool {
	if info.dbVersion == "" {
		return false
	}
	major, err := strconv.Atoi(strings.SplitN(info.dbVersion, ".", 2)[0])
	if err != nil {
		return false
	}
	return major >= minMajor
}

const (
	// minMultitenantVersion is the Oracle major version that introduced
	// multitenant (CDB/PDB) architecture.
	minMultitenantVersion = 12

	// instanceInfoDetectTimeout caps the total time spent on instance
	// detection queries at startup. Detection is best-effort so a slow or
	// blackholed endpoint must not stall the collector.
	instanceInfoDetectTimeout = 5 * time.Second

	instanceVersionSQL  = "SELECT version FROM v$instance"
	instanceCDBSQL      = "SELECT cdb FROM v$database"
	instanceConTypeSQL  = "SELECT decode(sys_context('USERENV','CON_ID'),1,'CDB','PDB') FROM dual"
	instanceConNameSQL  = "SELECT sys_context('USERENV','CON_NAME') FROM dual"
)

// detectInstanceInfo runs a small set of read-only queries using the provided
// dbClient instances to populate and return an oracleInstanceInfo. All queries
// run within a single short timeout context. Any failure is logged at Warn
// level and causes that field to retain its zero value; the receiver continues
// normally.
func detectInstanceInfo(
	ctx context.Context,
	versionClient dbClient,
	cdbClient dbClient,
	conTypeClient dbClient,
	conNameClient dbClient,
	logger *zap.Logger,
) oracleInstanceInfo {
	ctx, cancel := context.WithTimeout(ctx, instanceInfoDetectTimeout)
	defer cancel()

	info := oracleInstanceInfo{}

	// Step 1 — Oracle version from v$instance.
	rows, err := versionClient.metricRows(ctx)
	if err != nil || len(rows) == 0 {
		logger.Warn("oracledbreceiver: failed to detect Oracle version; pdb_name attribute will not be set",
			zap.Error(err))
		return info
	}
	info.dbVersion = rows[0]["VERSION"]
	logger.Info("oracledbreceiver: detected Oracle version", zap.String("version", info.dbVersion))

	// Remaining detection requires Oracle 12c+.
	if !info.isVersionGTE(minMultitenantVersion) {
		logger.Info("oracledbreceiver: Oracle version is pre-12c; multitenant detection skipped",
			zap.String("version", info.dbVersion))
		return info
	}

	// Step 2 — Is this a Container Database?
	rows, err = cdbClient.metricRows(ctx)
	if err != nil || len(rows) == 0 {
		logger.Warn("oracledbreceiver: failed to detect CDB status; assuming non-CDB",
			zap.Error(err))
		return info
	}
	info.isCDB = strings.EqualFold(rows[0]["CDB"], "YES")

	if !info.isCDB {
		// Non-CDB instance: no further multitenant detection needed.
		return info
	}

	// Step 3 — Is the monitoring user connected to a PDB or the CDB root?
	// CON_ID = 1 means CDB root; any other value means a specific PDB.
	rows, err = conTypeClient.metricRows(ctx)
	if err != nil || len(rows) == 0 {
		logger.Warn("oracledbreceiver: failed to detect connection type (CDB root vs PDB)",
			zap.Error(err))
		return info
	}
	// The decode() expression returns one unnamed column; the dbClient uppercases
	// column names, so the key is the expression text — access by first value.
	for _, v := range rows[0] {
		info.connectedToPDB = v == "PDB"
		break
	}

	if !info.connectedToPDB {
		return info
	}

	// Step 4 — Name of the PDB the monitoring user is connected to.
	rows, err = conNameClient.metricRows(ctx)
	if err != nil || len(rows) == 0 {
		logger.Warn("oracledbreceiver: failed to detect PDB name",
			zap.Error(err))
		return info
	}
	for _, v := range rows[0] {
		info.pdbName = v
		break
	}
	logger.Info("oracledbreceiver: connected to PDB", zap.String("pdb_name", info.pdbName))

	return info
}
