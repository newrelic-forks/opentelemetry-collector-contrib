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

// oracleInstanceInfo holds Oracle deployment metadata detected once at scraper start time.
type oracleInstanceInfo struct {
	dbVersion      string
	isCDB          bool
	connectedToPDB bool
	pdbName        string
}

// isVersionGTE reports whether the detected Oracle major version is >= minMajor.
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
	// minMultitenantVersion is the first Oracle major version that supports CDB/PDB.
	minMultitenantVersion     = 12
	instanceInfoDetectTimeout = 5 * time.Second

	instanceVersionSQL = "SELECT version FROM v$instance"
	instanceCDBSQL     = "SELECT cdb FROM v$database"
	instanceConTypeSQL = "SELECT decode(sys_context('USERENV','CON_ID'),1,'CDB','PDB') FROM dual"
	instanceConNameSQL = "SELECT sys_context('USERENV','CON_NAME') FROM dual"
)

// detectInstanceInfo queries Oracle at startup to populate version and multitenant info.
// Failures are logged at Warn level; affected fields retain their zero value.
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

	rows, err := versionClient.metricRows(ctx)
	if err != nil || len(rows) == 0 {
		logger.Warn("oracledbreceiver: failed to detect Oracle version; oracle.db.pdb attribute will not be set",
			zap.Error(err))
		return info
	}
	info.dbVersion = rows[0]["VERSION"]
	logger.Info("oracledbreceiver: detected Oracle version", zap.String("version", info.dbVersion))

	if !info.isVersionGTE(minMultitenantVersion) {
		logger.Info("oracledbreceiver: Oracle version is pre-12c; multitenant detection skipped",
			zap.String("version", info.dbVersion))
		return info
	}

	rows, err = cdbClient.metricRows(ctx)
	if err != nil || len(rows) == 0 {
		logger.Warn("oracledbreceiver: failed to detect CDB status; assuming non-CDB",
			zap.Error(err))
		return info
	}
	info.isCDB = strings.EqualFold(rows[0]["CDB"], "YES")

	if !info.isCDB {
		return info
	}

	rows, err = conTypeClient.metricRows(ctx)
	if err != nil || len(rows) == 0 {
		logger.Warn("oracledbreceiver: failed to detect connection type (CDB root vs PDB)",
			zap.Error(err))
		return info
	}
	// decode() returns an unnamed column; read the first value regardless of key.
	for _, v := range rows[0] {
		info.connectedToPDB = v == "PDB"
		break
	}

	if !info.connectedToPDB {
		return info
	}

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
