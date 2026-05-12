// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oracledbreceiver

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver/internal/metadata"
)

// errQuery is a sentinel error used to simulate a failed DB query.
var errQuery = errors.New("ORA-00942: table or view does not exist")

// versionRow builds the fakeDbClient response for the v$instance version query.
func versionRow(v string) []metricRow {
	return []metricRow{{"VERSION": v}}
}

// cdbRow builds the fakeDbClient response for the v$database CDB query.
func cdbRow(cdb string) []metricRow {
	return []metricRow{{"CDB": cdb}}
}

// conTypeRow builds the fakeDbClient response for the USERENV CON_ID query.
// The decode() expression produces an unnamed column; the dbClient stores it
// by whatever key the driver returns, so we use the same key the real driver
// would produce — but in tests we use the first map value (see instance_info.go).
func conTypeRow(t string) []metricRow {
	return []metricRow{{"TYPE": t}}
}

// conNameRow builds the fakeDbClient response for the USERENV CON_NAME query.
func conNameRow(name string) []metricRow {
	return []metricRow{{"NAME": name}}
}

// noopClient returns a fakeDbClient that should never be called.
// Use it for detection steps that must not run in a given test.
func noopClient(t *testing.T) dbClient {
	t.Helper()
	return &fakeDbClient{
		Err: errors.New("this client should not have been called"),
	}
}

// errClient returns a fakeDbClient that always returns an error.
func errClient() dbClient {
	return &fakeDbClient{Err: errQuery}
}

// rowClient returns a fakeDbClient that returns the given rows once.
func rowClient(rows []metricRow) dbClient {
	return &fakeDbClient{Responses: [][]metricRow{rows}}
}

// -- isVersionGTE unit tests --------------------------------------------------

func TestIsVersionGTE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		minMajor int
		expected bool
	}{
		{name: "empty version returns false", version: "", minMajor: 12, expected: false},
		{name: "19 >= 12", version: "19.0.0.0.0", minMajor: 12, expected: true},
		{name: "12 >= 12", version: "12.2.0.1.0", minMajor: 12, expected: true},
		{name: "11 not >= 12", version: "11.2.0.4.0", minMajor: 12, expected: false},
		{name: "19 >= 18", version: "19.0.0.0.0", minMajor: 18, expected: true},
		{name: "18 >= 18", version: "18.0.0.0.0", minMajor: 18, expected: true},
		{name: "12 not >= 18", version: "12.2.0.1.0", minMajor: 18, expected: false},
		{name: "21 >= 12", version: "21.0.0.0.0", minMajor: 12, expected: true},
		{name: "major-only version string", version: "19", minMajor: 12, expected: true},
		{name: "malformed version returns false", version: "not-a-version", minMajor: 12, expected: false},
		{name: "version with only dot returns false", version: ".", minMajor: 12, expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := oracleInstanceInfo{dbVersion: tt.version}
			assert.Equal(t, tt.expected, info.isVersionGTE(tt.minMajor))
		})
	}
}

// -- detectInstanceInfo tests -------------------------------------------------

func TestDetectInstanceInfo_VersionQueryFails(t *testing.T) {
	// When v$instance is inaccessible all fields stay at zero value and
	// detection stops — the three subsequent clients must not be called.
	core, logs := observer.New(zapcore.WarnLevel)

	info := detectInstanceInfo(context.Background(),
		errClient(),
		noopClient(t), noopClient(t), noopClient(t),
		zap.New(core),
	)

	assert.Empty(t, info.dbVersion)
	assert.False(t, info.isCDB)
	assert.False(t, info.connectedToPDB)
	assert.Empty(t, info.pdbName)
	assert.Equal(t, 1, logs.FilterMessage("oracledbreceiver: failed to detect Oracle version; pdb_name attribute will not be set").Len())
}

func TestDetectInstanceInfo_Pre12c(t *testing.T) {
	// Oracle 11g: version is set, multitenant detection is skipped entirely.
	core, logs := observer.New(zapcore.InfoLevel)

	info := detectInstanceInfo(context.Background(),
		rowClient(versionRow("11.2.0.4.0")),
		noopClient(t), noopClient(t), noopClient(t),
		zap.New(core),
	)

	assert.Equal(t, "11.2.0.4.0", info.dbVersion)
	assert.False(t, info.isCDB)
	assert.False(t, info.connectedToPDB)
	assert.Empty(t, info.pdbName)
	assert.Equal(t, 1, logs.FilterMessage("oracledbreceiver: Oracle version is pre-12c; multitenant detection skipped").Len())
}

func TestDetectInstanceInfo_NonCDB(t *testing.T) {
	// Oracle 19c non-CDB: isCDB=false, no further steps run.
	info := detectInstanceInfo(context.Background(),
		rowClient(versionRow("19.0.0.0.0")),
		rowClient(cdbRow("NO")),
		noopClient(t), noopClient(t),
		zap.NewNop(),
	)

	assert.Equal(t, "19.0.0.0.0", info.dbVersion)
	assert.False(t, info.isCDB)
	assert.False(t, info.connectedToPDB)
	assert.Empty(t, info.pdbName)
}

func TestDetectInstanceInfo_CDBQueryFails(t *testing.T) {
	// v$database query fails: isCDB stays false, no further steps run.
	core, logs := observer.New(zapcore.WarnLevel)

	info := detectInstanceInfo(context.Background(),
		rowClient(versionRow("19.0.0.0.0")),
		errClient(),
		noopClient(t), noopClient(t),
		zap.New(core),
	)

	assert.Equal(t, "19.0.0.0.0", info.dbVersion)
	assert.False(t, info.isCDB)
	assert.False(t, info.connectedToPDB)
	assert.Empty(t, info.pdbName)
	assert.Equal(t, 1, logs.FilterMessage("oracledbreceiver: failed to detect CDB status; assuming non-CDB").Len())
}

func TestDetectInstanceInfo_CDBRootConnection(t *testing.T) {
	// Oracle 19c CDB, monitoring user connected to CDB root (CON_ID=1).
	// connectedToPDB=false, pdbName stays empty, conNameClient not called.
	info := detectInstanceInfo(context.Background(),
		rowClient(versionRow("19.0.0.0.0")),
		rowClient(cdbRow("YES")),
		rowClient(conTypeRow("CDB")),
		noopClient(t),
		zap.NewNop(),
	)

	assert.Equal(t, "19.0.0.0.0", info.dbVersion)
	assert.True(t, info.isCDB)
	assert.False(t, info.connectedToPDB)
	assert.Empty(t, info.pdbName)
}

func TestDetectInstanceInfo_ConnTypeQueryFails(t *testing.T) {
	// USERENV CON_ID query fails: connectedToPDB stays false, conNameClient not called.
	core, logs := observer.New(zapcore.WarnLevel)

	info := detectInstanceInfo(context.Background(),
		rowClient(versionRow("19.0.0.0.0")),
		rowClient(cdbRow("YES")),
		errClient(),
		noopClient(t),
		zap.New(core),
	)

	assert.Equal(t, "19.0.0.0.0", info.dbVersion)
	assert.True(t, info.isCDB)
	assert.False(t, info.connectedToPDB)
	assert.Empty(t, info.pdbName)
	assert.Equal(t, 1, logs.FilterMessage("oracledbreceiver: failed to detect connection type (CDB root vs PDB)").Len())
}

func TestDetectInstanceInfo_PDBConnection(t *testing.T) {
	// All four steps succeed: all fields populated.
	core, logs := observer.New(zapcore.InfoLevel)

	info := detectInstanceInfo(context.Background(),
		rowClient(versionRow("19.0.0.0.0")),
		rowClient(cdbRow("YES")),
		rowClient(conTypeRow("PDB")),
		rowClient(conNameRow("MYPDB")),
		zap.New(core),
	)

	assert.Equal(t, "19.0.0.0.0", info.dbVersion)
	assert.True(t, info.isCDB)
	assert.True(t, info.connectedToPDB)
	assert.Equal(t, "MYPDB", info.pdbName)
	assert.Equal(t, 1, logs.FilterField(zap.String("pdb_name", "MYPDB")).Len())
}

func TestDetectInstanceInfo_PDBNameQueryFails(t *testing.T) {
	// CON_NAME query fails: connectedToPDB=true but pdbName stays empty.
	// Receiver still starts without the PDB name attribute.
	core, logs := observer.New(zapcore.WarnLevel)

	info := detectInstanceInfo(context.Background(),
		rowClient(versionRow("19.0.0.0.0")),
		rowClient(cdbRow("YES")),
		rowClient(conTypeRow("PDB")),
		errClient(),
		zap.New(core),
	)

	assert.Equal(t, "19.0.0.0.0", info.dbVersion)
	assert.True(t, info.isCDB)
	assert.True(t, info.connectedToPDB)
	assert.Empty(t, info.pdbName)
	assert.Equal(t, 1, logs.FilterMessage("oracledbreceiver: failed to detect PDB name").Len())
}

func TestDetectInstanceInfo_CDBFlagCaseInsensitive(t *testing.T) {
	// Oracle may return "YES", "Yes", or "yes" — all must set isCDB=true.
	for _, cdbVal := range []string{"YES", "Yes", "yes"} {
		t.Run("cdb="+cdbVal, func(t *testing.T) {
			info := detectInstanceInfo(context.Background(),
				rowClient(versionRow("19.0.0.0.0")),
				rowClient(cdbRow(cdbVal)),
				rowClient(conTypeRow("CDB")),
				noopClient(t),
				zap.NewNop(),
			)
			assert.True(t, info.isCDB, "expected isCDB=true for cdb=%q", cdbVal)
		})
	}
}

func TestDetectInstanceInfo_Oracle12c(t *testing.T) {
	// Oracle 12c is the minimum multitenant version — full detection runs.
	info := detectInstanceInfo(context.Background(),
		rowClient(versionRow("12.2.0.1.0")),
		rowClient(cdbRow("YES")),
		rowClient(conTypeRow("PDB")),
		rowClient(conNameRow("SALESPDB")),
		zap.NewNop(),
	)

	assert.Equal(t, "12.2.0.1.0", info.dbVersion)
	assert.True(t, info.isCDB)
	assert.True(t, info.connectedToPDB)
	assert.Equal(t, "SALESPDB", info.pdbName)
}

// -- setupResourceBuilder tests -----------------------------------------------

func TestSetupResourceBuilder_NoPDB(t *testing.T) {
	// When not connected to a PDB, oracledb.pdb_name must not appear in resource.
	cfg := metadata.NewDefaultMetricsBuilderConfig()
	scrpr := oracleScraper{
		mb:                   metadata.NewMetricsBuilder(cfg, receivertest.NewNopSettings(metadata.Type)),
		metricsBuilderConfig: cfg,
		instanceName:         "myinstance",
		hostName:             "myhost",
		instanceInfo:         oracleInstanceInfo{dbVersion: "19.0.0.0.0", isCDB: false},
	}

	res := scrpr.setupResourceBuilder(scrpr.mb.NewResourceBuilder()).Emit()

	_, hasPDB := res.Attributes().Get("oracledb.pdb_name")
	assert.False(t, hasPDB, "pdb_name should not be set for non-PDB connections")

	name, _ := res.Attributes().Get("oracledb.instance.name")
	assert.Equal(t, "myinstance", name.Str())
	host, _ := res.Attributes().Get("host.name")
	assert.Equal(t, "myhost", host.Str())
}

func TestSetupResourceBuilder_WithPDB(t *testing.T) {
	// When connected to a PDB, oracledb.pdb_name must be set on the resource.
	cfg := metadata.NewDefaultMetricsBuilderConfig()
	scrpr := oracleScraper{
		mb:                   metadata.NewMetricsBuilder(cfg, receivertest.NewNopSettings(metadata.Type)),
		metricsBuilderConfig: cfg,
		instanceName:         "myinstance",
		hostName:             "myhost",
		instanceInfo: oracleInstanceInfo{
			dbVersion:      "19.0.0.0.0",
			isCDB:          true,
			connectedToPDB: true,
			pdbName:        "SALESPDB",
		},
	}

	res := scrpr.setupResourceBuilder(scrpr.mb.NewResourceBuilder()).Emit()

	pdbName, ok := res.Attributes().Get("oracledb.pdb_name")
	require.True(t, ok, "oracledb.pdb_name should be set when connected to a PDB")
	assert.Equal(t, "SALESPDB", pdbName.Str())
}

func TestSetupResourceBuilder_PDBConnectedButEmptyName(t *testing.T) {
	// connectedToPDB=true but pdbName="" (name query failed): pdb_name must not
	// be emitted as an empty string — it should simply be absent.
	cfg := metadata.NewDefaultMetricsBuilderConfig()
	scrpr := oracleScraper{
		mb:                   metadata.NewMetricsBuilder(cfg, receivertest.NewNopSettings(metadata.Type)),
		metricsBuilderConfig: cfg,
		instanceInfo: oracleInstanceInfo{
			dbVersion:      "19.0.0.0.0",
			isCDB:          true,
			connectedToPDB: true,
			pdbName:        "",
		},
	}

	res := scrpr.setupResourceBuilder(scrpr.mb.NewResourceBuilder()).Emit()

	_, hasPDB := res.Attributes().Get("oracledb.pdb_name")
	assert.False(t, hasPDB, "pdb_name should not be emitted when name is empty")
}
