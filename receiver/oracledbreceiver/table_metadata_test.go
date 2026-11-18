// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oracledbreceiver

import (
	"database/sql"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/oracledbreceiver/internal/metadata"
)

func newTableMetadataScraper(t *testing.T, dbclientFn clientProviderFunc) *oracleScraper {
	t.Helper()

	logsCfg := metadata.DefaultLogsBuilderConfig()
	logsCfg.Events.DbServerTableMetadata.Enabled = true
	logsCfg.Events.DbServerViewMetadata.Enabled = true

	serverAddress, serverPort, serviceInstanceID := resolveInstanceIdentity("oraclehost:1521", "oraclehost:1521/ORCL", zap.NewNop())

	return &oracleScraper{
		logger: zap.NewNop(),
		lb:     metadata.NewLogsBuilder(logsCfg, receivertest.NewNopSettings(metadata.Type)),
		dbProviderFunc: func() (*sql.DB, error) {
			return nil, nil
		},
		clientProviderFunc: dbclientFn,
		id:                 component.ID{},
		logsBuilderConfig:  logsCfg,
		tableMetadataCfg:   TableMetadataCollection{MaxTables: 300, CollectionInterval: 600 * time.Second},
		viewMetadataCfg:    ViewMetadataCollection{MaxViews: 1000, CollectionInterval: 600 * time.Second},
		instanceName:       "oraclehost:1521/ORCL",
		hostName:           "oraclehost:1521",
		obfuscator:         newObfuscator(),
		serviceInstanceID:  serviceInstanceID,
		serverAddress:      serverAddress,
		serverPort:         serverPort,
	}
}

func staticRowsFn(rows []metricRow) clientProviderFunc {
	return func(*sql.DB, string, *zap.Logger) dbClient {
		return &fakeDbClient{Responses: [][]metricRow{rows}}
	}
}

func tableMetadataRow(overrides map[string]string) metricRow {
	row := metricRow{
		"SCHEMA_NAME":  "TESTAPP",
		"TABLE_NAME":   "ORDERS",
		"DB_NAMESPACE": "ORCLPDB1",
		"ROW_COUNT":    "417628",
		"COLUMNS_JSON": `[{"name":"ID","data_type":"NUMBER","data_length":22,"nullable":"N","default":""},` +
			`{"name":"USER_ID","data_type":"NUMBER","data_length":22,"nullable":"N","default":""}]`,
		"INDEXES_JSON": `[{"name":"SYS_C008748","index_type":"NORMAL","uniqueness":"UNIQUE","column_names":"ID"}]`,
		"FOREIGN_KEYS_JSON": `[{"name":"SYS_C008749","column_names":"USER_ID","referenced_schema":"TESTAPP",` +
			`"referenced_table_name":"USERS","referenced_column_names":"ID","delete_rule":"NO ACTION"}]`,
		"TABLE_BYTES": "24117248",
		"INDEX_BYTES": "58700000",
		"LOB_BYTES":   "0",
		"TOTAL_BYTES": "82817248",
	}
	maps.Copy(row, overrides)
	return row
}

func TestScrapeTableMetadata(t *testing.T) {
	rows := []metricRow{tableMetadataRow(nil)}
	s := newTableMetadataScraper(t, staticRowsFn(rows))
	s.logsBuilderConfig.Events.DbServerViewMetadata.Enabled = false

	logs, err := s.scrapeLogs(t.Context())
	require.NoError(t, err)

	require.Equal(t, 1, logs.ResourceLogs().Len())
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 1, records.Len())
	record := records.At(0)
	assert.Equal(t, "db.server.table_metadata", record.EventName())

	name, ok := record.Attributes().Get("oracledb.table.name")
	require.True(t, ok)
	assert.Equal(t, "ORDERS", name.Str())

	columns, ok := record.Attributes().Get("oracledb.table.columns")
	require.True(t, ok)
	assert.Equal(t, 2, columns.Slice().Len())

	indexes, ok := record.Attributes().Get("oracledb.table.indexes")
	require.True(t, ok)
	require.Equal(t, 1, indexes.Slice().Len())

	foreignKeys, ok := record.Attributes().Get("oracledb.table.foreign_keys")
	require.True(t, ok)
	require.Equal(t, 1, foreignKeys.Slice().Len())
	fkColumns, ok := foreignKeys.Slice().At(0).Map().Get("column_names")
	require.True(t, ok)
	assert.Equal(t, "USER_ID", fkColumns.Str())

	size, ok := record.Attributes().Get("oracledb.table.size")
	require.True(t, ok)
	require.Equal(t, 4, size.Slice().Len())
}

// A table with no indexes or foreign keys has the query's COALESCE turn SQL NULL into
// the literal text "[]", which must be reported as an empty list, not a parse error.
func TestScrapeTableMetadataHandlesEmptyNestedData(t *testing.T) {
	rows := []metricRow{tableMetadataRow(map[string]string{
		"TABLE_NAME": "LOOKUP", "INDEXES_JSON": "[]", "FOREIGN_KEYS_JSON": "[]",
	})}
	s := newTableMetadataScraper(t, staticRowsFn(rows))
	s.logsBuilderConfig.Events.DbServerViewMetadata.Enabled = false

	logs, err := s.scrapeLogs(t.Context())
	require.NoError(t, err)

	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	indexes, ok := record.Attributes().Get("oracledb.table.indexes")
	require.True(t, ok)
	assert.Equal(t, 0, indexes.Slice().Len())

	foreignKeys, ok := record.Attributes().Get("oracledb.table.foreign_keys")
	require.True(t, ok)
	assert.Equal(t, 0, foreignKeys.Slice().Len())
}

func TestScrapeTableMetadataRespectsCollectionInterval(t *testing.T) {
	rows := []metricRow{tableMetadataRow(nil)}
	s := newTableMetadataScraper(t, staticRowsFn(rows))
	s.tableMetadataCfg.CollectionInterval = time.Minute
	s.lastTableMetadataTimestamp = time.Now()
	// View metadata would otherwise run on the same scrapeLogs call; disable it for
	// this test so only the table-metadata skip behavior is under test.
	s.logsBuilderConfig.Events.DbServerViewMetadata.Enabled = false

	logs, err := s.scrapeLogs(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 0, logs.ResourceLogs().Len(), "scrape within the collection interval should be skipped")
}

func tableViewMetadataRow(overrides map[string]string) metricRow {
	row := metricRow{
		"SCHEMA_NAME":  "TESTAPP",
		"VIEW_NAME":    "CUSTOMER_ORDER_SUMMARY",
		"DB_NAMESPACE": "ORCLPDB1",
		"COLUMNS_JSON": `[{"name":"USER_ID","data_type":"NUMBER","data_length":22,"nullable":"N","default":""}]`,
		"DEFINITION":   "SELECT user_id FROM orders",
	}
	maps.Copy(row, overrides)
	return row
}

func TestScrapeViewMetadata(t *testing.T) {
	rows := []metricRow{tableViewMetadataRow(nil)}
	s := newTableMetadataScraper(t, staticRowsFn(rows))
	s.logsBuilderConfig.Events.DbServerTableMetadata.Enabled = false

	logs, err := s.scrapeLogs(t.Context())
	require.NoError(t, err)

	require.Equal(t, 1, logs.ResourceLogs().Len())
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 1, records.Len())
	record := records.At(0)
	assert.Equal(t, "db.server.view_metadata", record.EventName())

	definition, ok := record.Attributes().Get("oracledb.view.definition")
	require.True(t, ok)
	assert.Equal(t, "SELECT user_id FROM orders", definition.Str())

	columns, ok := record.Attributes().Get("oracledb.table.columns")
	require.True(t, ok)
	assert.Equal(t, 1, columns.Slice().Len())
}

func TestBuildTableMetadataSQL(t *testing.T) {
	tests := []struct {
		name     string
		useCDB   bool
		wantView string
	}{
		{name: "CDB root uses CDB_TABLES", useCDB: true, wantView: "CDB_TABLES"},
		{name: "non-root uses DBA_TABLES", useCDB: false, wantView: "DBA_TABLES"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scrpr := oracleScraper{useCDBTableMetadataViews: test.useCDB}
			got := scrpr.buildTableMetadataSQL()
			assert.Contains(t, got, test.wantView)
		})
	}
}

func TestBuildViewMetadataSQL(t *testing.T) {
	tests := []struct {
		name     string
		useCDB   bool
		wantView string
	}{
		{name: "CDB root uses CDB_VIEWS", useCDB: true, wantView: "CDB_VIEWS"},
		{name: "non-root uses DBA_VIEWS", useCDB: false, wantView: "DBA_VIEWS"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scrpr := oracleScraper{useCDBTableMetadataViews: test.useCDB}
			got := scrpr.buildViewMetadataSQL()
			assert.Contains(t, got, test.wantView)
			// TEXT_VC, not the legacy LONG-typed TEXT column.
			assert.Contains(t, got, "TEXT_VC")
		})
	}
}
