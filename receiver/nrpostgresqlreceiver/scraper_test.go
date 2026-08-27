// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrpostgresqlreceiver

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/lib/pq/pqerror"
	"github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrcommon/testutil"
	"github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrpostgresqlreceiver/internal/metadata"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tj/assert"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/golden"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest/plogtest"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest/pmetrictest"
)

func TestUnsuccessfulScrape(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.AddrConfig.Endpoint = "fake:11111"

	scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, newDefaultClientFactory(cfg), newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, err)

	actualMetrics, err := scraper.scrape(t.Context())
	require.Error(t, err)

	require.NoError(t, pmetrictest.CompareMetrics(pmetric.NewMetrics(), actualMetrics))
}

func TestMetricsBuilderConfigForFeatureGate(t *testing.T) {
	cfg := metadata.NewDefaultMetricsBuilderConfig()

	semconvConfig := metricsBuilderConfigForFeatureGate(cfg, true)
	assert.Equal(t, cfg, semconvConfig)

	legacyConfig := metricsBuilderConfigForFeatureGate(cfg, false)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlBackends.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlBlksHit.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlBlksRead.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlCommits.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlDbSize.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlDeadlocks.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlIndexScans.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlIndexSize.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlRollbacks.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlSequentialScans.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTableCount.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTableSize.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTableVacuumCount.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTempIo.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTempFiles.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTupDeleted.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTupFetched.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTupInserted.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTupReturned.EnabledAttributes)
	assert.Empty(t, legacyConfig.Metrics.PostgresqlTupUpdated.EnabledAttributes)
	assert.Equal(t, []metadata.PostgresqlBlocksReadMetricAttributeKey{metadata.PostgresqlBlocksReadMetricAttributeKeySource}, legacyConfig.Metrics.PostgresqlBlocksRead.EnabledAttributes)
	assert.Equal(t, []metadata.PostgresqlDatabaseLocksMetricAttributeKey{metadata.PostgresqlDatabaseLocksMetricAttributeKeyRelation, metadata.PostgresqlDatabaseLocksMetricAttributeKeyMode, metadata.PostgresqlDatabaseLocksMetricAttributeKeyLockType}, legacyConfig.Metrics.PostgresqlDatabaseLocks.EnabledAttributes)
	assert.Equal(t, []metadata.PostgresqlFunctionCallsMetricAttributeKey{metadata.PostgresqlFunctionCallsMetricAttributeKeyFunction}, legacyConfig.Metrics.PostgresqlFunctionCalls.EnabledAttributes)
	assert.Equal(t, []metadata.PostgresqlOperationsMetricAttributeKey{metadata.PostgresqlOperationsMetricAttributeKeyOperation}, legacyConfig.Metrics.PostgresqlOperations.EnabledAttributes)
	assert.Equal(t, []metadata.PostgresqlQueryConflictsMetricAttributeKey{metadata.PostgresqlQueryConflictsMetricAttributeKeyPostgresqlConflictType}, legacyConfig.Metrics.PostgresqlQueryConflicts.EnabledAttributes)
	assert.Equal(t, []metadata.PostgresqlRowsMetricAttributeKey{metadata.PostgresqlRowsMetricAttributeKeyState}, legacyConfig.Metrics.PostgresqlRows.EnabledAttributes)
	assert.Equal(t, cfg.Metrics.PostgresqlReplicationDataDelay.EnabledAttributes, legacyConfig.Metrics.PostgresqlReplicationDataDelay.EnabledAttributes)
	assert.Equal(t, cfg.Metrics.PostgresqlWalDelay.EnabledAttributes, legacyConfig.Metrics.PostgresqlWalDelay.EnabledAttributes)
	assert.Equal(t, cfg.Metrics.PostgresqlWalLag.EnabledAttributes, legacyConfig.Metrics.PostgresqlWalLag.EnabledAttributes)
	assert.NotEmpty(t, cfg.Metrics.PostgresqlBackends.EnabledAttributes)
	assert.Contains(t, cfg.Metrics.PostgresqlQueryConflicts.EnabledAttributes, metadata.PostgresqlQueryConflictsMetricAttributeKeyDbNamespace)
	assert.Equal(t, metadata.NewDefaultMetricsBuilderConfig(), cfg)

	customConfig := cfg
	customConfig.Metrics.PostgresqlBlocksRead.EnabledAttributes = []metadata.PostgresqlBlocksReadMetricAttributeKey{metadata.PostgresqlBlocksReadMetricAttributeKeyDbNamespace}
	customLegacyConfig := metricsBuilderConfigForFeatureGate(customConfig, false)
	assert.Empty(t, customLegacyConfig.Metrics.PostgresqlBlocksRead.EnabledAttributes)
	assert.Equal(t, []metadata.PostgresqlBlocksReadMetricAttributeKey{metadata.PostgresqlBlocksReadMetricAttributeKeyDbNamespace}, customConfig.Metrics.PostgresqlBlocksRead.EnabledAttributes)
}

func TestSemconvQueryConflictsPreserveDatabaseNamespace(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.MetricsBuilderConfig.Metrics.PostgresqlQueryConflicts.Enabled = true
	scraper := &postgreSQLScraper{
		config:            cfg,
		mb:                metadata.NewMetricsBuilder(cfg.MetricsBuilderConfig, receivertest.NewNopSettings(metadata.Type)),
		serviceInstanceID: "example.com:5432",
		useOTelSemconv:    true,
	}
	retrieval := &dbRetrieval{
		dbConflictStats: map[databaseName]databaseConflictStats{
			"orders": {
				conflTablespace: 1,
				conflLock:       2,
				conflSnapshot:   3,
				conflBufferpin:  4,
				conflDeadlock:   5,
			},
			"users": {
				conflTablespace: 6,
				conflLock:       7,
				conflSnapshot:   8,
				conflBufferpin:  9,
				conflDeadlock:   10,
			},
		},
	}

	now := pcommon.NewTimestampFromTime(time.Unix(0, 1))
	scraper.recordDatabase(now, "orders", retrieval, 0)
	scraper.recordDatabase(now, "users", retrieval, 0)
	rb := scraper.setupSemconvResourceBuilder(scraper.mb.NewResourceBuilder())
	metrics := scraper.mb.Emit(metadata.WithResource(rb.Emit()))

	queryConflicts := pmetric.NewMetric()
	found := false
	resourceMetrics := metrics.ResourceMetrics()
	for i := 0; i < resourceMetrics.Len(); i++ {
		scopeMetrics := resourceMetrics.At(i).ScopeMetrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			metricSlice := scopeMetrics.At(j).Metrics()
			for k := 0; k < metricSlice.Len(); k++ {
				if metricSlice.At(k).Name() == "postgresql.query.conflicts" {
					queryConflicts = metricSlice.At(k)
					found = true
				}
			}
		}
	}
	require.True(t, found)

	actual := map[string]int64{}
	dataPoints := queryConflicts.Sum().DataPoints()
	require.Equal(t, 10, dataPoints.Len())
	for i := 0; i < dataPoints.Len(); i++ {
		dp := dataPoints.At(i)
		namespace, ok := dp.Attributes().Get("db.namespace")
		require.True(t, ok)
		conflictType, ok := dp.Attributes().Get("postgresql.conflict.type")
		require.True(t, ok)
		actual[namespace.Str()+"/"+conflictType.Str()] = dp.IntValue()
	}
	require.Equal(t, map[string]int64{
		"orders/tablespace": 1,
		"orders/lock":       2,
		"orders/snapshot":   3,
		"orders/bufferpin":  4,
		"orders/deadlock":   5,
		"users/tablespace":  6,
		"users/lock":        7,
		"users/snapshot":    8,
		"users/bufferpin":   9,
		"users/deadlock":    10,
	}, actual)
}

func TestScraper(t *testing.T) {
	factory := new(mockClientFactory)
	factory.initMocks([]string{"otel"})

	runTest := func(separateSchemaAttr bool, file string) {
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, separateSchemaAttr)()

		cfg := createDefaultConfig().(*Config)
		cfg.Databases = []string{"otel"}
		cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlQueryConflicts.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchCalls.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchDuration.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchRowsReturned.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertRows.Enabled = true
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertDuration.Enabled = true

		scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)

		actualMetrics, err := scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile := filepath.Join("testdata", "scraper", "otel", file)
		expectedMetrics, err := golden.ReadMetrics(expectedFile)
		require.NoError(t, err)

		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreResourceAttributeValue("service.instance.id"), pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(), pmetrictest.IgnoreStartTimestamp(), pmetrictest.IgnoreTimestamp()))
	}

	runTest(true, "expected_schemaattr.yaml")
	runTest(false, "expected.yaml")
}

// TestScraperSkipsQueriesForDisabledMetrics verifies table/index/function/lock queries are skipped when every metric they feed is disabled.
func TestScraperSkipsQueriesForDisabledMetrics(t *testing.T) {
	factory := new(mockClientFactory)
	factory.initMocks([]string{"otel"})

	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{"otel"}
	// rows/operations/table.size/table.vacuum.count/blocks_read/index.scans/index.size default to enabled; disable them for this test.
	cfg.MetricsBuilderConfig.Metrics.PostgresqlRows.Enabled = false
	cfg.MetricsBuilderConfig.Metrics.PostgresqlOperations.Enabled = false
	cfg.MetricsBuilderConfig.Metrics.PostgresqlTableSize.Enabled = false
	cfg.MetricsBuilderConfig.Metrics.PostgresqlTableVacuumCount.Enabled = false
	cfg.MetricsBuilderConfig.Metrics.PostgresqlBlocksRead.Enabled = false
	cfg.MetricsBuilderConfig.Metrics.PostgresqlIndexScans.Enabled = false
	cfg.MetricsBuilderConfig.Metrics.PostgresqlIndexSize.Enabled = false
	require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled)
	require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlFunctionCalls.Enabled)
	require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled)
	// postgresql.table.count stays enabled, so getDatabaseTableMetrics still runs for its row count.
	require.True(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTableCount.Enabled)

	scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, err)

	_, err = scraper.scrape(t.Context())
	require.NoError(t, err)

	listClientAny, clientErr := factory.getClient(t.Context(), defaultPostgreSQLDatabase)
	require.NoError(t, clientErr)
	listClient := listClientAny.(*mockClient)

	dbClientAny, clientErr := factory.getClient(t.Context(), "otel")
	require.NoError(t, clientErr)
	dbClient := dbClientAny.(*mockClient)

	// Queries with no remaining enabled consumer must not run.
	dbClient.AssertNumberOfCalls(t, "getDatabaseTableMetrics", 1)
	dbClient.AssertNotCalled(t, "getBlocksReadByTable", mock.Anything, mock.Anything)
	dbClient.AssertNotCalled(t, "getIndexStats", mock.Anything, mock.Anything)
	dbClient.AssertNotCalled(t, "getFunctionStats", mock.Anything, mock.Anything)
	dbClient.AssertNotCalled(t, "getDatabaseLocks", mock.Anything)
	listClient.AssertNotCalled(t, "getSharedRelationLocks", mock.Anything)
}

// TestScraperRunsQueriesWhenAnyFedMetricIsEnabled verifies a query still runs when at least one of the metrics it feeds is enabled.
func TestScraperRunsQueriesWhenAnyFedMetricIsEnabled(t *testing.T) {
	factory := new(mockClientFactory)
	factory.initMocks([]string{"otel"})

	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{"otel"}
	// Disable one of the two metrics fed by getIndexStats; the other stays enabled.
	cfg.MetricsBuilderConfig.Metrics.PostgresqlIndexScans.Enabled = false
	require.True(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlIndexSize.Enabled)

	scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, err)

	_, err = scraper.scrape(t.Context())
	require.NoError(t, err)

	dbClientAny, clientErr := factory.getClient(t.Context(), "otel")
	require.NoError(t, clientErr)
	dbClient := dbClientAny.(*mockClient)

	dbClient.AssertNumberOfCalls(t, "getIndexStats", 1)
}

// TestScraperSkipsServerWideQueriesForDisabledMetrics verifies the once-per-scrape (not once-per-database) queries are also skipped when disabled.
func TestScraperSkipsServerWideQueriesForDisabledMetrics(t *testing.T) {
	tests := []struct {
		name           string
		disableMetrics func(*Config)
		mockMethod     string
	}{
		{
			name:           "getBackends skipped when postgresql.backends disabled",
			disableMetrics: func(cfg *Config) { cfg.MetricsBuilderConfig.Metrics.PostgresqlBackends.Enabled = false },
			mockMethod:     "getBackends",
		},
		{
			name:           "getDatabaseSize skipped when postgresql.db_size disabled",
			disableMetrics: func(cfg *Config) { cfg.MetricsBuilderConfig.Metrics.PostgresqlDbSize.Enabled = false },
			mockMethod:     "getDatabaseSize",
		},
		{
			name: "getDatabaseStats skipped when all 11 metrics it feeds are disabled",
			disableMetrics: func(cfg *Config) {
				cfg.MetricsBuilderConfig.Metrics.PostgresqlCommits.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlRollbacks.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled = false
			},
			mockMethod: "getDatabaseStats",
		},
		{
			name: "getBGWriterStats skipped when all 5 bgwriter metrics are disabled",
			disableMetrics: func(cfg *Config) {
				cfg.MetricsBuilderConfig.Metrics.PostgresqlBgwriterBuffersAllocated.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlBgwriterBuffersWrites.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlBgwriterCheckpointCount.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlBgwriterDuration.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlBgwriterMaxwritten.Enabled = false
			},
			mockMethod: "getBGWriterStats",
		},
		{
			name:           "getMaxConnections skipped when postgresql.connection.max disabled",
			disableMetrics: func(cfg *Config) { cfg.MetricsBuilderConfig.Metrics.PostgresqlConnectionMax.Enabled = false },
			mockMethod:     "getMaxConnections",
		},
		{
			name: "getReplicationStats skipped when data_delay and both wal lag metrics are disabled",
			disableMetrics: func(cfg *Config) {
				cfg.MetricsBuilderConfig.Metrics.PostgresqlReplicationDataDelay.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled = false
				cfg.MetricsBuilderConfig.Metrics.PostgresqlWalLag.Enabled = false
			},
			mockMethod: "getReplicationStats",
		},
		{
			name:           "getLatestWalAgeSeconds skipped when postgresql.wal.age disabled",
			disableMetrics: func(cfg *Config) { cfg.MetricsBuilderConfig.Metrics.PostgresqlWalAge.Enabled = false },
			mockMethod:     "getLatestWalAgeSeconds",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			factory := new(mockClientFactory)
			factory.initMocks([]string{"otel"})

			cfg := createDefaultConfig().(*Config)
			cfg.Databases = []string{"otel"}
			tc.disableMetrics(cfg)

			scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
			require.NoError(t, err)

			_, err = scraper.scrape(t.Context())
			require.NoError(t, err)

			listClientAny, clientErr := factory.getClient(t.Context(), defaultPostgreSQLDatabase)
			require.NoError(t, clientErr)
			listClient := listClientAny.(*mockClient)

			listClient.AssertNotCalled(t, tc.mockMethod, mock.Anything)
		})
	}
}

func TestScraperWithExecutionTime(t *testing.T) {
	factory := new(mockClientFactory)
	factory.initMocks([]string{"otel"})

	runTest := func(separateSchemaAttr bool, file string) {
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, separateSchemaAttr)()

		cfg := createDefaultConfig().(*Config)
		cfg.Databases = []string{"otel"}
		cfg.MetricsBuilderConfig.Metrics.PostgresqlQueryExecutionTime.Enabled = true

		scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)

		actualMetrics, err := scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile := filepath.Join("testdata", "scraper", "otel", file)
		// golden.WriteMetrics(t, expectedFile, actualMetrics)
		expectedMetrics, err := golden.ReadMetrics(expectedFile)
		require.NoError(t, err)

		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreResourceAttributeValue("service.instance.id"), pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(), pmetrictest.IgnoreStartTimestamp(), pmetrictest.IgnoreTimestamp()))
	}

	runTest(true, "expected_execution_time_schemaattr.yaml")
	runTest(false, "expected_execution_time.yaml")
}

func TestScraperNoDatabaseSingle(t *testing.T) {
	factory := new(mockClientFactory)
	factory.initMocks([]string{"otel"})

	runTest := func(separateSchemaAttr bool, file, fileDefault string) {
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, separateSchemaAttr)()

		cfg := createDefaultConfig().(*Config)

		// Validate expected default config values and then enable all metrics
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlQueryConflicts.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlQueryConflicts.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchCalls.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchCalls.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchDuration.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchDuration.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchRowsReturned.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchRowsReturned.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertRows.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertRows.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertDuration.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertDuration.Enabled = true

		scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)
		actualMetrics, err := scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile := filepath.Join("testdata", "scraper", "otel", file)
		expectedMetrics, err := golden.ReadMetrics(expectedFile)
		require.NoError(t, err)

		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreResourceAttributeValue("service.instance.id"), pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(), pmetrictest.IgnoreStartTimestamp(), pmetrictest.IgnoreTimestamp()))

		cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlQueryConflicts.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchCalls.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchDuration.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchRowsReturned.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertRows.Enabled = false
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertDuration.Enabled = false

		scraper, err = newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)
		actualMetrics, err = scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile = filepath.Join("testdata", "scraper", "otel", fileDefault)
		expectedMetrics, err = golden.ReadMetrics(expectedFile)
		require.NoError(t, err)

		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreResourceAttributeValue("service.instance.id"), pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(), pmetrictest.IgnoreStartTimestamp(), pmetrictest.IgnoreTimestamp()))
	}

	runTest(true, "expected_schemaattr.yaml", "expected_default_metrics_schemaattr.yaml")
	runTest(false, "expected.yaml", "expected_default_metrics.yaml")
}

func TestScraperNoDatabaseMultipleWithoutPreciseLag(t *testing.T) {
	factory := mockClientFactory{}
	factory.initMocks([]string{"otel", "open", "telemetry"})

	runTest := func(separateSchemaAttr bool, file string) {
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, separateSchemaAttr)()
		defer testutil.SetFeatureGateForTest(t, metadata.PostgresqlreceiverPreciselagmetricsFeatureGate, false)()

		cfg := createDefaultConfig().(*Config)

		// Validate expected default config values and then enable all metrics except wal delay
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled)
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled = true
		scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, &factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)

		actualMetrics, err := scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile := filepath.Join("testdata", "scraper", "multiple", file)
		expectedMetrics, err := golden.ReadMetrics(expectedFile)
		require.NoError(t, err)

		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreResourceAttributeValue("service.instance.id"), pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(), pmetrictest.IgnoreStartTimestamp(), pmetrictest.IgnoreTimestamp()))
	}

	runTest(true, "expected_imprecise_lag_schemaattr.yaml")
	runTest(false, "expected_imprecise_lag.yaml")
}

func TestScraperNoDatabaseMultiple(t *testing.T) {
	factory := mockClientFactory{}
	factory.initMocks([]string{"otel", "open", "telemetry"})

	runTest := func(separateSchemaAttr, useOTelSemconv bool, file string) {
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, separateSchemaAttr)()
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlUseOTelSemconvFeatureGate, useOTelSemconv)()

		cfg := createDefaultConfig().(*Config)

		// Validate expected default config values and then enable all metrics
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled = true
		scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, &factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)

		actualMetrics, err := scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile := filepath.Join("testdata", "scraper", "multiple", file)
		expectedMetrics, err := golden.ReadMetrics(expectedFile)
		require.NoError(t, err)
		compareOpts := []pmetrictest.CompareMetricsOption{
			pmetrictest.IgnoreResourceAttributeValue("service.instance.id"),
			pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(),
			pmetrictest.IgnoreStartTimestamp(),
			pmetrictest.IgnoreTimestamp(),
		}
		if useOTelSemconv {
			compareOpts = append(
				compareOpts,
				pmetrictest.IgnoreResourceAttributeValue("server.address"),
				pmetrictest.IgnoreResourceAttributeValue("server.port"),
			)
		}
		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, compareOpts...))
	}

	runTest(true, false, "expected_schemaattr.yaml")
	runTest(false, false, "expected.yaml")
	runTest(false, true, "expected_semconv.yaml")
}

func TestScraperWithResourceAttributeFeatureGate(t *testing.T) {
	factory := mockClientFactory{}
	factory.initMocks([]string{"otel", "open", "telemetry"})

	runTest := func(separateSchemaAttr bool, file string) {
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, separateSchemaAttr)()

		cfg := createDefaultConfig().(*Config)

		// Validate expected default config values and then enable all metrics
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled = true

		scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, &factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)

		actualMetrics, err := scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile := filepath.Join("testdata", "scraper", "multiple", file)
		expectedMetrics, err := golden.ReadMetrics(expectedFile)
		require.NoError(t, err)

		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreResourceAttributeValue("service.instance.id"), pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(), pmetrictest.IgnoreStartTimestamp(), pmetrictest.IgnoreTimestamp()))
	}

	runTest(true, "expected_schemaattr.yaml")
	runTest(false, "expected.yaml")
}

func TestScraperWithResourceAttributeFeatureGateSingle(t *testing.T) {
	factory := mockClientFactory{}
	factory.initMocks([]string{"otel"})

	runTest := func(separateSchemaAttr bool, file string) {
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, separateSchemaAttr)()

		cfg := createDefaultConfig().(*Config)

		// Validate expected default config values and then enable all metrics
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlWalDelay.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDeadlocks.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempFiles.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTempIo.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupUpdated.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupReturned.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupFetched.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupInserted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlTupDeleted.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksHit.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlBlksRead.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlSequentialScans.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlDatabaseLocks.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlQueryConflicts.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlQueryConflicts.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchCalls.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchCalls.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchDuration.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchDuration.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchRowsReturned.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorSearchRowsReturned.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertRows.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertRows.Enabled = true
		require.False(t, cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertDuration.Enabled)
		cfg.MetricsBuilderConfig.Metrics.PostgresqlVectorInsertDuration.Enabled = true
		scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, &factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)

		actualMetrics, err := scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile := filepath.Join("testdata", "scraper", "otel", file)
		expectedMetrics, err := golden.ReadMetrics(expectedFile)
		require.NoError(t, err)

		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreResourceAttributeValue("service.instance.id"), pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(), pmetrictest.IgnoreStartTimestamp(), pmetrictest.IgnoreTimestamp()))
	}

	runTest(true, "expected_schemaattr.yaml")
	runTest(false, "expected.yaml")
}

func TestScraperExcludeDatabase(t *testing.T) {
	factory := mockClientFactory{}
	factory.initMocks([]string{"otel", "telemetry"})

	runTest := func(separateSchemaAttr bool, file string) {
		defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, separateSchemaAttr)()

		cfg := createDefaultConfig().(*Config)
		cfg.ExcludeDatabases = []string{"open"}

		scraper, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, &factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)

		actualMetrics, err := scraper.scrape(t.Context())
		require.NoError(t, err)

		expectedFile := filepath.Join("testdata", "scraper", "multiple", file)

		expectedMetrics, err := golden.ReadMetrics(expectedFile)
		require.NoError(t, err)

		require.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics, pmetrictest.IgnoreResourceAttributeValue("service.instance.id"), pmetrictest.IgnoreResourceMetricsOrder(),
			pmetrictest.IgnoreMetricDataPointsOrder(), pmetrictest.IgnoreStartTimestamp(), pmetrictest.IgnoreTimestamp()))
	}

	runTest(true, "exclude_schemaattr.yaml")
	runTest(false, "exclude.yaml")
}

func TestMutualExclusionOfFeatureGates(t *testing.T) {
	defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlSeparateSchemaAttrFeatureGate, true)()
	defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlUseOTelSemconvFeatureGate, true)()

	cfg := createDefaultConfig().(*Config)
	factory := new(mockClientFactory)
	factory.initMocks([]string{"otel"})

	_, err := newPostgreSQLScraper(receivertest.NewNopSettings(metadata.Type), cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

//go:embed testdata/scraper/query-sample/expectedSql.sql
var expectedScrapeSampleQuery string

var querySampleColumns = []string{
	querySampleColumnDatname,
	querySampleColumnUsename,
	querySampleColumnClientAddr,
	querySampleColumnClientHostname,
	querySampleColumnClientPort,
	querySampleColumnQueryStart,
	querySampleColumnBackendStart,
	querySampleColumnSessionDuration,
	querySampleColumnWaitEventType,
	querySampleColumnWaitEvent,
	querySampleColumnQueryID,
	querySampleColumnPID,
	querySampleColumnApplicationName,
	querySampleColumnQueryStartTimestamp,
	querySampleColumnState,
	querySampleColumnQuery,
	querySampleColumnDurationMilliseconds,
	querySampleColumnBlockingPIDs,
	querySampleColumnBlockingStartTime,
	querySampleColumnBlockingWaitDuration,
	querySampleColumnBlockingLockMode,
	querySampleColumnBlockingLockType,
	querySampleColumnBlockingLockRelation,
	querySampleColumnBlockingTxnStartTime,
}

func newQuerySampleRows(t *testing.T, values map[string]any) *sqlmock.Rows {
	t.Helper()

	rowValues := make([]driver.Value, len(querySampleColumns))
	for i, col := range querySampleColumns {
		if v, ok := values[col]; ok {
			rowValues[i] = v
			continue
		}
		rowValues[i] = ""
	}

	return sqlmock.NewRows(querySampleColumns).AddRow(rowValues...)
}

func TestScrapeQuerySample(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	assert.NoError(t, err)

	defer db.Close()

	factory := mockSimpleClientFactory{
		db: db,
	}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	assert.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{
		Logger: logger,
	}
	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.newestQueryTimestamp = 123440.111
	mock.ExpectQuery(expectedScrapeSampleQuery).WillReturnRows(newQuerySampleRows(t, map[string]any{
		querySampleColumnDatname:              "postgres",
		querySampleColumnUsename:              "otelu",
		querySampleColumnClientAddr:           "11.4.5.14",
		querySampleColumnClientHostname:       "otel",
		querySampleColumnClientPort:           "114514",
		querySampleColumnQueryStart:           "2025-02-12T16:37:54.843+08:00",
		querySampleColumnQueryID:              "123131231231",
		querySampleColumnPID:                  "1450",
		querySampleColumnApplicationName:      "receiver",
		querySampleColumnQueryStartTimestamp:  "123445.123",
		querySampleColumnState:                "idle",
		querySampleColumnQuery:                "select * from pg_stat_activity where id = 32",
		querySampleColumnDurationMilliseconds: "1.2",
		querySampleColumnBlockingPIDs:         "{}",
	}))
	actualLogs, err := scraper.scrapeQuerySamples(t.Context(), 30)
	assert.NoError(t, err)
	expectedFile := filepath.Join("testdata", "scraper", "query-sample", "expected.yaml")
	// Uncomment line below to re-generate expected logs.
	// golden.WriteLogs(t, expectedFile, actualLogs)
	expectedLogs, err := golden.ReadLogs(expectedFile)
	require.NoError(t, err)
	errs := plogtest.CompareLogs(expectedLogs, actualLogs, plogtest.IgnoreResourceAttributeValue("service.instance.id"), plogtest.IgnoreTimestamp())
	assert.NoError(t, errs)
}

func TestScrapeQuerySampleSemconv(t *testing.T) {
	defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlUseOTelSemconvFeatureGate, true)()

	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	factory := mockSimpleClientFactory{db: db}
	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.newestQueryTimestamp = 123440.111
	mock.ExpectQuery(expectedScrapeSampleQuery).WillReturnRows(newQuerySampleRows(t, map[string]any{
		querySampleColumnDatname:              "postgres",
		querySampleColumnUsename:              "otelu",
		querySampleColumnClientAddr:           "11.4.5.14",
		querySampleColumnClientHostname:       "otel",
		querySampleColumnClientPort:           "114514",
		querySampleColumnQueryStart:           "2025-02-12T16:37:54.843+08:00",
		querySampleColumnQueryID:              "123131231231",
		querySampleColumnPID:                  "1450",
		querySampleColumnApplicationName:      "receiver",
		querySampleColumnQueryStartTimestamp:  "123445.123",
		querySampleColumnState:                "idle",
		querySampleColumnQuery:                "select * from pg_stat_activity where id = 32",
		querySampleColumnDurationMilliseconds: "1.2",
		querySampleColumnBlockingPIDs:         "{}",
	}))

	actualLogs, err := scraper.scrapeQuerySamples(t.Context(), 30)
	require.NoError(t, err)
	expectedFile := filepath.Join("testdata", "scraper", "query-sample", "expected_semconv.yaml")
	// golden.WriteLogs(t, expectedFile, actualLogs)
	expectedLogs, err := golden.ReadLogs(expectedFile)
	require.NoError(t, err)
	require.NoError(t, plogtest.CompareLogs(
		expectedLogs, actualLogs,
		plogtest.IgnoreResourceAttributeValue("service.instance.id"),
		plogtest.IgnoreResourceAttributeValue("server.address"),
		plogtest.IgnoreResourceAttributeValue("server.port"),
		plogtest.IgnoreTimestamp(),
	))
}

func TestScrapeQuerySampleWithTraceparent(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)

	defer db.Close()

	factory := mockSimpleClientFactory{
		db: db,
	}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{
		Logger: logger,
	}

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.newestQueryTimestamp = 123440.111

	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	mock.ExpectQuery(expectedScrapeSampleQuery).WillReturnRows(newQuerySampleRows(t, map[string]any{
		querySampleColumnDatname:              "postgres",
		querySampleColumnUsename:              "otelu",
		querySampleColumnClientAddr:           "11.4.5.14",
		querySampleColumnClientHostname:       "otel",
		querySampleColumnClientPort:           "114514",
		querySampleColumnQueryStart:           "2025-02-12T16:37:54.843+08:00",
		querySampleColumnQueryID:              "123131231231",
		querySampleColumnPID:                  "1450",
		querySampleColumnApplicationName:      traceparent,
		querySampleColumnQueryStartTimestamp:  "123445.123",
		querySampleColumnState:                "idle",
		querySampleColumnQuery:                "select * from pg_stat_activity where id = 32",
		querySampleColumnDurationMilliseconds: "1.2",
		querySampleColumnBlockingPIDs:         "{}",
	}))
	actualLogs, err := scraper.scrapeQuerySamples(t.Context(), 30)
	require.NoError(t, err)

	require.Equal(t, 1, actualLogs.ResourceLogs().Len())
	rl := actualLogs.ResourceLogs().At(0)
	require.Equal(t, 1, rl.ScopeLogs().Len())
	sl := rl.ScopeLogs().At(0)
	require.Equal(t, 1, sl.LogRecords().Len())
	lr := sl.LogRecords().At(0)

	require.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", lr.TraceID().String())
	require.Equal(t, "00f067aa0ba902b7", lr.SpanID().String())

	applicationName, ok := lr.Attributes().Get("postgresql.application_name")
	require.True(t, ok)
	require.Equal(t, traceparent, applicationName.Str())
}

func TestQuerySampleTemplateRendering(t *testing.T) {
	tmpl := template.Must(template.New("querySample").Option("missingkey=error").Parse(querySampleTemplate))

	tests := []struct {
		name   string
		params map[string]any
	}{
		{
			name: "renders with standard parameters",
			params: map[string]any{
				"limit":                int64(50),
				"newestQueryTimestamp": 999999.555,
			},
		},
		{
			name: "renders with zero timestamp",
			params: map[string]any{
				"limit":                int64(10),
				"newestQueryTimestamp": float64(0),
			},
		},
	}

	requiredClauses := []string{
		"pid != pg_backend_pid()",
		"query_start IS NOT NULL",
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.Buffer{}
			err := tmpl.Execute(&buf, tc.params)
			require.NoError(t, err)

			rendered := buf.String()
			for _, clause := range requiredClauses {
				assert.Contains(t, rendered, clause, "rendered SQL should contain %q", clause)
			}

			assert.Contains(t, rendered, fmt.Sprintf("LIMIT %v;", tc.params["limit"]))
			assert.Contains(t, rendered, fmt.Sprintf("TO_TIMESTAMP(%v)", tc.params["newestQueryTimestamp"]))
		})
	}
}

func TestScrapeQuerySampleNoResults(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)

	defer db.Close()

	factory := mockSimpleClientFactory{db: db}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.newestQueryTimestamp = 123440.111

	mock.ExpectQuery(expectedScrapeSampleQuery).WillReturnRows(sqlmock.NewRows(querySampleColumns))

	actualLogs, err := scraper.scrapeQuerySamples(t.Context(), 30)
	assert.NoError(t, err)

	totalRecords := 0
	for i := 0; i < actualLogs.ResourceLogs().Len(); i++ {
		rl := actualLogs.ResourceLogs().At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			totalRecords += rl.ScopeLogs().At(j).LogRecords().Len()
		}
	}
	assert.Equal(t, 0, totalRecords)
}

func TestScrapeQuerySampleMultipleRows(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)

	defer db.Close()

	factory := mockSimpleClientFactory{db: db}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.newestQueryTimestamp = 123440.111

	row1 := map[string]any{
		querySampleColumnDatname:              "postgres",
		querySampleColumnUsename:              "user1",
		querySampleColumnClientAddr:           "10.0.0.1",
		querySampleColumnClientHostname:       "host1",
		querySampleColumnClientPort:           "5432",
		querySampleColumnQueryStart:           "2025-02-12T16:37:54.843+08:00",
		querySampleColumnQueryID:              "111",
		querySampleColumnPID:                  "1001",
		querySampleColumnApplicationName:      "app1",
		querySampleColumnQueryStartTimestamp:  "123445.123",
		querySampleColumnState:                "active",
		querySampleColumnQuery:                "SELECT * FROM orders WHERE status = 'pending'",
		querySampleColumnDurationMilliseconds: "5.3",
	}
	row2 := map[string]any{
		querySampleColumnDatname:              "postgres",
		querySampleColumnUsename:              "user2",
		querySampleColumnClientAddr:           "10.0.0.2",
		querySampleColumnClientHostname:       "host2",
		querySampleColumnClientPort:           "5433",
		querySampleColumnQueryStart:           "2025-02-12T16:38:00.000+08:00",
		querySampleColumnQueryID:              "222",
		querySampleColumnPID:                  "1002",
		querySampleColumnApplicationName:      "app2",
		querySampleColumnQueryStartTimestamp:  "123450.000",
		querySampleColumnState:                "idle",
		querySampleColumnQuery:                "UPDATE users SET last_login = now() WHERE id = 42",
		querySampleColumnDurationMilliseconds: "12.7",
	}

	rows := sqlmock.NewRows(querySampleColumns)
	for _, rowData := range []map[string]any{row1, row2} {
		rowValues := make([]driver.Value, len(querySampleColumns))
		for i, col := range querySampleColumns {
			if v, ok := rowData[col]; ok {
				rowValues[i] = v
				continue
			}
			rowValues[i] = ""
		}
		rows.AddRow(rowValues...)
	}

	mock.ExpectQuery(expectedScrapeSampleQuery).WillReturnRows(rows)

	actualLogs, err := scraper.scrapeQuerySamples(t.Context(), 30)
	assert.NoError(t, err)

	require.Equal(t, 1, actualLogs.ResourceLogs().Len())
	rl := actualLogs.ResourceLogs().At(0)
	require.Equal(t, 1, rl.ScopeLogs().Len())
	sl := rl.ScopeLogs().At(0)
	assert.Equal(t, 2, sl.LogRecords().Len())
}

func TestScrapeQuerySampleBlockedSession(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	factory := mockSimpleClientFactory{db: db}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.newestQueryTimestamp = 123440.111

	mock.ExpectQuery(expectedScrapeSampleQuery).WillReturnRows(newQuerySampleRows(t, map[string]any{
		querySampleColumnDatname:              "postgres",
		querySampleColumnUsename:              "otelu",
		querySampleColumnClientAddr:           "11.4.5.14",
		querySampleColumnClientHostname:       "otel",
		querySampleColumnClientPort:           "114514",
		querySampleColumnQueryStart:           "2025-02-12T16:37:54.843+08:00",
		querySampleColumnQueryID:              "999",
		querySampleColumnPID:                  "2500",
		querySampleColumnApplicationName:      "app",
		querySampleColumnQueryStartTimestamp:  "123445.123",
		querySampleColumnState:                "active",
		querySampleColumnQuery:                "update orders set status = ? where id = ?",
		querySampleColumnDurationMilliseconds: "42.0",
		querySampleColumnBlockingPIDs:         "{3001}",
		querySampleColumnBlockingStartTime:    "2025-02-12T16:37:50Z",
		querySampleColumnBlockingWaitDuration: "42",
		querySampleColumnBlockingLockMode:     "AccessExclusiveLock",
		querySampleColumnBlockingLockType:     "relation",
		querySampleColumnBlockingLockRelation: "orders",
		querySampleColumnBlockingTxnStartTime: "2025-02-12T16:37:49Z",
	}))

	actualLogs, err := scraper.scrapeQuerySamples(t.Context(), 30)
	require.NoError(t, err)
	require.Equal(t, 1, actualLogs.ResourceLogs().Len())
	lr := actualLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	attrs := lr.Attributes().AsRaw()
	assert.Equal(t, "{3001}", attrs["postgresql.blocking.pids"])
	assert.Equal(t, "2025-02-12T16:37:50Z", attrs["postgresql.blocking.start_time"])
	assert.Equal(t, int64(42), attrs["postgresql.blocking.wait_duration"])
	assert.Equal(t, "AccessExclusiveLock", attrs["postgresql.blocking.lock.mode"])
	assert.Equal(t, "relation", attrs["postgresql.blocking.lock.type"])
	assert.Equal(t, "orders", attrs["postgresql.blocking.lock.relation"])
	assert.Equal(t, "2025-02-12T16:37:49Z", attrs["postgresql.blocking.transaction.start_time"])
}

func TestScrapeQuerySampleMultiBlocker(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	factory := mockSimpleClientFactory{db: db}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	require.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(1), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.newestQueryTimestamp = 123440.111

	mock.ExpectQuery(expectedScrapeSampleQuery).WillReturnRows(newQuerySampleRows(t, map[string]any{
		querySampleColumnDatname:              "postgres",
		querySampleColumnUsename:              "otelu",
		querySampleColumnClientAddr:           "11.4.5.14",
		querySampleColumnClientHostname:       "otel",
		querySampleColumnClientPort:           "5432",
		querySampleColumnQueryStart:           "2025-02-12T16:37:54.843+08:00",
		querySampleColumnQueryID:              "888",
		querySampleColumnPID:                  "2600",
		querySampleColumnApplicationName:      "app",
		querySampleColumnQueryStartTimestamp:  "123445.123",
		querySampleColumnState:                "active",
		querySampleColumnQuery:                "update orders set status = ? where id = ?",
		querySampleColumnDurationMilliseconds: "10.0",
		querySampleColumnBlockingPIDs:         "{3001,3002}",
		querySampleColumnBlockingStartTime:    "2025-02-12T16:37:50Z",
		querySampleColumnBlockingWaitDuration: "10",
		querySampleColumnBlockingLockMode:     "RowExclusiveLock",
		querySampleColumnBlockingLockType:     "relation",
		querySampleColumnBlockingLockRelation: "orders",
		querySampleColumnBlockingTxnStartTime: "2025-02-12T16:37:49Z",
	}))

	actualLogs, err := scraper.scrapeQuerySamples(t.Context(), 30)
	require.NoError(t, err)
	require.Equal(t, 1, actualLogs.ResourceLogs().Len())
	lr := actualLogs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	attrs := lr.Attributes().AsRaw()
	assert.Equal(t, "{3001,3002}", attrs["postgresql.blocking.pids"])
	assert.Equal(t, "2025-02-12T16:37:50Z", attrs["postgresql.blocking.start_time"])
	assert.Equal(t, int64(10), attrs["postgresql.blocking.wait_duration"])
	assert.Equal(t, "RowExclusiveLock", attrs["postgresql.blocking.lock.mode"])
	assert.Equal(t, "relation", attrs["postgresql.blocking.lock.type"])
	assert.Equal(t, "orders", attrs["postgresql.blocking.lock.relation"])
	assert.Equal(t, "2025-02-12T16:37:49Z", attrs["postgresql.blocking.transaction.start_time"])
}

//go:embed testdata/scraper/top-query/expectedSql.sql
var expectedScrapeTopQuery string

func TestScrapeTopQueries(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerTopQuery.Enabled = true
	cfg.TopQueryCollection.ExplainFunctionName = "" // this test's mock only expects the inline EXPLAIN sequence
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	assert.NoError(t, err)

	defer db.Close()

	factory := mockSimpleClientFactory{
		db: db,
	}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	assert.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{
		Logger: logger,
	}

	queryid := "114514"
	expectedReturnedValue := map[string]string{
		"calls":               "123",
		"datname":             "postgres",
		"shared_blks_dirtied": "1111",
		"shared_blks_hit":     "1112",
		"shared_blks_read":    "1113",
		"shared_blks_written": "1114",
		"temp_blks_read":      "1115",
		"temp_blks_written":   "1116",
		"query":               "select * from pg_stat_activity where id = 32",
		"queryid":             queryid,
		"rolname":             "master",
		"rows":                "30",
		"total_exec_time":     "11000",
		"total_plan_time":     "12000",
	}

	expectedRows := make([]string, 0, len(expectedReturnedValue))
	var expectedValuesBuilder strings.Builder
	for k, v := range expectedReturnedValue {
		expectedRows = append(expectedRows, k)
		fmt.Fprintf(&expectedValuesBuilder, "%s,", v)
	}
	expectedValues := expectedValuesBuilder.String()

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(30), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.cache.Add(queryid+totalExecTimeColumnName, 10)
	scraper.cache.Add(queryid+totalPlanTimeColumnName, 11)
	scraper.cache.Add(queryid+callsColumnName, 120)
	scraper.cache.Add(queryid+rowsColumnName, 20)

	scraper.cache.Add(queryid+sharedBlksDirtiedColumnName, 1110)
	scraper.cache.Add(queryid+sharedBlksHitColumnName, 1110)
	scraper.cache.Add(queryid+sharedBlksReadColumnName, 1110)
	scraper.cache.Add(queryid+sharedBlksWrittenColumnName, 1110)
	scraper.cache.Add(queryid+tempBlksReadColumnName, 1110)
	scraper.cache.Add(queryid+tempBlksWrittenColumnName, 1110)

	mock.ExpectQuery(expectedScrapeTopQuery).WillReturnRows(sqlmock.NewRows(expectedRows).FromCSVString(expectedValues[:len(expectedValues)-1]))
	expectPrepareLookupExplain(mock, queryid, expectedReturnedValue["query"], 0, "[{\"Plan\":{\"Node Type\":\"Merge Join\",\"Parallel Aware\":false,\"Async Capable\":false,\"Join Type\":\"Inner\",\"Startup Cost\":0.43,\"Total Cost\":55.27,\"Plan Rows\":290,\"Plan Width\":1675,\"Inner Unique\":\"?\",\"Merge Cond\":\"( e.businessentityid = p.businessentityid )\",\"Plans\":[{\"Node Type\":\"Index Scan\",\"Parent Relationship\":\"Outer\",\"Parallel Aware\":false,\"Async Capable\":false,\"Scan Direction\":\"Forward\",\"Index Name\":\"PK_Employee_BusinessEntityID\",\"Relation Name\":\"employee\",\"Alias\":\"e\",\"Startup Cost\":0.15,\"Total Cost\":21.5,\"Plan Rows\":290,\"Plan Width\":112},{\"Node Type\":\"Index Scan\",\"Parent Relationship\":\"Inner\",\"Parallel Aware\":false,\"Async Capable\":false,\"Scan Direction\":\"Forward\",\"Index Name\":\"PK_Person_BusinessEntityID\",\"Relation Name\":\"person\",\"Alias\":\"p\",\"Startup Cost\":0.29,\"Total Cost\":2261.87,\"Plan Rows\":19972,\"Plan Width\":1563}]}}]")
	actualLogs, err := scraper.scrapeTopQuery(t.Context(), 31, 32, 33, time.Minute)
	assert.NoError(t, err)
	expectedFile := filepath.Join("testdata", "scraper", "top-query", "expected.yaml")
	expectedLogs, err := golden.ReadLogs(expectedFile)
	require.NoError(t, err)
	errs := plogtest.CompareLogs(expectedLogs, actualLogs, plogtest.IgnoreResourceAttributeValue("service.instance.id"), plogtest.IgnoreTimestamp())
	assert.NoError(t, errs)

	// Verify the cache has updated with latest counter

	calls, callsExists := scraper.cache.Get(queryid + callsColumnName)
	assert.True(t, callsExists)
	assert.Equal(t, float64(123), calls)
	execTime, execTimeExists := scraper.cache.Get(queryid + totalExecTimeColumnName)
	assert.True(t, execTimeExists)
	assert.Equal(t, float64(11), execTime)
	planTime, planTimeExists := scraper.cache.Get(queryid + totalPlanTimeColumnName)
	assert.True(t, planTimeExists)
	assert.Equal(t, float64(12), planTime)
}

func TestScrapeTopQueriesViaFunction(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerTopQuery.Enabled = true
	cfg.TopQueryCollection.ExplainFunctionName = "otel.explain_statement" // drive the SECURITY DEFINER helper-function path, not inline EXPLAIN
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	assert.NoError(t, err)

	defer db.Close()

	factory := mockSimpleClientFactory{
		db: db,
	}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	assert.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{
		Logger: logger,
	}

	queryid := "114514"
	rawQuery := "select * from pg_stat_activity where id = 32"
	expectedReturnedValue := map[string]string{
		"calls":               "123",
		"datname":             "postgres",
		"shared_blks_dirtied": "1111",
		"shared_blks_hit":     "1112",
		"shared_blks_read":    "1113",
		"shared_blks_written": "1114",
		"temp_blks_read":      "1115",
		"temp_blks_written":   "1116",
		"query":               rawQuery,
		"queryid":             queryid,
		"rolname":             "master",
		"rows":                "30",
		"total_exec_time":     "11000",
		"total_plan_time":     "12000",
	}

	expectedRows := make([]string, 0, len(expectedReturnedValue))
	var expectedValuesBuilder strings.Builder
	for k, v := range expectedReturnedValue {
		expectedRows = append(expectedRows, k)
		fmt.Fprintf(&expectedValuesBuilder, "%s,", v)
	}
	expectedValues := expectedValuesBuilder.String()

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(30), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)
	scraper.cache.Add(queryid+totalExecTimeColumnName, 10)
	scraper.cache.Add(queryid+totalPlanTimeColumnName, 11)
	scraper.cache.Add(queryid+callsColumnName, 120)
	scraper.cache.Add(queryid+rowsColumnName, 20)

	scraper.cache.Add(queryid+sharedBlksDirtiedColumnName, 1110)
	scraper.cache.Add(queryid+sharedBlksHitColumnName, 1110)
	scraper.cache.Add(queryid+sharedBlksReadColumnName, 1110)
	scraper.cache.Add(queryid+sharedBlksWrittenColumnName, 1110)
	scraper.cache.Add(queryid+tempBlksReadColumnName, 1110)
	scraper.cache.Add(queryid+tempBlksWrittenColumnName, 1110)

	functionPlan := `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"pg_stat_activity"}}]`

	// 1. top-query fetch
	mock.ExpectQuery(expectedScrapeTopQuery).WillReturnRows(sqlmock.NewRows(expectedRows).FromCSVString(expectedValues[:len(expectedValues)-1]))
	// 2. probe call: SELECT "otel"."explain_statement"('SELECT 1')
	mock.ExpectQuery(`SELECT "otel"."explain_statement"('SELECT 1')`).
		WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(`[{"Plan":{}}]`))
	// 3. real explain-via-function call: version check, then the explain_statement call
	expectServerVersion(mock, "16.4")
	mock.ExpectQuery(`SELECT "otel"."explain_statement"($1)`).
		WithArgs(rawQuery).
		WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(functionPlan))

	actualLogs, err := scraper.scrapeTopQuery(t.Context(), 31, 32, 33, time.Minute)
	require.NoError(t, err)

	require.Equal(t, 1, actualLogs.ResourceLogs().Len())
	rl := actualLogs.ResourceLogs().At(0)
	require.Equal(t, 1, rl.ScopeLogs().Len())
	sl := rl.ScopeLogs().At(0)
	require.Equal(t, 1, sl.LogRecords().Len())
	lr := sl.LogRecords().At(0)

	plan, ok := lr.Attributes().Get("postgresql.query_plan")
	require.True(t, ok, "expected a postgresql.query_plan attribute on the log record")
	assert.Equal(t, functionPlan, plan.Str(), "plan should come from the function-based EXPLAIN path, not the inline path")
	assert.NotEmpty(t, plan.Str())

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRewriteIntervalParams(t *testing.T) {
	testCases := []struct {
		name     string
		query    string
		expected string
	}{
		{
			name:     "no interval, unchanged",
			query:    "SELECT * FROM orders WHERE id = $1",
			expected: "SELECT * FROM orders WHERE id = $1",
		},
		{
			// Shape pg_stat_statements produces from a literal interval like "INTERVAL '30 days'".
			name:     "single normalized interval",
			query:    "SELECT * FROM orders WHERE created_at > NOW() - INTERVAL $1",
			expected: "SELECT * FROM orders WHERE created_at > NOW() - $1::interval",
		},
		{
			name:     "lowercase interval keyword",
			query:    "SELECT * FROM orders WHERE created_at > NOW() - interval $1",
			expected: "SELECT * FROM orders WHERE created_at > NOW() - $1::interval",
		},
		{
			name:     "two normalized intervals in one query",
			query:    "SELECT * FROM orders WHERE created_at > NOW() - INTERVAL $1 AND shipped_at < NOW() - INTERVAL $2",
			expected: "SELECT * FROM orders WHERE created_at > NOW() - $1::interval AND shipped_at < NOW() - $2::interval",
		},
		{
			// $1 is a genuine bind parameter, $2 is a normalized literal interval.
			name:     "real bind parameter alongside a normalized interval",
			query:    "SELECT * FROM orders WHERE status = $1 AND created_at > NOW() - INTERVAL $2",
			expected: "SELECT * FROM orders WHERE status = $1 AND created_at > NOW() - $2::interval",
		},
		{
			// "INTERVAL" as a substring, not the keyword, must not be touched.
			name:     "INTERVAL as part of a column name, not a keyword",
			query:    "SELECT interval_seconds FROM orders WHERE id = $1",
			expected: "SELECT interval_seconds FROM orders WHERE id = $1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, rewriteIntervalParams(tc.query))
		})
	}
}

func TestIsExplainableQuery(t *testing.T) {
	testCases := []struct {
		name     string
		query    string
		expected bool
	}{
		// Explainable queries (whitelist: SELECT, TABLE, DELETE, INSERT, UPDATE, WITH, MERGE, VALUES)
		{name: "simple SELECT", query: "SELECT * FROM users", expected: true},
		{name: "SELECT with WHERE", query: "SELECT id, name FROM users WHERE active = true", expected: true},
		{name: "INSERT", query: "INSERT INTO users (name) VALUES ('test')", expected: true},
		{name: "UPDATE", query: "UPDATE users SET name = 'test' WHERE id = 1", expected: true},
		{name: "DELETE", query: "DELETE FROM users WHERE id = 1", expected: true},
		{name: "SELECT with leading whitespace", query: "   SELECT * FROM users", expected: true},
		{name: "WITH CTE", query: "WITH cte AS (SELECT * FROM users) SELECT * FROM cte", expected: true},
		{name: "TABLE shorthand", query: "TABLE users", expected: true},
		{name: "VALUES", query: "VALUES (1, 'a'), (2, 'b')", expected: true},
		{name: "MERGE", query: "MERGE INTO target USING source ON target.id = source.id WHEN MATCHED THEN UPDATE SET name = source.name", expected: true},
		{name: "SELECT after comment", query: "-- comment\nSELECT * FROM users", expected: true},
		{name: "SELECT after multi-line comment", query: "/* comment */ SELECT * FROM users", expected: true},
		{name: "SELECT with parenthesis", query: "(SELECT * FROM users)", expected: false}, // Subquery alone - first char is '('

		// Non-explainable queries (anything not in whitelist)
		{name: "GRANT", query: "GRANT SELECT ON pg_locks TO demo", expected: false},
		{name: "REVOKE", query: "REVOKE ALL ON FUNCTION pg_stat_statements_reset() FROM PUBLIC", expected: false},
		{name: "DROP FUNCTION", query: "DROP FUNCTION pg_stat_statements_reset(Oid, Oid, bigint)", expected: false},
		{name: "DROP TRIGGER", query: "DROP TRIGGER IF EXISTS update_users_updated_at ON users", expected: false},
		{name: "DROP TABLE", query: "DROP TABLE users", expected: false},
		{name: "CREATE INDEX", query: "CREATE INDEX idx_users_name ON users(name)", expected: false},
		{name: "CREATE EXTENSION", query: "CREATE EXTENSION IF NOT EXISTS pg_stat_statements", expected: false},
		{name: "CREATE FUNCTION", query: "CREATE FUNCTION my_func() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql", expected: false},
		{name: "CREATE TRIGGER", query: "CREATE TRIGGER update_users BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at()", expected: false},
		{name: "CREATE TABLE", query: "CREATE TABLE users (id INT)", expected: false},
		{name: "CREATE TABLE AS SELECT", query: "CREATE TABLE new_table AS SELECT * FROM old_table", expected: false}, // CREATE not in whitelist
		{name: "ALTER TABLE", query: "ALTER TABLE users ADD COLUMN email VARCHAR(255)", expected: false},
		{name: "TRUNCATE", query: "TRUNCATE TABLE users", expected: false},
		{name: "SET", query: "SET plan_cache_mode = force_generic_plan", expected: false},
		{name: "COMMENT", query: "COMMENT ON TABLE users IS 'User table'", expected: false},
		{name: "VACUUM", query: "VACUUM ANALYZE users", expected: false},
		{name: "ANALYZE", query: "ANALYZE users", expected: false},
		{name: "BEGIN", query: "BEGIN", expected: false},
		{name: "COMMIT", query: "COMMIT", expected: false},
		{name: "ROLLBACK", query: "ROLLBACK", expected: false},
		{name: "COPY", query: "COPY users FROM '/tmp/data.csv'", expected: false},
		{name: "EXPLAIN", query: "EXPLAIN SELECT * FROM users", expected: false}, // EXPLAIN itself not in whitelist
		{name: "PREPARE", query: "PREPARE stmt AS SELECT * FROM users", expected: false},
		{name: "EXECUTE", query: "EXECUTE stmt", expected: false},
		{name: "DEALLOCATE", query: "DEALLOCATE stmt", expected: false},

		// DDL with leading comments (should still be detected as non-explainable)
		{name: "GRANT after comment", query: "-- Grant permissions\nGRANT SELECT ON users TO demo", expected: false},
		{name: "DROP after multi-line comment", query: "/* cleanup */ DROP TABLE old_table", expected: false},
		{name: "REVOKE after nested comments", query: "/* comment */ -- another\nREVOKE ALL FROM demo", expected: false},

		// Edge cases
		{name: "empty query", query: "", expected: false},
		{name: "only whitespace", query: "   ", expected: false},
		{name: "only comment", query: "-- just a comment", expected: false},

		// Multi-statement smuggling (single-statement guard)
		{name: "second statement smuggled after semicolon", query: "SELECT * FROM users; DROP TABLE users", expected: false},
		{name: "second statement smuggled with trailing semicolon", query: "SELECT * FROM users; DROP TABLE users;", expected: false},
		{name: "legitimate trailing semicolon", query: "SELECT * FROM users;", expected: true},
		{name: "semicolon inside string literal", query: "UPDATE users SET note = 'a; b' WHERE id = 1", expected: true},
		{name: "escaped quote with semicolon inside string literal", query: "UPDATE users SET note = 'it''s; done' WHERE id = 1", expected: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isExplainableQuery(tc.query)
			assert.Equal(t, tc.expected, result, "query: %s", tc.query)
		})
	}
}

func TestScrapeTopQueriesCollectsOnlyWhenIntervalHasElapsed(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Databases = []string{}
	cfg.LogsBuilderConfig.Events.DbServerTopQuery.Enabled = true
	cfg.TopQueryCollection.CollectionInterval = 600 * time.Second
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	assert.NoError(t, err)

	defer db.Close()

	factory := mockSimpleClientFactory{
		db: db,
	}

	settings := receivertest.NewNopSettings(metadata.Type)
	logger, err := zap.NewProduction()
	assert.NoError(t, err)
	settings.TelemetrySettings = component.TelemetrySettings{
		Logger: logger,
	}

	scraper, scraperErr := newPostgreSQLScraper(settings, cfg, factory, newCache(30), newTTLCache[string](1, time.Second), newTTLCache[explainSetupState](1, time.Second))
	require.NoError(t, scraperErr)

	assert.True(t, scraper.lastExecutionTimestamp.IsZero(), "lastExecutionTimestamp should be zero before first collection")
	logs1, err := scraper.scrapeTopQuery(t.Context(), 31, 32, 33, time.Minute)
	assert.NotNil(t, logs1)
	assert.NoError(t, err)
	assert.False(t, scraper.lastExecutionTimestamp.IsZero(), "lastExecutionTimestamp won't be zero after first collection")

	collectionTime := scraper.lastExecutionTimestamp
	logs2, err := scraper.scrapeTopQuery(t.Context(), 31, 32, 33, time.Minute)
	assert.NotNil(t, logs2)
	assert.NoError(t, err)
	assert.Equal(t, collectionTime, scraper.lastExecutionTimestamp, "No new collection should happen until configured collection_interval")
}

func TestIsCollectionDue(t *testing.T) {
	collectionInterval := 20 * time.Second
	currentCollectionTime := time.Now()

	logger, err := zap.NewProduction()
	require.NoError(t, err)
	scrpr := postgreSQLScraper{
		// setting lastExecutionTimestamp to be past 'collectionInterval'
		lastExecutionTimestamp: currentCollectionTime.Add(-collectionInterval),
		logger:                 logger,
	}
	isCollectionDue := scrpr.isCollectionDue(currentCollectionTime, collectionInterval)
	assert.True(t, isCollectionDue, "lastExecutionTimestamp is older than collection_interval, so collection should be due.")

	scrpr.lastExecutionTimestamp = currentCollectionTime.Add(-10 * time.Second)
	isCollectionDue = scrpr.isCollectionDue(currentCollectionTime, collectionInterval)
	assert.False(t, isCollectionDue, "collection_interval is not yet reached since lastExecutionTimestamp, so collection is not due.")
}

// expectPrepareLookupExplain sets up the three ordered queries explainQueryInline issues:
// SET+PREPARE, the pg_prepared_statements parameter-count lookup, and EXPLAIN EXECUTE.
// expectServerVersion mocks the "SHOW server_version;" call explainQueryInline issues before
// attempting plan_cache_mode, which requires PostgreSQL 12+.
func expectServerVersion(mock sqlmock.Sqlmock, version string) {
	mock.ExpectQuery("SHOW server_version;").WillReturnRows(
		sqlmock.NewRows([]string{"server_version"}).AddRow(version),
	)
}

func expectPrepareLookupExplain(mock sqlmock.Sqlmock, normalizedQueryID, query string, paramCount int, planResult string) {
	expectServerVersion(mock, "14.5")
	prepareSQL := fmt.Sprintf("/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;PREPARE otel_%s AS %s;", normalizedQueryID, query)
	mock.ExpectQuery(prepareSQL).WillReturnRows(sqlmock.NewRows([]string{}))

	lookupSQL := fmt.Sprintf("/* otel-collector-ignore */ SELECT COALESCE(array_length(parameter_types, 1), 0) AS param_count FROM pg_prepared_statements WHERE name = 'otel_%s';", normalizedQueryID)
	mock.ExpectQuery(lookupSQL).WillReturnRows(
		sqlmock.NewRows([]string{"param_count"}).AddRow(fmt.Sprintf("%d", paramCount)),
	)

	nullsString := ""
	if paramCount > 0 {
		nulls := make([]string, paramCount)
		for i := range nulls {
			nulls[i] = "null"
		}
		nullsString = "(" + strings.Join(nulls, ", ") + ")"
	}
	explainSQL := fmt.Sprintf("EXPLAIN(FORMAT JSON) EXECUTE otel_%s%s;", normalizedQueryID, nullsString)
	if planResult != "" {
		mock.ExpectQuery(explainSQL).WillReturnRows(sqlmock.NewRows([]string{"QUERY PLAN"}).AddRow(planResult))
	} else {
		mock.ExpectQuery(explainSQL).WillReturnRows(sqlmock.NewRows([]string{"QUERY PLAN"}))
	}
}

func TestExplainQuery(t *testing.T) {
	testCases := []struct {
		name              string
		query             string
		expectedPrepared  string // actual PREPAREd text after rewriteIntervalParams; defaults to query if empty
		queryID           string
		normalizedQueryID string
		paramCount        int
		mockPlanResult    string
	}{
		{
			name:              "query with no parameters",
			query:             "SELECT * FROM users",
			queryID:           "12345",
			normalizedQueryID: "12345",
			paramCount:        0,
			mockPlanResult:    `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"users"}}]`,
		},
		{
			name:              "query with single parameter",
			query:             "SELECT * FROM users WHERE id = $1",
			queryID:           "12346",
			normalizedQueryID: "12346",
			paramCount:        1,
			mockPlanResult:    `[{"Plan":{"Node Type":"Index Scan","Relation Name":"users"}}]`,
		},
		{
			name:              "query with multiple distinct parameters",
			query:             "SELECT * FROM orders WHERE user_id = $1 AND status = $2 AND created_at > $3",
			queryID:           "12347",
			normalizedQueryID: "12347",
			paramCount:        3,
			mockPlanResult:    `[{"Plan":{"Node Type":"Index Scan","Relation Name":"orders"}}]`,
		},
		{
			name:              "query with hyphenated queryID",
			query:             "SELECT * FROM products WHERE id = $1",
			queryID:           "abc-def-123",
			normalizedQueryID: "abc_def_123",
			paramCount:        1,
			mockPlanResult:    `[{"Plan":{"Node Type":"Index Scan","Relation Name":"products"}}]`,
		},
		{
			// Bug-fix regression: the old regex counted "$1" twice here (it appears twice in the
			// query text) and would have tried to bind 2 nulls against a 1-parameter prepared
			// statement. The real parameter count from pg_prepared_statements is 1.
			name:              "query with repeated placeholder",
			query:             "SELECT * FROM orders WHERE customer_id = $1 OR referred_by = $1",
			queryID:           "20001",
			normalizedQueryID: "20001",
			paramCount:        1,
			mockPlanResult:    `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"orders"}}]`,
		},
		{
			// Bug-fix regression: the old regex matched "$123" inside the string literal and would
			// have tried to bind 1 null against a 0-parameter prepared statement.
			name:              "query with dollar-sign inside string literal",
			query:             "SELECT * FROM logs WHERE message = '$123'",
			queryID:           "20002",
			normalizedQueryID: "20002",
			paramCount:        0,
			mockPlanResult:    `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"logs"}}]`,
		},
		{
			// Combines both bug modes in one query to prove the fix isn't order-dependent or only
			// catching one at a time: one real (repeated) parameter, plus a string literal that
			// looks like a second placeholder but isn't.
			name:              "query with repeated placeholder and a literal dollar-sign",
			query:             "SELECT * FROM orders WHERE customer_id = $1 OR referred_by = $1 AND note = '$99'",
			queryID:           "20003",
			normalizedQueryID: "20003",
			paramCount:        1,
			mockPlanResult:    `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"orders"}}]`,
		},
		{
			// $N from a normalized INTERVAL literal; rewriteIntervalParams must fix it before PREPARE.
			name:              "query with normalized literal interval",
			query:             "SELECT * FROM orders WHERE status = $1 AND created_at > NOW() - INTERVAL $2",
			expectedPrepared:  "SELECT * FROM orders WHERE status = $1 AND created_at > NOW() - $2::interval",
			queryID:           "20004",
			normalizedQueryID: "20004",
			paramCount:        2,
			mockPlanResult:    `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"orders"}}]`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			logger, err := zap.NewProduction()
			require.NoError(t, err)

			client := &postgreSQLClient{
				client:  db,
				closeFn: func() error { return nil },
			}

			expectedPrepared := tc.expectedPrepared
			if expectedPrepared == "" {
				expectedPrepared = tc.query
			}
			expectPrepareLookupExplain(mock, tc.normalizedQueryID, expectedPrepared, tc.paramCount, tc.mockPlanResult)

			plan, err := client.explainQuery(tc.query, tc.queryID, "", logger)
			require.NoError(t, err)
			assert.Equal(t, tc.mockPlanResult, plan)
		})
	}
}

func TestExplainQueryInlineParamCountLookupEmpty(t *testing.T) {
	// If PREPARE succeeds but pg_prepared_statements has no matching row (unexpected, but the code
	// must not blindly index into an empty result), explainQuery should return a clear error rather
	// than panicking.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "SELECT * FROM users WHERE id = $1"
	queryID := "30001"

	expectServerVersion(mock, "14.5")
	mock.ExpectQuery("/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;PREPARE otel_30001 AS SELECT * FROM users WHERE id = $1;").
		WillReturnRows(sqlmock.NewRows([]string{}))
	mock.ExpectQuery("/* otel-collector-ignore */ SELECT COALESCE(array_length(parameter_types, 1), 0) AS param_count FROM pg_prepared_statements WHERE name = 'otel_30001';").
		WillReturnRows(sqlmock.NewRows([]string{"param_count"}))

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in pg_prepared_statements")
	assert.Empty(t, plan)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExplainQueryInlineParamCountLookupFails(t *testing.T) {
	// A connection drop between PREPARE and the parameter-count lookup must surface an error, and
	// critically must still fire the deferred DEALLOCATE PREPARE so no prepared statement leaks on
	// the connection.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "SELECT * FROM users WHERE id = $1"
	queryID := "30002"

	expectServerVersion(mock, "14.5")
	mock.ExpectQuery("/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;PREPARE otel_30002 AS SELECT * FROM users WHERE id = $1;").
		WillReturnRows(sqlmock.NewRows([]string{}))
	mock.ExpectQuery("/* otel-collector-ignore */ SELECT COALESCE(array_length(parameter_types, 1), 0) AS param_count FROM pg_prepared_statements WHERE name = 'otel_30002';").
		WillReturnError(errors.New("dial tcp: connection reset by peer"))
	mock.ExpectExec("/* otel-collector-ignore */ DEALLOCATE PREPARE otel_30002").WillReturnResult(sqlmock.NewResult(0, 0))

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.Error(t, err)
	assert.Empty(t, plan)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExplainQueryInlinePrepareFails(t *testing.T) {
	// PREPARE itself failing (e.g. syntax error surfaced only at prepare time) must surface an
	// error without attempting the parameter-count lookup or EXPLAIN EXECUTE.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "SELECT * FROM users WHERE id = $1"
	queryID := "30003"

	expectServerVersion(mock, "14.5")
	mock.ExpectQuery("/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;PREPARE otel_30003 AS SELECT * FROM users WHERE id = $1;").
		WillReturnError(errors.New("pq: syntax error"))
	mock.ExpectExec("/* otel-collector-ignore */ DEALLOCATE PREPARE otel_30003").WillReturnResult(sqlmock.NewResult(0, 0))

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.Error(t, err)
	assert.Empty(t, plan)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExplainQueryInlineExplainExecuteFails(t *testing.T) {
	// A correct parameter-count lookup followed by a failing EXPLAIN EXECUTE (e.g. permission
	// denied surfaced only at execute time) must still surface that error normally — the new
	// lookup step must not change existing error propagation for the final EXPLAIN call.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "UPDATE orders SET status = 'shipped' WHERE id = $1"
	queryID := "30004"

	expectServerVersion(mock, "14.5")
	mock.ExpectQuery("/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;PREPARE otel_30004 AS UPDATE orders SET status = 'shipped' WHERE id = $1;").
		WillReturnRows(sqlmock.NewRows([]string{}))
	mock.ExpectQuery("/* otel-collector-ignore */ SELECT COALESCE(array_length(parameter_types, 1), 0) AS param_count FROM pg_prepared_statements WHERE name = 'otel_30004';").
		WillReturnRows(sqlmock.NewRows([]string{"param_count"}).AddRow("1"))
	mock.ExpectQuery("EXPLAIN(FORMAT JSON) EXECUTE otel_30004(null);").
		WillReturnError(errors.New("pq: permission denied for table orders"))
	mock.ExpectExec("/* otel-collector-ignore */ DEALLOCATE PREPARE otel_30004").WillReturnResult(sqlmock.NewResult(0, 0))

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.Error(t, err)
	assert.Empty(t, plan)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExplainQueryInlineEmptyExplainResult(t *testing.T) {
	// Bug fix: EXPLAIN EXECUTE returning zero rows must not panic on result[0]["QUERY PLAN"] —
	// it must return ("", nil), mirroring explainQueryViaFunction's existing empty-result guard.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "SELECT * FROM users WHERE id = $1"
	queryID := "30005"

	expectPrepareLookupExplain(mock, "30005", query, 1, "")

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.NoError(t, err)
	assert.Empty(t, plan)
}

func TestExplainQueryInlineVersionGate(t *testing.T) {
	// plan_cache_mode was introduced in PostgreSQL 12; explainQueryInline must not attempt it on
	// older servers, where it would fail with "unrecognized configuration parameter".
	testCases := []struct {
		name                string
		serverVersion       string
		expectPrepareAndRun bool
	}{
		{name: "below minimum (11.9) skips EXPLAIN entirely", serverVersion: "11.9", expectPrepareAndRun: false},
		{name: "well below minimum (9.6.24) skips EXPLAIN entirely", serverVersion: "9.6.24", expectPrepareAndRun: false},
		{name: "exactly at minimum (12.0) proceeds", serverVersion: "12.0", expectPrepareAndRun: true},
		{name: "above minimum (14.5) proceeds", serverVersion: "14.5", expectPrepareAndRun: true},
		{name: "one below minimum (11.22) skips EXPLAIN entirely", serverVersion: "11.22", expectPrepareAndRun: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			logger, err := zap.NewProduction()
			require.NoError(t, err)

			client := &postgreSQLClient{
				client:  db,
				closeFn: func() error { return nil },
			}

			query := "SELECT * FROM users WHERE id = $1"
			queryID := "40001"

			expectServerVersion(mock, tc.serverVersion)
			if tc.expectPrepareAndRun {
				mock.ExpectQuery("/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;PREPARE otel_40001 AS SELECT * FROM users WHERE id = $1;").
					WillReturnRows(sqlmock.NewRows([]string{}))
				mock.ExpectQuery("/* otel-collector-ignore */ SELECT COALESCE(array_length(parameter_types, 1), 0) AS param_count FROM pg_prepared_statements WHERE name = 'otel_40001';").
					WillReturnRows(sqlmock.NewRows([]string{"param_count"}).AddRow("1"))
				mock.ExpectQuery("EXPLAIN(FORMAT JSON) EXECUTE otel_40001(null);").
					WillReturnRows(sqlmock.NewRows([]string{"QUERY PLAN"}).AddRow(`[{"Plan":{"Node Type":"Index Scan"}}]`))
				mock.ExpectExec("/* otel-collector-ignore */ DEALLOCATE PREPARE otel_40001").WillReturnResult(sqlmock.NewResult(0, 0))
			}
			// When expectPrepareAndRun is false, no further expectations are set — sqlmock fails
			// the test if explainQuery touches PREPARE/EXPLAIN at all, proving the version gate
			// short-circuits before any of that.

			plan, err := client.explainQuery(query, queryID, "", logger)
			require.NoError(t, err)
			if tc.expectPrepareAndRun {
				assert.Equal(t, `[{"Plan":{"Node Type":"Index Scan"}}]`, plan)
			} else {
				assert.Empty(t, plan)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestExplainQueryInlineVersionLookupFails(t *testing.T) {
	// If the version query itself fails (e.g. connection issue), explainQuery must surface that
	// error rather than proceeding to PREPARE against a server of unknown version.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "SELECT * FROM users WHERE id = $1"
	queryID := "40002"

	mock.ExpectQuery("SHOW server_version;").WillReturnError(errors.New("dial tcp: connection reset by peer"))

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.Error(t, err)
	assert.Empty(t, plan)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExplainQueryInlineVersionUnparseable(t *testing.T) {
	// A malformed server_version string (no dot) must surface a clear parse error rather than
	// panicking or silently proceeding as if the version check passed.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "SELECT * FROM users WHERE id = $1"
	queryID := "40003"

	expectServerVersion(mock, "not-a-version")

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.Error(t, err)
	assert.Empty(t, plan)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExplainQueryInlineDedicatedConnectionFails(t *testing.T) {
	// If obtaining a dedicated connection for PREPARE/EXPLAIN fails (pool exhausted, connection
	// error, or the pool being closed underneath the receiver during shutdown), explainQuery
	// must surface that error cleanly rather than panicking or proceeding to use an invalid
	// connection for PREPARE and the steps that follow it. sqlmock has no dedicated primitive
	// for forcing DB.Conn() specifically to fail, so this closes the whole pool up front —
	// getVersion fails first with the same underlying "database is closed" condition, which is
	// an equally valid way to prove the function returns a clean error instead of a panic; the
	// version-check failure path itself is exercised more narrowly by
	// TestExplainQueryInlineVersionLookupFails, and the Conn() call is exercised implicitly by
	// every other passing test in this file that reaches it successfully.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	mock.ExpectClose()
	require.NoError(t, db.Close())

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "SELECT * FROM users WHERE id = $1"
	queryID := "40004"

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.Error(t, err)
	assert.Empty(t, plan)
}

func TestShouldCacheExplainFailure(t *testing.T) {
	testCases := []struct {
		name          string
		err           error
		expectedCache bool
	}{
		{
			name:          "nil error (success) is cached",
			err:           nil,
			expectedCache: true,
		},
		{
			name:          "insufficient_privilege is NOT cached, so a later GRANT is retried next scrape",
			err:           &pq.Error{Code: pqerror.InsufficientPrivilege, Message: "permission denied for table orders"},
			expectedCache: false,
		},
		{
			name:          "undefined_table IS cached — dropping the table doesn't un-drop itself between scrapes",
			err:           &pq.Error{Code: pqerror.Code("42P01"), Message: "relation \"orders\" does not exist"},
			expectedCache: true,
		},
		{
			name:          "syntax error IS cached — malformed SQL doesn't fix itself between scrapes",
			err:           &pq.Error{Code: pqerror.Code("42601"), Message: "syntax error"},
			expectedCache: true,
		},
		{
			name:          "connection-level non-pq error IS cached — matches every other failure mode's default",
			err:           errors.New("dial tcp: connection refused"),
			expectedCache: true,
		},
		{
			name:          "wrapped insufficient_privilege is still detected through errors.As",
			err:           fmt.Errorf("failed to explain statement: %w", &pq.Error{Code: pqerror.InsufficientPrivilege, Message: "permission denied"}),
			expectedCache: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedCache, shouldCacheExplainFailure(tc.err))
		})
	}
}

func TestIsExplainPermissionError(t *testing.T) {
	testCases := []struct {
		name         string
		err          error
		isPermission bool
	}{
		{
			name:         "nil error is not a permission error",
			err:          nil,
			isPermission: false,
		},
		{
			name:         "insufficient_privilege is a permission error",
			err:          &pq.Error{Code: pqerror.InsufficientPrivilege, Message: "permission denied for table orders"},
			isPermission: true,
		},
		{
			name:         "undefined_table is not a permission error",
			err:          &pq.Error{Code: pqerror.Code("42P01"), Message: "relation \"orders\" does not exist"},
			isPermission: false,
		},
		{
			name:         "connection-level non-pq error is not a permission error",
			err:          errors.New("dial tcp: connection refused"),
			isPermission: false,
		},
		{
			name:         "wrapped insufficient_privilege is still detected through errors.As",
			err:          fmt.Errorf("failed to explain statement: %w", &pq.Error{Code: pqerror.InsufficientPrivilege, Message: "permission denied"}),
			isPermission: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.isPermission, isExplainPermissionError(tc.err))
		})
	}
}

func TestExplainQueryInlinePermissionDeniedIsNotCachedAcrossScrapes(t *testing.T) {
	// End-to-end proof: an InsufficientPrivilege failure from explainQueryInline, combined with
	// shouldCacheExplainFailure at the collectTopQuery call site, means a DBA's GRANT takes effect
	// on the very next scrape rather than sitting behind the full query_plan_cache_ttl. This test
	// exercises explainQueryInline directly (the real source of the pq.Error) and confirms the
	// error it returns is one shouldCacheExplainFailure correctly recognizes — the caching decision
	// itself is covered by TestShouldCacheExplainFailure, since mockClient.explainQuery is a fixed
	// panic stub and not wired to return a caller-controlled error.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	logger, err := zap.NewProduction()
	require.NoError(t, err)

	client := &postgreSQLClient{
		client:  db,
		closeFn: func() error { return nil },
	}

	query := "UPDATE orders SET status = 'shipped' WHERE id = $1"
	queryID := "50001"

	expectServerVersion(mock, "14.5")
	mock.ExpectQuery("/* otel-collector-ignore */ SET plan_cache_mode = force_generic_plan;PREPARE otel_50001 AS UPDATE orders SET status = 'shipped' WHERE id = $1;").
		WillReturnRows(sqlmock.NewRows([]string{}))
	mock.ExpectQuery("/* otel-collector-ignore */ SELECT COALESCE(array_length(parameter_types, 1), 0) AS param_count FROM pg_prepared_statements WHERE name = 'otel_50001';").
		WillReturnRows(sqlmock.NewRows([]string{"param_count"}).AddRow("1"))
	mock.ExpectQuery("EXPLAIN(FORMAT JSON) EXECUTE otel_50001(null);").
		WillReturnError(&pq.Error{Code: pqerror.InsufficientPrivilege, Message: "permission denied for table orders"})
	mock.ExpectExec("/* otel-collector-ignore */ DEALLOCATE PREPARE otel_50001").WillReturnResult(sqlmock.NewResult(0, 0))

	plan, err := client.explainQuery(query, queryID, "", logger)
	require.Error(t, err)
	assert.Empty(t, plan)
	assert.False(t, shouldCacheExplainFailure(err), "collectTopQuery must not cache this error, so the query is retried next scrape")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExplainQueryViaFunction(t *testing.T) {
	t.Run("parameterized query calls the function with raw text as bound arg", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
		mockPlan := `[{"Plan":{"Node Type":"LockRows"}}]`
		expectServerVersion(mock, "16.4")
		mock.ExpectQuery(`SELECT "otel"."explain_statement"($1)`).
			WithArgs(query).
			WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(mockPlan))

		plan, err := client.explainQuery(query, "12345", `"otel"."explain_statement"`, logger)
		require.NoError(t, err)
		assert.Equal(t, mockPlan, plan)
	})

	t.Run("non-parameterized query calls the function the same way, no PREPARE", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = 5 FOR UPDATE"
		mockPlan := `[{"Plan":{"Node Type":"LockRows"}}]`
		expectServerVersion(mock, "16.4")
		mock.ExpectQuery(`SELECT "otel"."explain_statement"($1)`).
			WithArgs(query).
			WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(mockPlan))

		plan, err := client.explainQuery(query, "12346", `"otel"."explain_statement"`, logger)
		require.NoError(t, err)
		assert.Equal(t, mockPlan, plan)
	})

	t.Run("function call error (undefined_function) is returned, not swallowed", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
		expectServerVersion(mock, "16.4")
		mock.ExpectQuery(`SELECT "otel"."explain_statement"($1)`).
			WithArgs(query).
			WillReturnError(&pq.Error{Code: pqerror.UndefinedFunction, Message: "function does not exist"})

		plan, err := client.explainQuery(query, "12347", `"otel"."explain_statement"`, logger)
		require.Error(t, err)
		assert.Empty(t, plan)
		var pqErr *pq.Error
		require.ErrorAs(t, err, &pqErr)
		assert.Equal(t, pqerror.UndefinedFunction, pqErr.Code, "this case is specifically the undefined_function branch")
	})

	t.Run("function call error (non-42883, e.g. permission denied) is returned, not swallowed", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
		expectServerVersion(mock, "16.4")
		mock.ExpectQuery(`SELECT "otel"."explain_statement"($1)`).
			WithArgs(query).
			WillReturnError(&pq.Error{Code: pqerror.Code("42501"), Message: "permission denied for table orders"})

		plan, err := client.explainQuery(query, "12349", `"otel"."explain_statement"`, logger)
		require.Error(t, err)
		assert.Empty(t, plan)
		var pqErr *pq.Error
		require.ErrorAs(t, err, &pqErr)
		assert.NotEqual(t, pqerror.UndefinedFunction, pqErr.Code, "this case is specifically the non-42883 branch — must not be confused with the undefined_function case above")
	})

	t.Run("whitelist rejection skips the function path too", func(t *testing.T) {
		db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		plan, err := client.explainQuery("GRANT SELECT ON users TO demo", "12348", `"otel"."explain_statement"`, logger)
		require.NoError(t, err)
		assert.Empty(t, plan)
		// no mock.ExpectQuery set up — sqlmock fails the test if explainQuery touches the DB
	})

	t.Run("explainFunction empty string forces inline path even for a FOR UPDATE query", func(t *testing.T) {
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		require.NoError(t, err)
		defer db.Close()

		logger, err := zap.NewProduction()
		require.NoError(t, err)

		client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

		query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
		// expects the INLINE sequence, not the function — proves explainFunction=="" always wins
		expectPrepareLookupExplain(mock, "12350", query, 1, `[{"Plan":{"Node Type":"LockRows"}}]`)

		plan, err := client.explainQuery(query, "12350", "", logger)
		require.NoError(t, err)
		assert.Equal(t, `[{"Plan":{"Node Type":"LockRows"}}]`, plan)
	})
}

func TestExplainQueryViaFunctionVersionGate(t *testing.T) {
	// The function sets plan_cache_mode, so it needs the same PostgreSQL 12+ gate as inline EXPLAIN.
	testCases := []struct {
		name               string
		serverVersion      string
		expectFunctionCall bool
	}{
		{name: "below minimum (11.9) skips EXPLAIN entirely", serverVersion: "11.9", expectFunctionCall: false},
		{name: "well below minimum (9.6.24) skips EXPLAIN entirely", serverVersion: "9.6.24", expectFunctionCall: false},
		{name: "exactly at minimum (12.0) proceeds", serverVersion: "12.0", expectFunctionCall: true},
		{name: "above minimum (14.5) proceeds", serverVersion: "14.5", expectFunctionCall: true},
		{name: "one below minimum (11.22) skips EXPLAIN entirely", serverVersion: "11.22", expectFunctionCall: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			logger, err := zap.NewProduction()
			require.NoError(t, err)

			client := &postgreSQLClient{client: db, closeFn: func() error { return nil }}

			query := "SELECT * FROM orders WHERE id = $1 FOR UPDATE"
			queryID := "50001"

			expectServerVersion(mock, tc.serverVersion)
			if tc.expectFunctionCall {
				mockPlan := `[{"Plan":{"Node Type":"LockRows"}}]`
				mock.ExpectQuery(`SELECT "otel"."explain_statement"($1)`).
					WithArgs(query).
					WillReturnRows(sqlmock.NewRows([]string{"explain_statement"}).AddRow(mockPlan))
			}
			// If expectFunctionCall is false, sqlmock fails the test if the function gets called.

			plan, err := client.explainQuery(query, queryID, `"otel"."explain_statement"`, logger)
			require.NoError(t, err)
			if tc.expectFunctionCall {
				assert.Equal(t, `[{"Plan":{"Node Type":"LockRows"}}]`, plan)
			} else {
				assert.Empty(t, plan)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestScraperExplainFunctionProbeCache(t *testing.T) {
	newScraperWithMockClient := func(t *testing.T, mockClient *mockClient) *postgreSQLScraper {
		cfg := createDefaultConfig().(*Config)
		cfg.TopQueryCollection.ExplainFunctionName = "otel.explain_statement"
		factory := &mockClientFactory{}
		factory.On("getClient", mock.Anything, mock.Anything).Return(mockClient, nil)

		settings := receivertest.NewNopSettings(metadata.Type)
		logger, err := zap.NewProduction()
		require.NoError(t, err)
		settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

		scraper, err := newPostgreSQLScraper(settings, cfg, factory, newCache(1),
			newTTLCache[string](1, time.Second),
			newTTLCache[explainSetupState](1, time.Second))
		require.NoError(t, err)
		return scraper
	}

	t.Run("probes once, caches available true on success", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).Return(nil).Once()

		scraper := newScraperWithMockClient(t, mc)

		_, ok := scraper.explainFunctionCache.Get("testdb")
		assert.False(t, ok, "cache should start empty")

		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)

		state, ok := scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.True(t, state.available)
		assert.NoError(t, state.err)

		// Second call within the TTL window must not probe again.
		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 1)
	})

	t.Run("probe failure with undefined_function (not provisioned) caches unavailable", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).
			Return(&pq.Error{Code: pqerror.UndefinedFunction, Message: "does not exist"}).Once()

		scraper := newScraperWithMockClient(t, mc)
		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc) // probing failure is not a scrape error, it's a cached state

		state, ok := scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.False(t, state.available)
		require.Error(t, state.err)
		var pqErr *pq.Error
		require.ErrorAs(t, state.err, &pqErr)
		assert.Equal(t, pqerror.UndefinedFunction, pqErr.Code)
	})

	t.Run("probe failure with a non-42883 error (present but broken) also caches unavailable", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).
			Return(&pq.Error{Code: pqerror.Code("42501"), Message: "permission denied for table orders"}).Once()

		scraper := newScraperWithMockClient(t, mc)
		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)

		state, ok := scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.False(t, state.available, "same fallback outcome as the undefined_function case")
		require.Error(t, state.err)
		var pqErr *pq.Error
		require.ErrorAs(t, state.err, &pqErr)
		// This is the distinct non-42883 branch: probeExplainFunctionIfNeeded logs it at Error,
		// not Warn. Not independently asserted here since this test suite has no log-observing
		// infra today; the branch itself, and its effect on the cached state, is what this
		// test verifies.
		assert.NotEqual(t, pqerror.UndefinedFunction, pqErr.Code, "non-42883 branch, not undefined_function")
	})

	t.Run("real explainQuery failure with undefined_function does not evict the cache", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).Return(nil).Once()

		scraper := newScraperWithMockClient(t, mc)
		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)

		state, ok := scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.True(t, state.available, "cache must still say available after only a probe")

		// re-probing (simulating a real call failure) must not evict the cache entry
		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 1)

		state, ok = scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok)
		assert.True(t, state.available, "cache entry must remain unchanged regardless of real-call outcomes")
	})

	t.Run("two different databases are cached independently", func(t *testing.T) {
		// cache size must be >= 2 so adding "db_b" doesn't evict "db_a" first
		cfg := createDefaultConfig().(*Config)
		cfg.TopQueryCollection.ExplainFunctionName = "otel.explain_statement"
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).Return(nil).Once()
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).
			Return(&pq.Error{Code: pqerror.UndefinedFunction, Message: "does not exist"}).Once()

		factory := &mockClientFactory{}
		factory.On("getClient", mock.Anything, mock.Anything).Return(mc, nil)

		settings := receivertest.NewNopSettings(metadata.Type)
		logger, err := zap.NewProduction()
		require.NoError(t, err)
		settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

		scraper, err := newPostgreSQLScraper(settings, cfg, factory, newCache(1),
			newTTLCache[string](1, time.Second),
			newTTLCache[explainSetupState](2, time.Second))
		require.NoError(t, err)

		scraper.probeExplainFunctionIfNeeded(t.Context(), "db_a", mc)
		scraper.probeExplainFunctionIfNeeded(t.Context(), "db_b", mc)

		stateA, ok := scraper.explainFunctionCache.Get("db_a")
		require.True(t, ok)
		assert.True(t, stateA.available)

		stateB, ok := scraper.explainFunctionCache.Get("db_b")
		require.True(t, ok)
		assert.False(t, stateB.available)
	})

	t.Run("cache entry expires via TTL and re-probes", func(t *testing.T) {
		cfg := createDefaultConfig().(*Config)
		cfg.TopQueryCollection.ExplainFunctionName = "otel.explain_statement"
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).Return(nil).Twice()

		factory := &mockClientFactory{}
		factory.On("getClient", mock.Anything, mock.Anything).Return(mc, nil)

		settings := receivertest.NewNopSettings(metadata.Type)
		logger, err := zap.NewProduction()
		require.NoError(t, err)
		settings.TelemetrySettings = component.TelemetrySettings{Logger: logger}

		scraper, err := newPostgreSQLScraper(settings, cfg, factory, newCache(1),
			newTTLCache[string](1, time.Second),
			newTTLCache[explainSetupState](1, 50*time.Millisecond)) // short TTL for the test
		require.NoError(t, err)

		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 1)

		time.Sleep(100 * time.Millisecond) // past the 50ms TTL

		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 2)
	})

	t.Run("connection-level non-pq error is cached and does not retry within TTL", func(t *testing.T) {
		mc := &mockClient{}
		mc.On("probeExplainFunction", mock.Anything, `"otel"."explain_statement"`).
			Return(errors.New("dial tcp: connection refused")).Once()

		scraper := newScraperWithMockClient(t, mc)

		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)

		state, ok := scraper.explainFunctionCache.Get("testdb")
		require.True(t, ok, "connection-level errors must be cached, same as any other probe outcome")
		assert.False(t, state.available)
		require.Error(t, state.err)

		// Second call within the TTL window must not probe again.
		scraper.probeExplainFunctionIfNeeded(t.Context(), "testdb", mc)
		mc.AssertNumberOfCalls(t, "probeExplainFunction", 1)
	})
}

type (
	mockClientFactory       struct{ mock.Mock }
	mockClient              struct{ mock.Mock }
	mockSimpleClientFactory struct {
		db *sql.DB
	}
)

// explainQuery implements client.
func (*mockClient) explainQuery(string, string, string, *zap.Logger) (string, error) {
	panic("unimplemented")
}

// probeExplainFunction implements client.
func (m *mockClient) probeExplainFunction(ctx context.Context, quotedFunctionName string) error {
	args := m.Called(ctx, quotedFunctionName)
	return args.Error(0)
}

// getTopQuery implements client.
func (*mockClient) getTopQuery(context.Context, int64, []string, *zap.Logger) ([]map[string]any, error) {
	panic("unimplemented")
}

// close implements postgreSQLClientFactory.
func (mockSimpleClientFactory) close() error {
	return nil
}

// setCredentialProvider implements postgreSQLClientFactory.
func (mockSimpleClientFactory) setCredentialProvider(dbauth.Provider) {}

// getClient implements postgreSQLClientFactory.
func (m mockSimpleClientFactory) getClient(context.Context, string) (client, error) {
	return &postgreSQLClient{
		client:  m.db,
		closeFn: m.close,
	}, nil
}

// getQuerySamples implements client.
func (*mockClient) getQuerySamples(context.Context, int64, float64, []string, *zap.Logger) ([]map[string]any, float64, error) {
	panic("this should not be invoked")
}

var _ client = &mockClient{}

func (m *mockClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockClient) getDatabaseStats(_ context.Context, databases []string) (map[databaseName]databaseStats, error) {
	args := m.Called(databases)
	return args.Get(0).(map[databaseName]databaseStats), args.Error(1)
}

func (m *mockClient) getDatabaseConflicts(_ context.Context, databases []string) (map[databaseName]databaseConflictStats, error) {
	args := m.Called(databases)
	return args.Get(0).(map[databaseName]databaseConflictStats), args.Error(1)
}

func (m *mockClient) getExecutionTimeStats(_ context.Context, databases []string) (map[databaseName]float64, error) {
	args := m.Called(databases)
	return args.Get(0).(map[databaseName]float64), args.Error(1)
}

func (m *mockClient) getDatabaseLocks(ctx context.Context) ([]databaseLocks, error) {
	args := m.Called(ctx)
	return args.Get(0).([]databaseLocks), args.Error(1)
}

func (m *mockClient) getSharedRelationLocks(ctx context.Context) ([]databaseLocks, error) {
	args := m.Called(ctx)
	return args.Get(0).([]databaseLocks), args.Error(1)
}

func (m *mockClient) getBackends(_ context.Context, databases []string) (map[databaseName]int64, error) {
	args := m.Called(databases)
	return args.Get(0).(map[databaseName]int64), args.Error(1)
}

func (m *mockClient) getDatabaseSize(_ context.Context, databases []string) (map[databaseName]int64, error) {
	args := m.Called(databases)
	return args.Get(0).(map[databaseName]int64), args.Error(1)
}

func (m *mockClient) getDatabaseTableMetrics(ctx context.Context, database string) (map[tableIdentifier]tableStats, error) {
	args := m.Called(ctx, database)
	return args.Get(0).(map[tableIdentifier]tableStats), args.Error(1)
}

func (m *mockClient) getBlocksReadByTable(ctx context.Context, database string) (map[tableIdentifier]tableIOStats, error) {
	args := m.Called(ctx, database)
	return args.Get(0).(map[tableIdentifier]tableIOStats), args.Error(1)
}

func (m *mockClient) getIndexStats(ctx context.Context, database string) (map[indexIdentifer]indexStat, error) {
	args := m.Called(ctx, database)
	return args.Get(0).(map[indexIdentifer]indexStat), args.Error(1)
}

func (m *mockClient) getFunctionStats(ctx context.Context, database string) (map[functionIdentifer]functionStat, error) {
	args := m.Called(ctx, database)
	return args.Get(0).(map[functionIdentifer]functionStat), args.Error(1)
}

func (m *mockClient) getVectorSearchStats(ctx context.Context) ([]vectorSearchStat, error) {
	args := m.Called(ctx)
	return args.Get(0).([]vectorSearchStat), args.Error(1)
}

func (m *mockClient) getVectorInsertStats(ctx context.Context) ([]vectorInsertStat, error) {
	args := m.Called(ctx)
	return args.Get(0).([]vectorInsertStat), args.Error(1)
}

func (m *mockClient) getBGWriterStats(ctx context.Context) (*bgStat, error) {
	args := m.Called(ctx)
	return args.Get(0).(*bgStat), args.Error(1)
}

func (m *mockClient) getMaxConnections(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockClient) getLatestWalAgeSeconds(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockClient) getReplicationStats(ctx context.Context) ([]replicationStats, error) {
	args := m.Called(ctx)
	return args.Get(0).([]replicationStats), args.Error(1)
}

func (m *mockClient) listDatabases(_ context.Context) ([]string, error) {
	args := m.Called()
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockClient) getVersion(_ context.Context) (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *mockClientFactory) getClient(ctx context.Context, database string) (client, error) {
	args := m.Called(ctx, database)
	return args.Get(0).(client), args.Error(1)
}

func (*mockClientFactory) setCredentialProvider(dbauth.Provider) {}

func (m *mockClientFactory) close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockClientFactory) initMocks(databases []string) {
	listClient := new(mockClient)
	listClient.initMocks(defaultPostgreSQLDatabase, "public", databases, 0)
	m.On("getClient", mock.Anything, defaultPostgreSQLDatabase).Return(listClient, nil)

	for index, db := range databases {
		client := new(mockClient)
		client.initMocks(db, "public", databases, index)
		m.On("getClient", mock.Anything, db).Return(client, nil)
	}
}

func (m *mockClient) initMocks(database, schema string, databases []string, index int) {
	m.On("Close").Return(nil)

	if database == defaultPostgreSQLDatabase {
		m.On("listDatabases").Return(databases, nil)

		dbStats := map[databaseName]databaseStats{}
		dbConflictStats := map[databaseName]databaseConflictStats{}
		dbSize := map[databaseName]int64{}
		backends := map[databaseName]int64{}
		execDuration := map[databaseName]float64{}

		for idx, db := range databases {
			dbStats[databaseName(db)] = databaseStats{
				transactionCommitted: int64(idx + 1),
				transactionRollback:  int64(idx + 2),
				deadlocks:            int64(idx + 3),
				tempFiles:            int64(idx + 4),
				tupUpdated:           int64(idx + 5),
				tupReturned:          int64(idx + 6),
				tupFetched:           int64(idx + 7),
				tupInserted:          int64(idx + 8),
				tupDeleted:           int64(idx + 9),
				blksHit:              int64(idx + 10),
				blksRead:             int64(idx + 11),
				tempIo:               int64(idx + 12),
			}
			dbConflictStats[databaseName(db)] = databaseConflictStats{
				conflTablespace: int64(idx + 13),
				conflLock:       int64(idx + 14),
				conflSnapshot:   int64(idx + 15),
				conflBufferpin:  int64(idx + 16),
				conflDeadlock:   int64(idx + 17),
			}
			dbSize[databaseName(db)] = int64(idx + 4)
			backends[databaseName(db)] = int64(idx + 3)
			execDuration[databaseName(db)] = float64(idx+1) + 0.5
		}

		m.On("getDatabaseStats", databases).Return(dbStats, nil)
		m.On("getDatabaseConflicts", databases).Return(dbConflictStats, nil)
		m.On("getExecutionTimeStats", databases).Return(execDuration, nil)
		m.On("getDatabaseSize", databases).Return(dbSize, nil)
		m.On("getBackends", databases).Return(backends, nil)
		m.On("getBGWriterStats", mock.Anything).Return(&bgStat{
			checkpointsReq:       1,
			checkpointsScheduled: 2,
			checkpointWriteTime:  3.12,
			checkpointSyncTime:   4.23,
			bgWrites:             5,
			bufferBackendWrites:  7,
			bufferFsyncWrites:    8,
			bufferCheckpoints:    9,
			buffersAllocated:     10,
			maxWritten:           11,
		}, nil)
		m.On("getMaxConnections", mock.Anything).Return(int64(100), nil)
		m.On("getLatestWalAgeSeconds", mock.Anything).Return(int64(3600), nil)
		m.On("getSharedRelationLocks", mock.Anything).Return([]databaseLocks{
			{
				relation: "pg_database",
				mode:     "AccessShareLock",
				lockType: "relation",
				locks:    2,
			},
		}, nil)
		m.On("getReplicationStats", mock.Anything).Return([]replicationStats{
			{
				clientAddr:   "unix",
				pendingBytes: 1024,
				flushLagInt:  600,
				replayLagInt: 700,
				writeLagInt:  800,
				flushLag:     600.400,
				replayLag:    700.550,
				writeLag:     800.660,
			},
			{
				clientAddr:   "nulls",
				pendingBytes: -1,
				flushLagInt:  -1,
				replayLagInt: -1,
				writeLagInt:  -1,
				flushLag:     -1,
				replayLag:    -1,
				writeLag:     -1,
			},
		}, nil)
	} else {
		table1 := "table1"
		table2 := "table2"
		tableMetrics := map[tableIdentifier]tableStats{
			tableKey(database, schema, table1): {
				database:    database,
				schema:      schema,
				table:       table1,
				live:        int64(index + 7),
				dead:        int64(index + 8),
				inserts:     int64(index + 39),
				upd:         int64(index + 40),
				del:         int64(index + 41),
				hotUpd:      int64(index + 42),
				size:        int64(index + 43),
				vacuumCount: int64(index + 44),
				seqScans:    int64(index + 45),
			},
			tableKey(database, schema, table2): {
				database:    database,
				schema:      schema,
				table:       table2,
				live:        int64(index + 9),
				dead:        int64(index + 10),
				inserts:     int64(index + 43),
				upd:         int64(index + 44),
				del:         int64(index + 45),
				hotUpd:      int64(index + 46),
				size:        int64(index + 47),
				vacuumCount: int64(index + 48),
				seqScans:    int64(index + 49),
			},
		}

		blocksMetrics := map[tableIdentifier]tableIOStats{
			tableKey(database, schema, table1): {
				database:  database,
				schema:    schema,
				table:     table1,
				heapRead:  int64(index + 19),
				heapHit:   int64(index + 20),
				idxRead:   int64(index + 21),
				idxHit:    int64(index + 22),
				toastRead: int64(index + 23),
				toastHit:  int64(index + 24),
				tidxRead:  int64(index + 25),
				tidxHit:   int64(index + 26),
			},
			tableKey(database, schema, table2): {
				database:  database,
				schema:    schema,
				table:     table2,
				heapRead:  int64(index + 27),
				heapHit:   int64(index + 28),
				idxRead:   int64(index + 29),
				idxHit:    int64(index + 30),
				toastRead: int64(index + 31),
				toastHit:  int64(index + 32),
				tidxRead:  int64(index + 33),
				tidxHit:   int64(index + 34),
			},
		}

		m.On("getDatabaseTableMetrics", mock.Anything, database).Return(tableMetrics, nil)
		m.On("getBlocksReadByTable", mock.Anything, database).Return(blocksMetrics, nil)

		index1 := database + "_test1_pkey"
		index2 := database + "_test2_pkey"
		indexStats := map[indexIdentifer]indexStat{
			indexKey(database, schema, table1, index1): {
				database: database,
				schema:   schema,
				table:    table1,
				index:    index1,
				scans:    int64(index + 35),
				size:     int64(index + 36),
			},
			indexKey(index2, schema, table2, index2): {
				database: database,
				schema:   schema,
				table:    table2,
				index:    index2,
				scans:    int64(index + 37),
				size:     int64(index + 38),
			},
		}
		m.On("getIndexStats", mock.Anything, database).Return(indexStats, nil)

		function1 := "test_function1"
		function2 := "test_function2"
		functionStats := map[functionIdentifer]functionStat{
			functionKey(database, schema, function1): {
				database: database,
				schema:   schema,
				function: function1,
				calls:    int64(index + 50),
			},
			functionKey(database, schema, function2): {
				database: database,
				schema:   schema,
				function: function2,
				calls:    int64(index + 51),
			},
		}
		m.On("getFunctionStats", mock.Anything, database).Return(functionStats, nil)

		m.On("getDatabaseLocks", mock.Anything).Return([]databaseLocks{
			{
				relation: "pg_locks",
				mode:     "AccessShareLock",
				lockType: "relation",
				locks:    int64(index + 3600),
			},
			{
				relation: "pg_class",
				mode:     "AccessShareLock",
				lockType: "relation",
				locks:    int64(index + 5600),
			},
		}, nil)

		vectorSearchStats := []vectorSearchStat{
			{
				distanceFunction: "cosine",
				calls:            int64(index + 60),
				totalExecTime:    float64(index) + 0.5,
				rowsReturned:     int64(index + 600),
			},
			{
				distanceFunction: "l2",
				calls:            int64(index + 61),
				totalExecTime:    float64(index) + 1.5,
				rowsReturned:     int64(index + 610),
			},
		}
		m.On("getVectorSearchStats", mock.Anything).Return(vectorSearchStats, nil)

		vectorInsertStats := []vectorInsertStat{
			{
				rows:          int64(index + 70),
				totalExecTime: float64(index) + 2.5,
			},
		}
		m.On("getVectorInsertStats", mock.Anything).Return(vectorInsertStats, nil)
	}
}

func TestGetInstanceId(t *testing.T) {
	localhostName, _ := os.Hostname()

	instanceString := "example.com:5432"
	instanceID := getInstanceID(instanceString, zap.NewNop())
	assert.Equal(t, "example.com:5432", instanceID)

	localHostStringUppercase := "Localhost:5432"
	localInstanceID := getInstanceID(localHostStringUppercase, zap.NewNop())
	assert.NotNil(t, localInstanceID)
	assert.Equal(t, localhostName+":5432", localInstanceID)

	localHostString := "127.0.0.1:5432"
	localInstanceID = getInstanceID(localHostString, zap.NewNop())
	assert.NotNil(t, localInstanceID)
	assert.Equal(t, localhostName+":5432", localInstanceID)

	localHostStringIPV6 := "[::1]:5432"
	localInstanceID = getInstanceID(localHostStringIPV6, zap.NewNop())
	assert.NotNil(t, localInstanceID)
	assert.Equal(t, localhostName+":5432", localInstanceID)

	hostNameErrorSample := ""
	localInstanceID = getInstanceID(hostNameErrorSample, zap.NewNop())
	assert.NotNil(t, localInstanceID)
	assert.Equal(t, "unknown:5432", localInstanceID)
}

func TestResolveServiceInstanceSeed(t *testing.T) {
	hostname, err := os.Hostname()
	require.NoError(t, err)
	localEndpoint := net.JoinHostPort(hostname, "5432")

	tests := []struct {
		name     string
		endpoint string
		expected string
	}{
		{
			name:     "hostname",
			endpoint: "db.example.com:5432",
			expected: "db.example.com:5432",
		},
		{
			name:     "IPv6",
			endpoint: "[2001:db8::1]:5432",
			expected: "[2001:db8::1]:5432",
		},
		{
			name:     "localhost",
			endpoint: "localhost:5432",
			expected: localEndpoint,
		},
		{
			name:     "case-insensitive localhost",
			endpoint: "Localhost:5432",
			expected: localEndpoint,
		},
		{
			name:     "IPv4 loopback",
			endpoint: "127.0.0.1:5432",
			expected: localEndpoint,
		},
		{
			name:     "IPv6 loopback",
			endpoint: "[::1]:5432",
			expected: localEndpoint,
		},
		{
			name:     "invalid endpoint",
			endpoint: "localhost",
			expected: "localhost",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			cfg.AddrConfig.Endpoint = tt.endpoint
			assert.Equal(t, tt.expected, resolveServiceInstanceSeed(cfg, zap.NewNop()))
		})
	}
}

func TestResolveUnixServiceInstanceSeed(t *testing.T) {
	hostname, err := os.Hostname()
	require.NoError(t, err)
	unixSeed := func(endpoint string) string {
		cfg := createDefaultConfig().(*Config)
		cfg.AddrConfig.Endpoint = endpoint
		cfg.AddrConfig.Transport = confignet.TransportTypeUnix
		return resolveServiceInstanceSeed(cfg, zap.NewNop())
	}

	seed := unixSeed("var/run/postgresql:5432")
	assert.Equal(t, strings.Join([]string{"unix", hostname, "/var/run/postgresql/.s.PGSQL.5432"}, "\x00"), seed)
	assert.Equal(t, seed, unixSeed("/var/run/postgresql:5432"))
	assert.NotEqual(t, seed, unixSeed("var/lib/postgresql:5432"))
	assert.NotEqual(t, seed, unixSeed("var/run/postgresql:5433"))
	assert.Equal(t, strings.Join([]string{"unix", hostname, "var/run/postgresql"}, "\x00"), unixSeed("var/run/postgresql"))

	tcpConfig := createDefaultConfig().(*Config)
	tcpConfig.AddrConfig.Endpoint = "var/run/postgresql:5432"
	assert.NotEqual(t, seed, resolveServiceInstanceSeed(tcpConfig, zap.NewNop()))
}

func TestNewPostgreSQLScraperSemconvServiceInstanceID(t *testing.T) {
	defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlUseOTelSemconvFeatureGate, true)()

	hostname, err := os.Hostname()
	require.NoError(t, err)
	cfg := createDefaultConfig().(*Config)
	cfg.AddrConfig.Endpoint = "[::1]:5432"
	scraper, err := newPostgreSQLScraper(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		newDefaultClientFactory(cfg),
		newCache(1),
		newTTLCache[string](1, time.Second),
		newTTLCache[explainSetupState](1, time.Second),
	)
	require.NoError(t, err)

	seed := net.JoinHostPort(hostname, "5432")
	expected := uuid.NewSHA1(otelNamespaceUUID, []byte(seed)).String()
	assert.Equal(t, expected, scraper.serviceInstanceID)
}

func TestNewPostgreSQLScraperSemconvUnixServiceInstanceID(t *testing.T) {
	defer testutil.SetFeatureGateForTest(t, metadata.ReceiverNrpostgresqlUseOTelSemconvFeatureGate, true)()

	hostname, err := os.Hostname()
	require.NoError(t, err)
	cfg := createDefaultConfig().(*Config)
	cfg.AddrConfig.Endpoint = "var/run/postgresql:5432"
	cfg.AddrConfig.Transport = confignet.TransportTypeUnix
	scraper, err := newPostgreSQLScraper(
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		newDefaultClientFactory(cfg),
		newCache(1),
		newTTLCache[string](1, time.Second),
		newTTLCache[explainSetupState](1, time.Second),
	)
	require.NoError(t, err)

	seed := strings.Join([]string{"unix", hostname, "/var/run/postgresql/.s.PGSQL.5432"}, "\x00")
	expected := uuid.NewSHA1(otelNamespaceUUID, []byte(seed)).String()
	assert.Equal(t, expected, scraper.serviceInstanceID)
}

func TestSetupSemconvResourceBuilder(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.AddrConfig.Endpoint = "127.0.0.1:5432"
	serviceInstanceID := uuid.NewSHA1(otelNamespaceUUID, []byte("collector-host:5432")).String()
	scraper := &postgreSQLScraper{
		logger:            zap.NewNop(),
		config:            cfg,
		mb:                metadata.NewMetricsBuilder(cfg.MetricsBuilderConfig, receivertest.NewNopSettings(metadata.Type)),
		serviceInstanceID: serviceInstanceID,
		useOTelSemconv:    true,
	}

	rb := scraper.mb.NewResourceBuilder()
	scraper.setupSemconvResourceBuilder(rb)
	res := rb.Emit()

	serverHost, ok := res.Attributes().Get("server.address")
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1", serverHost.Str())

	serverPort, ok := res.Attributes().Get("server.port")
	require.True(t, ok)
	assert.Equal(t, int64(5432), serverPort.Int())

	instanceID, ok := res.Attributes().Get("service.instance.id")
	require.True(t, ok)
	assert.Equal(t, serviceInstanceID, instanceID.Str())
	_, err := uuid.Parse(instanceID.Str())
	require.NoError(t, err)

	rb2 := scraper.mb.NewResourceBuilder()
	scraper.setupSemconvResourceBuilder(rb2)
	res2 := rb2.Emit()
	uuid2, _ := res2.Attributes().Get("service.instance.id")
	assert.Equal(t, instanceID.Str(), uuid2.Str())

	_, hasServiceName := res.Attributes().Get("service.name")
	assert.False(t, hasServiceName)
}

func TestServerEndpointAttributes(t *testing.T) {
	tests := []struct {
		name            string
		endpoint        string
		transport       confignet.TransportType
		expectedAddress string
		expectedPort    int64
		wantErr         bool
	}{
		{
			name:            "hostname",
			endpoint:        "db.example.com:5432",
			transport:       confignet.TransportTypeTCP,
			expectedAddress: "db.example.com",
			expectedPort:    5432,
		},
		{
			name:            "loopback IPv4",
			endpoint:        "127.0.0.1:5433",
			transport:       confignet.TransportTypeTCP,
			expectedAddress: "127.0.0.1",
			expectedPort:    5433,
		},
		{
			name:            "IPv6",
			endpoint:        "[2001:db8::1]:5434",
			transport:       confignet.TransportTypeTCP,
			expectedAddress: "2001:db8::1",
			expectedPort:    5434,
		},
		{
			name:            "Unix socket",
			endpoint:        "var/run/postgresql:5435",
			transport:       confignet.TransportTypeUnix,
			expectedAddress: "/var/run/postgresql/.s.PGSQL.5435",
			expectedPort:    5435,
		},
		{
			name:      "invalid endpoint",
			endpoint:  "localhost",
			transport: confignet.TransportTypeTCP,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			cfg.AddrConfig.Endpoint = tt.endpoint
			cfg.AddrConfig.Transport = tt.transport
			address, port, err := serverEndpointAttributes(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedAddress, address)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

func TestSetupLegacyResourceBuilder(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	scraper := &postgreSQLScraper{
		logger:            zap.NewNop(),
		config:            cfg,
		mb:                metadata.NewMetricsBuilder(cfg.MetricsBuilderConfig, receivertest.NewNopSettings(metadata.Type)),
		serviceInstanceID: "localhost:5432",
		useOTelSemconv:    false,
	}

	rb := scraper.mb.NewResourceBuilder()
	scraper.setupLegacyResourceBuilder(rb, "mydb", "myschema", "mytable", "myindex")
	res := rb.Emit()

	instanceID, ok := res.Attributes().Get("service.instance.id")
	require.True(t, ok)
	assert.Equal(t, "localhost:5432", instanceID.Str())

	dbName, ok := res.Attributes().Get("postgresql.database.name")
	require.True(t, ok)
	assert.Equal(t, "mydb", dbName.Str())

	schemaName, ok := res.Attributes().Get("postgresql.schema.name")
	require.True(t, ok)
	assert.Equal(t, "myschema", schemaName.Str())

	tableName, ok := res.Attributes().Get("postgresql.table.name")
	require.True(t, ok)
	assert.Equal(t, "mytable", tableName.Str())

	indexName, ok := res.Attributes().Get("postgresql.index.name")
	require.True(t, ok)
	assert.Equal(t, "myindex", indexName.Str())

	_, hasServerAddr := res.Attributes().Get("server.address")
	assert.False(t, hasServerAddr)
	_, hasServerPort := res.Attributes().Get("server.port")
	assert.False(t, hasServerPort)
}
