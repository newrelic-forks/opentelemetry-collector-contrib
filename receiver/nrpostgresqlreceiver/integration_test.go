// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package nrpostgresqlreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrpostgresqlreceiver"

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

const postgresqlPort = "5432/tcp"

// setupContainer starts a stock postgres container. The fork deliberately avoids
// the base internal/coreinternal/scraperinttest harness (see NR-596383); this uses
// testcontainers-go directly, mirroring receiver/nrsqlserverreceiver/integration_test.go.
func setupContainer(t *testing.T) testcontainers.Container {
	return setupContainerWith(t, "postgres:16-alpine", nil)
}

// setupContainerWith is setupContainer with the image and init files overridable,
// for tests that need a specific PostgreSQL version or seed data.
func setupContainerWith(t *testing.T, image string, initFiles []testcontainers.ContainerFile) testcontainers.Container {
	ctx := t.Context()

	// With init files, postgres restarts once its init scripts finish, logging
	// "ready to accept connections" a second time — wait for that occurrence
	// (see receiver/postgresqlreceiver/integration_test.go for the same pattern),
	// otherwise a query can race the init scripts on the first, premature startup.
	var waitStrategy wait.Strategy = wait.ForListeningPort(postgresqlPort).WithStartupTimeout(2 * time.Minute)
	if len(initFiles) > 0 {
		waitStrategy = wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(2 * time.Minute)
	}

	ci, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: image,
				Env: map[string]string{
					"POSTGRES_USER":     "otel",
					"POSTGRES_PASSWORD": "otel",
					"POSTGRES_DB":       "otel",
				},
				ExposedPorts: []string{postgresqlPort},
				Files:        initFiles,
				WaitingFor:   waitStrategy,
			},
			Started: true,
		},
	)
	require.NoError(t, err)
	return ci
}

// TestIntegrationScrapeMetrics stands up a real PostgreSQL instance, runs the
// nrpostgresql receiver against it, and asserts that metrics are collected.
func TestIntegrationScrapeMetrics(t *testing.T) {
	ci := setupContainer(t)
	defer testcontainers.CleanupContainer(t, ci)

	ctx := t.Context()
	host, err := ci.Host(ctx)
	require.NoError(t, err)
	mappedPort, err := ci.MappedPort(ctx, postgresqlPort)
	require.NoError(t, err)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.ControllerConfig.CollectionInterval = time.Second
	cfg.AddrConfig.Endpoint = net.JoinHostPort(host, mappedPort.Port())
	cfg.Username = "otel"
	cfg.Password = "otel"
	cfg.Databases = []string{"otel"}
	cfg.ClientConfig.Insecure = true

	sink := new(consumertest.MetricsSink)
	recv, err := factory.CreateMetrics(ctx, receivertest.NewNopSettings(factory.Type()), cfg, sink)
	require.NoError(t, err)

	require.NoError(t, recv.Start(ctx, componenttest.NewNopHost()))
	defer func() { require.NoError(t, recv.Shutdown(ctx)) }()

	require.Eventually(t, func() bool {
		return sink.DataPointCount() > 0
	}, 30*time.Second, time.Second, "expected the receiver to collect at least one metric data point")

	assert.NotEmpty(t, sink.AllMetrics())
}

// TestTableCountMatchesTableMetrics checks getTableCount equals len(getDatabaseTableMetrics) on a real instance.
func TestTableCountMatchesTableMetrics(t *testing.T) {
	t.Run("pre14", tableCountEquivalenceTest("postgres:13-alpine"))
	t.Run("post14", tableCountEquivalenceTest("postgres:16-alpine"))
}

func tableCountEquivalenceTest(image string) func(*testing.T) {
	return func(t *testing.T) {
		initFile := testcontainers.ContainerFile{
			HostFilePath:      filepath.Join("testdata", "integration", "03-table-count-init.sql"),
			ContainerFilePath: "/docker-entrypoint-initdb.d/01-init.sql",
			FileMode:          0o644,
		}
		ci := setupContainerWith(t, image, []testcontainers.ContainerFile{initFile})
		defer testcontainers.CleanupContainer(t, ci)

		ctx := t.Context()
		host, err := ci.Host(ctx)
		require.NoError(t, err)
		mappedPort, err := ci.MappedPort(ctx, postgresqlPort)
		require.NoError(t, err)

		cfg := createDefaultConfig().(*Config)
		cfg.AddrConfig.Endpoint = net.JoinHostPort(host, mappedPort.Port())
		cfg.Username = "otelu"
		cfg.Password = "otelp"
		cfg.Databases = []string{"otel"}
		cfg.ClientConfig.Insecure = true

		factory := newDefaultClientFactory(cfg)
		dbClient, err := factory.getClient(ctx, "otel")
		require.NoError(t, err)
		defer dbClient.Close()

		tableMetrics, err := dbClient.getDatabaseTableMetrics(ctx, "otel")
		require.NoError(t, err)
		count, err := dbClient.getTableCount(ctx)
		require.NoError(t, err)

		assert.Greater(t, len(tableMetrics), 2, "fixture should include partitions and materialized views, not just plain tables")
		assert.Equal(t, int64(len(tableMetrics)), count, "cheap table count must equal the full per-table query's row count")
	}
}

// TestTableSizeIncludesIndexesAndToast is a regression test for the table_size query using
// pg_relation_size, which silently excludes a table's indexes and TOAST storage. Both fixture
// tables are built so pg_total_relation_size exceeds pg_relation_size by an unambiguous,
// multi-page margin: reverting to pg_relation_size (or only adding index size, but forgetting
// TOAST) fails this test rather than passing by a rounding coincidence.
//
// Run against both sides of the PG14 pg_stat_user_tables boundary that
// tableCountEquivalenceTest also straddles: pg_total_relation_size and TOAST storage predate
// both, but nothing else in this file exercises table_size against a real database on 13.
func TestTableSizeIncludesIndexesAndToast(t *testing.T) {
	t.Run("pre14", tableSizeIncludesIndexesAndToastTest("postgres:13-alpine"))
	t.Run("post14", tableSizeIncludesIndexesAndToastTest("postgres:16-alpine"))
}

func tableSizeIncludesIndexesAndToastTest(image string) func(*testing.T) {
	return func(t *testing.T) {
		initFile := testcontainers.ContainerFile{
			HostFilePath:      filepath.Join("testdata", "integration", "03-table-size-init.sql"),
			ContainerFilePath: "/docker-entrypoint-initdb.d/01-init.sql",
			FileMode:          0o644,
		}
		ci := setupContainerWith(t, image, []testcontainers.ContainerFile{initFile})
		defer testcontainers.CleanupContainer(t, ci)

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		host, err := ci.Host(ctx)
		require.NoError(t, err)
		mappedPort, err := ci.MappedPort(ctx, postgresqlPort)
		require.NoError(t, err)

		cfg := createDefaultConfig().(*Config)
		cfg.AddrConfig.Endpoint = net.JoinHostPort(host, mappedPort.Port())
		cfg.Username = "otelu"
		cfg.Password = "otelp"
		cfg.Databases = []string{"otel"}
		cfg.ClientConfig.Insecure = true

		factory := newDefaultClientFactory(cfg)
		dbClient, err := factory.getClient(ctx, "otel")
		require.NoError(t, err)
		defer dbClient.Close()

		// The receiver's own connection runs as otelu, so compute the reference values it can
		// actually see rather than as the superuser -- a permission gap here would otherwise
		// surface as a silent 0, not a test failure.
		referenceQuery := `SELECT
    c.relname,
    pg_total_relation_size(c.oid),
    pg_relation_size(c.oid),
    pg_indexes_size(c.oid),
    COALESCE(pg_total_relation_size(c.reltoastrelid), 0)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relname IN ('big_index_table', 'toasted_table') AND n.nspname = 'public';`

		pgClient, ok := dbClient.(*postgreSQLClient)
		require.True(t, ok, "expected the default client factory to return a *postgreSQLClient")

		rows, err := pgClient.client.QueryContext(ctx, referenceQuery)
		require.NoError(t, err)
		defer rows.Close()

		type reference struct {
			totalSize, relationSize, indexesSize, toastSize int64
		}
		referenceByTable := map[string]reference{}
		for rows.Next() {
			var name string
			var ref reference
			require.NoError(t, rows.Scan(&name, &ref.totalSize, &ref.relationSize, &ref.indexesSize, &ref.toastSize))
			referenceByTable[name] = ref
		}
		require.NoError(t, rows.Err())
		require.Len(t, referenceByTable, 2, "reference query should see both fixture tables")

		tableMetrics, err := dbClient.getDatabaseTableMetrics(ctx, "otel")
		require.NoError(t, err)

		indexRef := referenceByTable["big_index_table"]
		require.Positive(t, indexRef.indexesSize, "fixture bug: index has no measurable size, assertion below would be vacuous")
		indexStats, ok := tableMetrics[tableKey("otel", "public", "big_index_table")]
		require.True(t, ok, "big_index_table missing from getDatabaseTableMetrics result")
		assert.Equal(t, indexRef.totalSize, indexStats.size,
			"postgresql.table.size must equal pg_total_relation_size, not pg_relation_size alone")
		assert.Greater(t, indexStats.size, indexRef.relationSize,
			"reported size must exceed the data-only size now that the table has a non-trivial index")

		toastRef := referenceByTable["toasted_table"]
		require.Positive(t, toastRef.toastSize, "fixture bug: no TOAST data was created, assertion below would be vacuous")
		toastStats, ok := tableMetrics[tableKey("otel", "public", "toasted_table")]
		require.True(t, ok, "toasted_table missing from getDatabaseTableMetrics result")
		assert.Equal(t, toastRef.totalSize, toastStats.size,
			"postgresql.table.size must equal pg_total_relation_size, not pg_relation_size alone")
		assert.Greater(t, toastStats.size, toastRef.relationSize+toastRef.indexesSize,
			"reported size must include TOAST data, not just the main heap and indexes")
	}
}
