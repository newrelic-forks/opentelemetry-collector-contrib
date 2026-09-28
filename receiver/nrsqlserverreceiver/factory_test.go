// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver/internal/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func TestFactory(t *testing.T) {
	testCases := []struct {
		desc     string
		testFunc func(*testing.T)
	}{
		{
			desc: "creates a new factory with correct type",
			testFunc: func(t *testing.T) {
				factory := NewFactory()
				require.Equal(t, metadata.Type, factory.Type())
			},
		},
		{
			desc: "creates a new factory with valid default config",
			testFunc: func(t *testing.T) {
				factory := NewFactory()

				var expectedCfg component.Config = &Config{
					ControllerConfig: scraperhelper.ControllerConfig{
						CollectionInterval: 10 * time.Second,
						InitialDelay:       time.Second,
					},
					TopQueryCollection: TopQueryCollection{
						MaxQuerySampleCount: 1000,
						TopQueryCount:       250,
						CollectionInterval:  time.Minute,
					},
					QuerySample: QuerySample{
						MaxRowsPerQuery: 100,
					},
					MetricsBuilderConfig: metadata.NewDefaultMetricsBuilderConfig(),
					LogsBuilderConfig:    metadata.DefaultLogsBuilderConfig(),
				}

				require.Equal(t, expectedCfg, factory.CreateDefaultConfig())
			},
		},
		{
			desc: "creates a new factory and CreateMetrics returns error with incorrect config",
			testFunc: func(t *testing.T) {
				factory := NewFactory()
				_, err := factory.CreateMetrics(
					t.Context(),
					receivertest.NewNopSettings(metadata.Type),
					nil,
					consumertest.NewNop(),
				)
				require.ErrorIs(t, err, errConfigNotSQLServer)
			},
		},
		{
			desc: "creates a new factory and CreateMetrics returns no error",
			testFunc: func(t *testing.T) {
				factory := NewFactory()
				cfg := factory.CreateDefaultConfig()
				r, err := factory.CreateMetrics(
					t.Context(),
					receivertest.NewNopSettings(metadata.Type),
					cfg,
					consumertest.NewNop(),
				)
				require.NoError(t, err)
				scrapers, _ := setupSQLServerScrapers(receivertest.NewNopSettings(metadata.Type), cfg.(*Config))
				require.Empty(t, scrapers)
				require.NoError(t, r.Start(t.Context(), componenttest.NewNopHost()))
				require.NoError(t, r.Shutdown(t.Context()))
			},
		},
		{
			desc: "[metrics] Test direct connection",
			testFunc: func(t *testing.T) {
				factory := NewFactory()
				cfg := factory.CreateDefaultConfig().(*Config)
				cfg.Username = "sa"
				cfg.Password = "password"
				cfg.Server = "0.0.0.0"
				cfg.Port = 1433
				require.NoError(t, cfg.Validate())
				cfg.Metrics.SqlserverDatabaseLatency.Enabled = true

				require.True(t, cfg.isDirectDBConnectionEnabled)
				require.Equal(t, "server=0.0.0.0;user id=sa;password=password;port=1433", getDBConnectionString(cfg))

				params := receivertest.NewNopSettings(metadata.Type)
				scrapers, _, err := setupScrapers(params, cfg)
				require.NoError(t, err)
				require.NotEmpty(t, scrapers)

				sqlScrapers, _ := setupSQLServerScrapers(params, cfg)
				require.NotEmpty(t, sqlScrapers)

				databaseIOScraperFound := false
				for _, scraper := range sqlScrapers {
					if scraper.sqlQuery == getSQLServerDatabaseIOQuery(cfg.InstanceName) {
						databaseIOScraperFound = true
						break
					}
				}

				require.True(t, databaseIOScraperFound)
				cfg.InstanceName = "instanceName"
				sqlScrapers, _ = setupSQLServerScrapers(params, cfg)
				require.NotEmpty(t, sqlScrapers)

				databaseIOScraperFound = false
				for _, scraper := range sqlScrapers {
					if scraper.sqlQuery == getSQLServerDatabaseIOQuery(cfg.InstanceName) {
						databaseIOScraperFound = true
						break
					}
				}

				require.True(t, databaseIOScraperFound)

				r, err := factory.CreateMetrics(
					t.Context(),
					receivertest.NewNopSettings(metadata.Type),
					cfg,
					consumertest.NewNop(),
				)
				require.NoError(t, err)
				require.NoError(t, r.Start(t.Context(), componenttest.NewNopHost()))
				require.NoError(t, r.Shutdown(t.Context()))
			},
		},
		// Test cases for logs
		{
			desc: "creates a new factory and CreateLogs returns error with incorrect config",
			testFunc: func(t *testing.T) {
				factory := NewFactory()
				_, err := factory.CreateLogs(
					t.Context(),
					receivertest.NewNopSettings(metadata.Type),
					nil,
					consumertest.NewNop(),
				)
				require.ErrorIs(t, err, errConfigNotSQLServer)
			},
		},
		{
			desc: "creates a new factory and CreateLogs returns no error",
			testFunc: func(t *testing.T) {
				factory := NewFactory()
				cfg := factory.CreateDefaultConfig()
				r, err := factory.CreateLogs(
					t.Context(),
					receivertest.NewNopSettings(metadata.Type),
					cfg,
					consumertest.NewNop(),
				)
				require.NoError(t, err)
				scrapers, _ := setupSQLServerLogsScrapers(receivertest.NewNopSettings(metadata.Type), cfg.(*Config))
				require.Empty(t, scrapers)
				require.NoError(t, r.Start(t.Context(), componenttest.NewNopHost()))
				require.NoError(t, r.Shutdown(t.Context()))
			},
		},
		{
			desc: "[logs] Test direct connection",
			testFunc: func(t *testing.T) {
				factory := NewFactory()
				cfg := factory.CreateDefaultConfig().(*Config)
				cfg.Username = "sa"
				cfg.Password = "password"
				cfg.Server = "0.0.0.0"
				cfg.Port = 1433
				require.NoError(t, cfg.Validate())
				cfg.Metrics.SqlserverDatabaseLatency.Enabled = true

				require.True(t, cfg.isDirectDBConnectionEnabled)
				require.Equal(t, "server=0.0.0.0;user id=sa;password=password;port=1433", getDBConnectionString(cfg))

				params := receivertest.NewNopSettings(metadata.Type)
				scrapers, _, err := setupLogsScrapers(params, cfg)
				require.NoError(t, err)
				require.Empty(t, scrapers)

				sqlScrapers, _ := setupSQLServerLogsScrapers(params, cfg)
				require.Empty(t, sqlScrapers)

				cfg.InstanceName = "instanceName"
				cfg.Events.DbServerTopQuery.Enabled = true
				scrapers, _, err = setupLogsScrapers(params, cfg)
				require.NoError(t, err)
				require.NotEmpty(t, scrapers)

				sqlScrapers, _ = setupSQLServerLogsScrapers(params, cfg)
				require.NotEmpty(t, sqlScrapers)

				q := getSQLServerQueryTextAndPlanQuery()

				databaseTopQueryScraperFound := false
				for _, scraper := range sqlScrapers {
					if scraper.sqlQuery == q {
						databaseTopQueryScraperFound = true
						break
					}
				}

				require.True(t, databaseTopQueryScraperFound)

				r, err := factory.CreateLogs(
					t.Context(),
					receivertest.NewNopSettings(metadata.Type),
					cfg,
					consumertest.NewNop(),
				)
				require.NoError(t, err)
				require.NoError(t, r.Start(t.Context(), componenttest.NewNopHost()))
				require.NoError(t, r.Shutdown(t.Context()))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, tc.testFunc)
	}
}

func TestNewCache(t *testing.T) {
	var cache *lru.Cache[string, int64]
	// even when size is less than 0, cache should be created with size 1.
	// Also noticed that the cache returned would never be nil, only
	// cache.lru could be nil, which is invisible to us. So we can
	// test the cache.Values() method to check if the cache is created.
	cache = newCache(10)
	require.NotNil(t, cache.Values())
	cache = newCache(-1)
	require.NotNil(t, cache.Values())
	cache = newCache(0)
	require.NotNil(t, cache.Values())
}

// TestScrapersShareSingleConnectionPool verifies that all scrapers created for
// a receiver share one *sql.DB connection pool rather than each opening its own.
func TestScrapersShareSingleConnectionPool(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.Username = "sa"
	cfg.Password = "password"
	cfg.Server = "0.0.0.0"
	cfg.Port = 1433
	// Enable metrics that map to several distinct queries so more than one
	// scraper is created.
	cfg.Metrics.SqlserverDatabaseLatency.Enabled = true // database IO query
	cfg.Metrics.SqlserverOsWaitDuration.Enabled = true  // wait stats query
	cfg.Metrics.SqlserverDatabaseCount.Enabled = true   // properties query
	require.NoError(t, cfg.Validate())
	require.True(t, cfg.isDirectDBConnectionEnabled)

	params := receivertest.NewNopSettings(metadata.Type)
	scrapers, provider := setupSQLServerScrapers(params, cfg)
	require.Greater(t, len(scrapers), 1, "expected more than one scraper to prove pool sharing")
	require.NotNil(t, provider)
	// The pool is owned by the receiver; close it once when the test finishes.
	defer func() { require.NoError(t, provider.close()) }()

	for _, s := range scrapers {
		require.NoError(t, s.Start(t.Context(), componenttest.NewNopHost()))
	}

	shared := scrapers[0].db
	require.NotNil(t, shared)
	for _, s := range scrapers {
		require.Same(t, shared, s.db, "all scrapers must share the same *sql.DB pool")
	}

	// Scraper shutdown must not close the shared pool; the receiver owns it.
	for _, s := range scrapers {
		require.NoError(t, s.Shutdown(t.Context()))
	}
}

// TestConnectionPoolSettings verifies the pool is sized from the scraper count
// by default and that explicit config overrides win.
func TestConnectionPoolSettings(t *testing.T) {
	const dsn = "server=0.0.0.0;user id=sa;password=password;port=1433"

	t.Run("default max_open derived from scraper count", func(t *testing.T) {
		db, err := sql.Open("sqlserver", dsn)
		require.NoError(t, err)
		defer db.Close()

		setConnectionPoolSettings(db, ConnectionPool{}, 4)
		require.Equal(t, 4, db.Stats().MaxOpenConnections)
	})

	t.Run("explicit max_open overrides the default", func(t *testing.T) {
		db, err := sql.Open("sqlserver", dsn)
		require.NoError(t, err)
		defer db.Close()

		maxOpen := 12
		setConnectionPoolSettings(db, ConnectionPool{MaxOpen: &maxOpen}, 4)
		require.Equal(t, 12, db.Stats().MaxOpenConnections)
	})

	t.Run("scraper count is floored at one", func(t *testing.T) {
		db, err := sql.Open("sqlserver", dsn)
		require.NoError(t, err)
		defer db.Close()

		setConnectionPoolSettings(db, ConnectionPool{}, 0)
		require.Equal(t, 1, db.Stats().MaxOpenConnections)
	})
}

// TestDBProviderCloseIsSafe verifies the close semantics the receiver relies on
// when construction fails: closing is safe on a nil provider, a no-op when the
// pool was never opened, and idempotent.
func TestDBProviderCloseIsSafe(t *testing.T) {
	t.Run("nil provider", func(t *testing.T) {
		var provider *dbProvider
		require.NoError(t, provider.close())
	})

	t.Run("never opened", func(t *testing.T) {
		provider := newDBProvider(&Config{Server: "0.0.0.0", Username: "sa", Password: "password", Port: 1433}, 2)
		require.NoError(t, provider.close())
	})

	t.Run("idempotent after open", func(t *testing.T) {
		provider := newDBProvider(&Config{Server: "0.0.0.0", Username: "sa", Password: "password", Port: 1433}, 2)
		_, err := provider.getDB()
		require.NoError(t, err)
		require.NoError(t, provider.close())
		require.NoError(t, provider.close())
	})

	t.Run("getDB after close does not open a new pool", func(t *testing.T) {
		provider := newDBProvider(&Config{Server: "0.0.0.0", Username: "sa", Password: "password", Port: 1433}, 2)
		// close before the pool is ever opened, as happens on construction
		// error paths.
		require.NoError(t, provider.close())

		db, err := provider.getDB()
		require.ErrorIs(t, err, errDBProviderClosed)
		require.Nil(t, db, "getDB must not open a pool after close")
	})
}

func TestSetupQueries(t *testing.T) {
	var metadata map[string]any

	yamlFile, err := os.ReadFile("./metadata.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(yamlFile, &metadata))
	require.NotNil(t, metadata["metrics"])

	metricsMetadata, ok := metadata["metrics"].(map[string]any)
	require.True(t, ok)
	require.Len(t, metricsMetadata, 131, "Every time metrics are added or removed, the function `setupQueries` must "+
		"be modified to properly account for the change. Please update `setupQueries` and then, "+
		"and only then, update the expected metric count here.")
}

// TestDetectSQLServerInstanceInfo_NilDB verifies that a nil db returns nil pointers safely.
func TestDetectSQLServerInstanceInfo_NilDB(t *testing.T) {
	v, e, err := detectSQLServerInstanceInfo(t.Context(), nil)
	require.NoError(t, err)
	require.Nil(t, v)
	require.Nil(t, e)
}

// TestDetectSQLServerInstanceInfo_ScanError verifies that a scan error returns nil pointers and the error.
func TestDetectSQLServerInstanceInfo_ScanError(t *testing.T) {
	db, err := sql.Open("sqlserver", "sqlserver://sa:invalid@127.0.0.1:1433")
	require.NoError(t, err)
	defer db.Close()

	orig := detectSQLServerInstanceInfo
	defer func() { detectSQLServerInstanceInfo = orig }()
	detectSQLServerInstanceInfo = func(_ context.Context, _ *sql.DB) (*string, *string, error) {
		return nil, nil, assert.AnError
	}

	v, e, err := detectSQLServerInstanceInfo(t.Context(), db)
	require.Error(t, err)
	require.Nil(t, v)
	require.Nil(t, e)
}

// TestDetectSQLServerInstanceInfo_NullResult verifies that NULL from SERVERPROPERTY
// returns non-nil pointers to empty strings (permanent latch — no retry).
func TestDetectSQLServerInstanceInfo_NullResult(t *testing.T) {
	orig := detectSQLServerInstanceInfo
	defer func() { detectSQLServerInstanceInfo = orig }()
	empty := ""
	detectSQLServerInstanceInfo = func(_ context.Context, _ *sql.DB) (*string, *string, error) {
		return &empty, &empty, nil
	}

	db, err := sql.Open("sqlserver", "sqlserver://sa:invalid@127.0.0.1:1433")
	require.NoError(t, err)
	defer db.Close()

	v, e, err := detectSQLServerInstanceInfo(t.Context(), db)
	require.NoError(t, err)
	require.NotNil(t, v)
	require.NotNil(t, e)
	assert.Empty(t, *v)
	assert.Empty(t, *e)
}

// TestDetectSQLServerInstanceInfo_ValidResult verifies that a successful query returns
// the version and edition strings.
func TestDetectSQLServerInstanceInfo_ValidResult(t *testing.T) {
	orig := detectSQLServerInstanceInfo
	defer func() { detectSQLServerInstanceInfo = orig }()
	ver := "15.0.4261.1"
	ed := "Enterprise Edition (64-bit)"
	detectSQLServerInstanceInfo = func(_ context.Context, _ *sql.DB) (*string, *string, error) {
		return &ver, &ed, nil
	}

	db, err := sql.Open("sqlserver", "sqlserver://sa:invalid@127.0.0.1:1433")
	require.NoError(t, err)
	defer db.Close()

	v, e, err := detectSQLServerInstanceInfo(t.Context(), db)
	require.NoError(t, err)
	require.NotNil(t, v)
	require.NotNil(t, e)
	assert.Equal(t, "15.0.4261.1", *v)
	assert.Equal(t, "Enterprise Edition (64-bit)", *e)
}

// TestDBProviderDetectInstanceInfoCaches verifies that once resolved, detectInstanceInfo
// returns the cached result without querying the DB again.
func TestDBProviderDetectInstanceInfoCaches(t *testing.T) {
	provider := newDBProvider(&Config{Server: "127.0.0.1", Port: 1433}, 1)

	ver := "15.0.4261.1"
	ed := "Enterprise Edition (64-bit)"
	provider.dbVersion = &ver
	provider.dbEdition = &ed

	got, gotEd, resolved := provider.detectInstanceInfo(t.Context(), zap.NewNop())
	require.True(t, resolved)
	assert.Equal(t, "15.0.4261.1", got)
	assert.Equal(t, "Enterprise Edition (64-bit)", gotEd)

	// Second call must also return from cache.
	got, gotEd, resolved = provider.detectInstanceInfo(t.Context(), zap.NewNop())
	require.True(t, resolved)
	assert.Equal(t, "15.0.4261.1", got)
	assert.Equal(t, "Enterprise Edition (64-bit)", gotEd)
}

// TestDBProviderDetectInstanceInfoRetriesOnFailure verifies that a transient error
// returns resolved=false so the caller retries next interval.
func TestDBProviderDetectInstanceInfoRetriesOnFailure(t *testing.T) {
	provider := newDBProvider(&Config{Server: "127.0.0.1", Port: 1433}, 1)
	// db is nil — first call must return "" and leave dbVersion/dbEdition nil.
	result, resultEd, resolved := provider.detectInstanceInfo(t.Context(), zap.NewNop())
	assert.Empty(t, result)
	assert.Empty(t, resultEd)
	assert.False(t, resolved)
	assert.Nil(t, provider.dbVersion)
	assert.Nil(t, provider.dbEdition)

	// After a real (closed) DB is injected, the next call should retry.
	db, err := sql.Open("sqlserver", "sqlserver://sa:invalid@127.0.0.1:1433")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	provider.db = db

	result, resultEd, resolved = provider.detectInstanceInfo(t.Context(), zap.NewNop())
	assert.Empty(t, result)
	assert.Empty(t, resultEd)
	assert.False(t, resolved)
	assert.Nil(t, provider.dbVersion)
	assert.Nil(t, provider.dbEdition)
}

// TestDBProviderDetectInstanceInfoNullLatches verifies that when SERVERPROPERTY returns NULL,
// detectInstanceInfo latches dbVersion/dbEdition so subsequent intervals do not retry.
func TestDBProviderDetectInstanceInfoNullLatches(t *testing.T) {
	orig := detectSQLServerInstanceInfo
	defer func() { detectSQLServerInstanceInfo = orig }()

	nullStr := ""
	detectSQLServerInstanceInfo = func(_ context.Context, _ *sql.DB) (*string, *string, error) {
		return &nullStr, &nullStr, nil
	}

	db, err := sql.Open("sqlserver", "sqlserver://sa:invalid@127.0.0.1:1433")
	require.NoError(t, err)
	defer db.Close()

	provider := newDBProvider(&Config{Server: "127.0.0.1", Port: 1433}, 1)
	provider.db = db

	result, resultEd, resolved := provider.detectInstanceInfo(t.Context(), zap.NewNop())
	assert.Empty(t, result)
	assert.Empty(t, resultEd)
	assert.True(t, resolved)
	assert.NotNil(t, provider.dbVersion) // latched — will not retry
	assert.NotNil(t, provider.dbEdition)

	// Second call must return "" from cache, not re-query.
	detectSQLServerInstanceInfo = func(_ context.Context, _ *sql.DB) (*string, *string, error) {
		t.Fatal("detectSQLServerInstanceInfo called again after NULL was latched")
		return nil, nil, nil
	}

	result, resultEd, resolved = provider.detectInstanceInfo(t.Context(), zap.NewNop())
	assert.Empty(t, result)
	assert.Empty(t, resultEd)
	assert.True(t, resolved)
}
