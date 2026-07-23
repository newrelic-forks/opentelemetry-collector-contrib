// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package nrmysqlreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrmysqlreceiver"

import (
	"net"
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

const mysqlPort = "3306/tcp"

// setupContainer starts a stock MySQL container. The fork deliberately avoids the
// base internal/coreinternal/scraperinttest harness; this uses testcontainers-go
// directly, mirroring receiver/nrpostgresqlreceiver/integration_test.go and
// receiver/nrsqlserverreceiver/integration_test.go.
func setupContainer(t *testing.T) testcontainers.Container {
	ctx := t.Context()
	ci, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: "mysql:8.0",
				Env: map[string]string{
					"MYSQL_ROOT_PASSWORD": "otel",
					"MYSQL_DATABASE":      "otel",
					"MYSQL_USER":          "otel",
					"MYSQL_PASSWORD":      "otel",
				},
				ExposedPorts: []string{mysqlPort},
				WaitingFor: wait.ForListeningPort(mysqlPort).
					WithStartupTimeout(3 * time.Minute),
			},
			Started: true,
		},
	)
	require.NoError(t, err)
	return ci
}

// TestIntegrationScrapeMetrics stands up a real MySQL instance, runs the
// nrmysql receiver against it, and asserts that metrics are collected.
func TestIntegrationScrapeMetrics(t *testing.T) {
	ci := setupContainer(t)
	defer testcontainers.CleanupContainer(t, ci)

	ctx := t.Context()
	host, err := ci.Host(ctx)
	require.NoError(t, err)
	mappedPort, err := ci.MappedPort(ctx, mysqlPort)
	require.NoError(t, err)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.CollectionInterval = time.Second
	cfg.Endpoint = net.JoinHostPort(host, mappedPort.Port())
	cfg.Username = "otel"
	cfg.Password = "otel"
	cfg.Database = "otel"
	cfg.AllowNativePasswords = true
	cfg.TLS.Insecure = true

	sink := new(consumertest.MetricsSink)
	recv, err := factory.CreateMetrics(ctx, receivertest.NewNopSettings(factory.Type()), cfg, sink)
	require.NoError(t, err)

	require.NoError(t, recv.Start(ctx, componenttest.NewNopHost()))
	defer func() { require.NoError(t, recv.Shutdown(ctx)) }()

	require.Eventually(t, func() bool {
		return sink.DataPointCount() > 0
	}, 60*time.Second, time.Second, "expected the receiver to collect at least one metric data point")

	assert.NotEmpty(t, sink.AllMetrics())
}
