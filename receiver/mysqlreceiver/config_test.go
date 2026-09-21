// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mysqlreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver"

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/confmap/confmaptest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver/internal/metadata"
)

func TestLoadConfig(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	sub, err := cm.Sub(component.NewIDWithName(metadata.Type, "").String())
	require.NoError(t, err)
	require.NoError(t, sub.Unmarshal(cfg))

	expected := factory.CreateDefaultConfig().(*Config)
	expected.AddrConfig.Endpoint = "localhost:3306"
	expected.Username = "otel"
	expected.Password = "${env:MYSQL_PASSWORD}"
	expected.Database = "otel"
	expected.ControllerConfig.CollectionInterval = 10 * time.Second
	// This defaults to true when tls is omitted from the configmap.
	expected.TLS.Insecure = true

	require.Equal(t, expected, cfg)
}

func TestLoadConfigDefaultTLS(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	sub, err := cm.Sub(component.NewIDWithName(metadata.Type, "").String() + "/default_tls")
	require.NoError(t, err)
	require.NoError(t, sub.Unmarshal(cfg))

	expected := factory.CreateDefaultConfig().(*Config)
	expected.AddrConfig.Endpoint = "localhost:3306"
	expected.Username = "otel"
	expected.Password = "${env:MYSQL_PASSWORD}"
	expected.Database = "otel"
	expected.ControllerConfig.CollectionInterval = 10 * time.Second
	// This defaults to false when tls is defined in the configmap.
	expected.TLS.Insecure = false
	expected.TLS.ServerName = "localhost"

	require.Equal(t, expected, cfg)
}

func TestConfigValidate_UnixSocketEndpoint(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Username = "otel"
	cfg.AddrConfig.Transport = confignet.TransportTypeUnix
	cfg.AddrConfig.Endpoint = "/var/run/mysqld/mysqld.sock"

	require.NoError(t, cfg.Validate())
}

func TestConfigValidate_UnixSocketMissingEndpoint(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Username = "otel"
	cfg.AddrConfig.Transport = confignet.TransportTypeUnix
	cfg.AddrConfig.Endpoint = ""

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), ErrNoEndpoint)
}

func TestConfigValidate_TCPEndpointWithoutPort(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Username = "otel"
	cfg.AddrConfig.Transport = confignet.TransportTypeTCP
	cfg.AddrConfig.Endpoint = "localhost"

	require.NoError(t, cfg.Validate())
}

func TestConfigValidate_TCPMissingEndpoint(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Username = "otel"
	cfg.AddrConfig.Transport = confignet.TransportTypeTCP
	cfg.AddrConfig.Endpoint = ""

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), ErrNoEndpoint)
}

// A query plan event reports the plans collected for its own source event, so each one is held to its
// own dependency.
func TestConfigValidate_QueryPlanEventWithoutItsSource(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enable   func(cfg *Config)
		expected string
	}{
		{
			name:     "top query plan without top query",
			enable:   func(cfg *Config) { cfg.LogsBuilderConfig.Events.DbServerTopQueryQueryPlan.Enabled = true },
			expected: ErrTopQueryPlanWithoutTopQuery,
		},
		{
			name:     "query sample plan without query sample",
			enable:   func(cfg *Config) { cfg.LogsBuilderConfig.Events.DbServerQuerySampleQueryPlan.Enabled = true },
			expected: ErrQuerySamplePlanWithoutQuerySample,
		},
		{
			name: "top query plan with query sample only",
			enable: func(cfg *Config) {
				cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
				cfg.LogsBuilderConfig.Events.DbServerTopQueryQueryPlan.Enabled = true
			},
			expected: ErrTopQueryPlanWithoutTopQuery,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := createDefaultConfig().(*Config)
			cfg.Username = "otel"
			tc.enable(cfg)

			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expected)
		})
	}
}

func TestConfigValidate_QueryPlanEventsWithTheirSources(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	cfg.Username = "otel"
	cfg.LogsBuilderConfig.Events.DbServerTopQuery.Enabled = true
	cfg.LogsBuilderConfig.Events.DbServerTopQueryQueryPlan.Enabled = true
	cfg.LogsBuilderConfig.Events.DbServerQuerySample.Enabled = true
	cfg.LogsBuilderConfig.Events.DbServerQuerySampleQueryPlan.Enabled = true

	require.NoError(t, cfg.Validate())
}
