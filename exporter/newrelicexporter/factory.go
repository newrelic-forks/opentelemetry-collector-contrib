// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package newrelicexporter

import (
	"context"
	"fmt"
	"github.com/newrelic/newrelic-telemetry-sdk-go/telemetry"
	"go.opencensus.io/stats/view"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configmodels"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.uber.org/zap"
)

const typeStr = "newrelic"

// NewFactory creates a factory for New Relic exporter.
func NewFactory() component.ExporterFactory {
	view.Register(MetricViews()...)

	return exporterhelper.NewFactory(
		typeStr,
		createDefaultConfig,
		exporterhelper.WithTraces(createTraceExporter),
		exporterhelper.WithMetrics(createMetricsExporter),
		exporterhelper.WithLogs(createLogsExporter),
	)
}

func createDefaultConfig() configmodels.Exporter {
	return &Config{
		ExporterSettings: configmodels.ExporterSettings{
			TypeVal: configmodels.Type(typeStr),
			NameVal: typeStr,
		},
		Timeout: time.Second * 15,
	}
}

type endpointConfig struct {
	// APIKey is the required authentication credentials for New Relic APIs. This field specifies the default key.
	APIKey string `mapstructure:"apikey"`

	// APIKeyHeader may be specified to instruct the exporter to extract the API key from the request context.
	APIKeyHeader string `mapstructure:"api_key_header"`

	// CommonAttributes are the attributes to be applied to all telemetry
	// sent to New Relic.
	CommonAttributes map[string]interface{} `mapstructure:"common_attributes"`

	// HostOverride overrides the endpoint.
	HostOverride string `mapstructure:"host_override"`

	// Insecure disables TLS on the endpoint.
	insecure bool
}

// CreateTracesExporter creates a New Relic trace exporter for this configuration.
func createTraceExporter(
	_ context.Context,
	params component.ExporterCreateParams,
	cfg configmodels.Exporter,
) (component.TracesExporter, error) {
	nrConfig, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config: %#v", cfg)
	}
	internalConfig := endpointConfig{
		APIKey:           nrConfig.APIKey,
		APIKeyHeader:     nrConfig.APIKeyHeader,
		CommonAttributes: nil, // FIXME: missing common attributes
		HostOverride:     nrConfig.SpansHostOverride,
		insecure:         nrConfig.spansInsecure,
	}
	exp, err := newExporter(params.Logger, internalConfig, telemetry.NewSpanRequestFactory)
	if err != nil {
		return nil, err
	}

	// The logger is only used in a disabled queuedRetrySender, which noisily logs at
	// the error level when it is disabled and errors occur.
	return exporterhelper.NewTraceExporter(cfg, zap.NewNop(), exp.pushTraceData,
		exporterhelper.WithTimeout(exporterhelper.TimeoutSettings{Timeout: nrConfig.Timeout}),
		exporterhelper.WithRetry(exporterhelper.RetrySettings{Enabled: false}),
		exporterhelper.WithQueue(exporterhelper.QueueSettings{Enabled: false}))
}

// CreateMetricsExporter creates a New Relic metrics exporter for this configuration.
func createMetricsExporter(
	_ context.Context,
	params component.ExporterCreateParams,
	cfg configmodels.Exporter,
) (component.MetricsExporter, error) {
	nrConfig, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config: %#v", cfg)
	}

	internalConfig := endpointConfig{
		APIKey:           nrConfig.APIKey,
		APIKeyHeader:     nrConfig.APIKeyHeader,
		CommonAttributes: nil, // FIXME: missing common attributes
		HostOverride:     nrConfig.MetricsHostOverride,
		insecure:         nrConfig.metricsInsecure,
	}

	exp, err := newExporter(params.Logger, internalConfig, telemetry.NewMetricRequestFactory)
	if err != nil {
		return nil, err
	}

	return exporterhelper.NewMetricsExporter(cfg, zap.NewNop(), exp.pushMetricData)
}

// CreateLogsExporter creates a New Relic logs exporter for this configuration.
func createLogsExporter(
	_ context.Context,
	params component.ExporterCreateParams,
	cfg configmodels.Exporter,
) (component.LogsExporter, error) {
	nrConfig, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config: %#v", cfg)
	}

	internalConfig := endpointConfig{
		APIKey:           nrConfig.APIKey,
		APIKeyHeader:     nrConfig.APIKeyHeader,
		CommonAttributes: nil, // FIXME: missing common attributes
		HostOverride:     nrConfig.LogsHostOverride,
		insecure:         nrConfig.logsInsecure,
	}
	exp, err := newExporter(params.Logger, internalConfig, telemetry.NewLogRequestFactory)
	if err != nil {
		return nil, err
	}
	return exporterhelper.NewLogsExporter(cfg, zap.NewNop(), exp.pushLogData)
}
