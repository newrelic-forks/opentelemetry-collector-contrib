// Copyright 2021, OpenTelemetry Authors
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

package stackdriverexporter

import (
	"context"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configmodels"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/googlecloudexporter"
)

type factory struct {
	component.ExporterFactory
}

const (
	// The value of "type" key in configuration.
	typeVal = configmodels.Type("stackdriver")
)

var once sync.Once

// NewFactory creates a factory for the stackdriver exporter
func NewFactory() component.ExporterFactory {
	return &factory{ExporterFactory: googlecloudexporter.NewFactory()}
}

func logDeprecation(logger *zap.Logger) {
	once.Do(func() {
		logger.Warn("stackdriver exporter is deprecated. Use googlecloudexporter instead.")
	})
}

func (f *factory) Type() configmodels.Type {
	return typeVal
}

func (f *factory) CreateDefaultConfig() configmodels.Exporter {
	cfg := f.ExporterFactory.CreateDefaultConfig()
	cfg.(*googlecloudexporter.Config).TypeVal = f.Type()
	return cfg
}

func (f *factory) CreateTracesExporter(
	ctx context.Context,
	params component.ExporterCreateParams,
	cfg configmodels.Exporter,
) (component.TracesExporter, error) {
	logDeprecation(params.Logger)
	return f.ExporterFactory.CreateTracesExporter(ctx, params, cfg)
}

func (f *factory) CreateMetricsExporter(
	ctx context.Context,
	params component.ExporterCreateParams,
	cfg configmodels.Exporter,
) (component.MetricsExporter, error) {
	logDeprecation(params.Logger)
	return f.ExporterFactory.CreateMetricsExporter(ctx, params, cfg)
}
