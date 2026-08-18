// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsizeawarebatchprocessor // import "github.com/newrelic-forks/opentelemetry-collector-contrib/processor/nrsizeawarebatchprocessor"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
)

// typeStr is the component type identifier.
const typeStr = "nrsizeawarebatch"

// NewFactory creates the processor factory.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(typeStr),
		func() component.Config { cfg := createDefaultConfig(); return &cfg },
		processor.WithLogs(createLogsProcessor, component.StabilityLevelDevelopment),
	)
}

func createLogsProcessor(
	_ context.Context,
	_ processor.Settings,
	cfg component.Config,
	next consumer.Logs,
) (processor.Logs, error) {
	processorCfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config type: %T", cfg)
	}
	if err := processorCfg.Validate(); err != nil {
		return nil, err
	}
	return newProcessor(processorCfg, next), nil
}
