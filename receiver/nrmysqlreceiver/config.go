// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrmysqlreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrmysqlreceiver"

import (
	"fmt"
	"time"

	"github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrmysqlreceiver/internal/metadata"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
)

const (
	defaultStatementEventsDigestTextLimit = 120
	defaultStatementEventsLimit           = 250
	defaultStatementEventsTimeLimit       = 24 * time.Hour
)

// EXPLAIN execution modes (see explain_mode config option).
const (
	// explainModeInline runs EXPLAIN directly on the monitoring connection.
	// EXPLAIN of a write statement then requires the connection user to hold the
	// matching DML privilege, so a read-only monitoring user loses plans for
	// UPDATE/DELETE/INSERT/REPLACE.
	explainModeInline = "inline"
	// explainModeProcedure routes EXPLAIN through a SQL SECURITY DEFINER stored
	// procedure (<schema>.explain_statement) so write statements can be explained
	// without granting DML to the monitoring user. Falls back to inline EXPLAIN
	// when the procedure is absent for a schema.
	explainModeProcedure = "procedure"
)

type Config struct {
	scraperhelper.ControllerConfig `mapstructure:",squash"`
	Username                       string              `mapstructure:"username,omitempty"`
	Password                       configopaque.String `mapstructure:"password,omitempty"`
	Database                       string              `mapstructure:"database,omitempty"`
	AllowNativePasswords           bool                `mapstructure:"allow_native_passwords,omitempty"`
	confignet.AddrConfig           `mapstructure:",squash"`
	TLS                            configtls.ClientConfig        `mapstructure:"tls,omitempty"`
	MetricsBuilderConfig           metadata.MetricsBuilderConfig `mapstructure:",squash"`
	LogsBuilderConfig              metadata.LogsBuilderConfig    `mapstructure:",squash"`
	StatementEvents                StatementEventsConfig         `mapstructure:"statement_events"`
	TopQueryCollection             TopQueryCollection            `mapstructure:"top_query_collection"`
	QuerySampleCollection          QuerySampleCollection         `mapstructure:"query_sample_collection"`
	// ExplainMode selects how execution plans are retrieved: "inline" (default,
	// direct EXPLAIN on the monitoring connection) or "procedure" (CALL the
	// <schema>.explain_statement SQL SECURITY DEFINER procedure, so write
	// statements can be explained without granting DML to the monitoring user).
	ExplainMode string `mapstructure:"explain_mode"`
}

type TopQueryCollection struct {
	LookbackTime        uint64        `mapstructure:"lookback_time"`
	MaxQuerySampleCount uint64        `mapstructure:"max_query_sample_count"`
	TopQueryCount       uint64        `mapstructure:"top_query_count"`
	CollectionInterval  time.Duration `mapstructure:"collection_interval"`
	QueryPlanCacheSize  int           `mapstructure:"query_plan_cache_size"`
	QueryPlanCacheTTL   time.Duration `mapstructure:"query_plan_cache_ttl"`
	AllowedCommentKeys  []string      `mapstructure:"allowed_comment_keys"`

	_ struct{}
}
type QuerySampleCollection struct {
	MaxRowsPerQuery    uint64   `mapstructure:"max_rows_per_query"`
	AllowedCommentKeys []string `mapstructure:"allowed_comment_keys"`

	_ struct{}
}

type StatementEventsConfig struct {
	DigestTextLimit int           `mapstructure:"digest_text_limit"`
	Limit           int           `mapstructure:"limit"`
	TimeLimit       time.Duration `mapstructure:"time_limit"`
}

func (cfg *Config) Validate() error {
	switch cfg.ExplainMode {
	case "", explainModeInline, explainModeProcedure:
		return nil
	default:
		return fmt.Errorf("invalid explain_mode %q: must be %q or %q", cfg.ExplainMode, explainModeInline, explainModeProcedure)
	}
}

func (cfg *Config) Unmarshal(componentParser *confmap.Conf) error {
	if componentParser == nil {
		// Nothing to do if there is no config given.
		return nil
	}

	// Change the default to Insecure = true as we don't want to break
	// existing deployments which does not use TLS by default.
	if !componentParser.IsSet("tls") {
		cfg.TLS = configtls.ClientConfig{}
		cfg.TLS.Insecure = true
	}

	return componentParser.Unmarshal(cfg)
}
