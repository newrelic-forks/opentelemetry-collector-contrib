// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mysqlreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver"

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/scraper/scraperhelper"
	"go.uber.org/multierr"

	"github.com/open-telemetry/opentelemetry-collector-contrib/config/configdbauth"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/dbauth"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver/internal/metadata"
)

const (
	defaultStatementEventsDigestTextLimit = 120
	defaultStatementEventsLimit           = 250
	defaultStatementEventsTimeLimit       = 24 * time.Hour
)

// Errors for missing required config parameters.
const (
	ErrNoUsername          = "invalid config: missing username"
	ErrTransportsSupported = "invalid config: 'transport' must be 'tcp' or 'unix'"
	ErrNoEndpoint          = "invalid config: missing endpoint"
	// #nosec G101 - not hardcoded credentials
	ErrPasswordAndDBAuth = "invalid config: set either 'password' or 'db_auth', not both"
	// #nosec G101 - not hardcoded credentials
	ErrDBAuthRequiresTLS = "invalid config: 'db_auth' requires TLS; set 'tls.insecure' to false"
	// db.server.query_plan reports the plans collected for the statements the other two events report,
	// so on its own it reports nothing.
	ErrQueryPlanWithoutSource = "invalid config: 'db.server.query_plan' requires 'db.server.top_query' or 'db.server.query_sample' to be enabled"
)

type Config struct {
	ControllerConfig      scraperhelper.ControllerConfig `mapstructure:",squash"`
	Username              string                         `mapstructure:"username,omitempty"`
	Password              configopaque.String            `mapstructure:"password,omitempty"`
	Database              string                         `mapstructure:"database,omitempty"`
	AllowNativePasswords  bool                           `mapstructure:"allow_native_passwords,omitempty"`
	AddrConfig            confignet.AddrConfig           `mapstructure:",squash"`
	TLS                   configtls.ClientConfig         `mapstructure:"tls,omitempty"`
	MetricsBuilderConfig  metadata.MetricsBuilderConfig  `mapstructure:",squash"`
	LogsBuilderConfig     metadata.LogsBuilderConfig     `mapstructure:",squash"`
	StatementEvents       StatementEventsConfig          `mapstructure:"statement_events"`
	TopQueryCollection    TopQueryCollection             `mapstructure:"top_query_collection"`
	QuerySampleCollection QuerySampleCollection          `mapstructure:"query_sample_collection"`
	// TableMetadataCollection configures the table structure/size inventory event.
	TableMetadataCollection TableMetadataCollection `mapstructure:"table_metadata_collection"`
	// ViewMetadataCollection configures the view structure inventory event.
	ViewMetadataCollection ViewMetadataCollection `mapstructure:"view_metadata_collection"`
	DBAuth                 configdbauth.ID        `mapstructure:"db_auth,omitempty"`
}

type TopQueryCollection struct {
	LookbackTime        uint64        `mapstructure:"lookback_time"`
	MaxQuerySampleCount uint64        `mapstructure:"max_query_sample_count"`
	TopQueryCount       uint64        `mapstructure:"top_query_count"`
	CollectionInterval  time.Duration `mapstructure:"collection_interval"`
	QueryPlanCacheSize  int           `mapstructure:"query_plan_cache_size"`
	QueryPlanCacheTTL   time.Duration `mapstructure:"query_plan_cache_ttl"`

	_ struct{}
}
type QuerySampleCollection struct {
	MaxRowsPerQuery uint64 `mapstructure:"max_rows_per_query"`

	_ struct{}
}

// TableMetadataCollection configures the collection of table structure and size
// inventory (db.server.table_metadata). Structure changes rarely, so this runs on its
// own, slower interval, decoupled from the main metrics scrape interval.
type TableMetadataCollection struct {
	CollectionInterval time.Duration `mapstructure:"collection_interval"`
	// MaxTables caps the number of tables reported per poll, to bound worst-case
	// payload size on very large schemas. 0 means use the default.
	MaxTables uint64 `mapstructure:"max_tables"`

	_ struct{}
}

// ViewMetadataCollection configures the collection of view structure inventory
// (db.server.view_metadata). Off by default.
type ViewMetadataCollection struct {
	CollectionInterval time.Duration `mapstructure:"collection_interval"`
	// MaxViews caps the number of views reported per poll. 0 means use the default.
	MaxViews uint64 `mapstructure:"max_views"`

	_ struct{}
}

type StatementEventsConfig struct {
	DigestTextLimit int           `mapstructure:"digest_text_limit"`
	Limit           int           `mapstructure:"limit"`
	TimeLimit       time.Duration `mapstructure:"time_limit"`
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

func (cfg *Config) Validate() error {
	var err error
	if cfg.Username == "" {
		err = multierr.Append(err, errors.New(ErrNoUsername))
	}

	dbAuthConfigured := !cfg.DBAuth.IsEmpty()
	switch {
	case dbAuthConfigured && cfg.Password != "":
		err = multierr.Append(err, errors.New(ErrPasswordAndDBAuth))
	case dbAuthConfigured && cfg.TLS.Insecure:
		err = multierr.Append(err, errors.New(ErrDBAuthRequiresTLS))
	}

	switch cfg.AddrConfig.Transport {
	case confignet.TransportTypeTCP, confignet.TransportTypeUnix:
		if cfg.AddrConfig.Endpoint == "" {
			err = multierr.Append(err, errors.New(ErrNoEndpoint))
		}
	default:
		err = multierr.Append(err, errors.New(ErrTransportsSupported))
	}

	events := cfg.LogsBuilderConfig.Events
	if events.DbServerQueryPlan.Enabled && !events.DbServerTopQuery.Enabled && !events.DbServerQuerySample.Enabled {
		err = multierr.Append(err, errors.New(ErrQueryPlanWithoutSource))
	}

	if cfg.TableMetadataCollection.CollectionInterval < 0 {
		err = multierr.Append(err, errors.New("`table_metadata_collection.collection_interval` must not be less than 0"))
	}
	if events.DbServerTableMetadata.Enabled && cfg.TableMetadataCollection.MaxTables < 1 {
		err = multierr.Append(err, errors.New("`table_metadata_collection.max_tables` must be greater than 0"))
	}

	if cfg.ViewMetadataCollection.CollectionInterval < 0 {
		err = multierr.Append(err, errors.New("`view_metadata_collection.collection_interval` must not be less than 0"))
	}
	if events.DbServerViewMetadata.Enabled && cfg.ViewMetadataCollection.MaxViews < 1 {
		err = multierr.Append(err, errors.New("`view_metadata_collection.max_views` must be greater than 0"))
	}

	return err
}

func (cfg *Config) resolveCredentialProvider(extensions map[component.ID]component.Component) (dbauth.Provider, error) {
	if cfg.DBAuth.IsEmpty() {
		return nil, nil
	}
	return cfg.DBAuth.GetProvider(extensions)
}
