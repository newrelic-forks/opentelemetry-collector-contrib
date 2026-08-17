// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsizeawarebatchprocessor // import "github.com/newrelic-forks/opentelemetry-collector-contrib/processor/nrsizeawarebatchprocessor"

import "errors"

const (
	// DefaultMaxCompressedBytes is the default split threshold: 900 KB,
	// a safe margin below New Relic's 1 MB per-request ingest limit.
	DefaultMaxCompressedBytes = 900_000
)

// Config holds configuration for the nrsizeawarebatch processor.
type Config struct {
	// MaxCompressedBytes is the maximum gzip-compressed proto size (in bytes)
	// allowed per sub-batch. Sub-batches exceeding this are split further.
	// Defaults to 900000 (900 KB). A single record that alone exceeds this
	// threshold is emitted alone and never dropped.
	MaxCompressedBytes int `mapstructure:"max_compressed_bytes"`

	// EventNames is the list of log event names to apply size-aware splitting
	// to. Records whose event name is NOT in this list are forwarded to the
	// downstream consumer unchanged (no compression measurement overhead).
	// An empty list means ALL log records go through size-aware splitting.
	EventNames []string `mapstructure:"event_names"`
}

func createDefaultConfig() Config {
	return Config{
		MaxCompressedBytes: DefaultMaxCompressedBytes,
		EventNames:         []string{},
	}
}

func (c *Config) Validate() error {
	if c.MaxCompressedBytes <= 0 {
		return errors.New("max_compressed_bytes must be greater than 0")
	}
	return nil
}
