// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package nrsizeawarebatchprocessor provides a processor that splits log
// batches by gzip-compressed size rather than record count, preventing
// HTTP 413 errors when individual records are large.
package nrsizeawarebatchprocessor // import "github.com/newrelic-forks/opentelemetry-collector-contrib/processor/nrsizeawarebatchprocessor"
