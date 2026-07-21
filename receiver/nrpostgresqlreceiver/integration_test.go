// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package nrpostgresqlreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrpostgresqlreceiver"

// NOTE: The upstream postgresqlreceiver integration test uses the base
// internal/coreinternal/scraperinttest and internal/common/testutil helpers,
// which the newrelic-forks receivers intentionally do not depend on. This file
// is a placeholder for the scaffold (NR-596382); a testcontainers-go based
// integration test — mirroring receiver/nrsqlserverreceiver/integration_test.go —
// is added in NR-596383.
