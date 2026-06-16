// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package nrsqlserverreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver"

func (*Config) validateInstanceAndComputerName() error {
	return nil
}
