// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package nrsqlserverreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver"

import "errors"

func (cfg *Config) validateInstanceAndComputerName() error {
	if cfg.InstanceName != "" && cfg.ComputerName == "" {
		return errors.New("'instance_name' may not be specified without 'computer_name'")
	}
	if cfg.InstanceName == "" && cfg.ComputerName != "" {
		return errors.New("'computer_name' may not be specified without 'instance_name'")
	}

	return nil
}
