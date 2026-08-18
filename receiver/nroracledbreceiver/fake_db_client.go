// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nroracledbreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nroracledbreceiver"

import (
	"context"
)

type fakeDbClient struct {
	Err            error
	Responses      [][]metricRow
	RequestCounter int
}

func (c *fakeDbClient) metricRows(context.Context, ...any) ([]metricRow, error) {
	if c.Err != nil {
		return nil, c.Err
	}
	idx := c.RequestCounter
	c.RequestCounter++
	return c.Responses[idx], nil
}
