// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver"

import (
	"context"
	"errors"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

// metricsChild is the subset of *sqlServerScraperHelper that the dispatcher
// needs. Declared as an interface so unit tests can substitute fakes without
// requiring a live SQL Server connection.
type metricsChild interface {
	Start(ctx context.Context, host component.Host) error
	Shutdown(ctx context.Context) error
	ScrapeMetrics(ctx context.Context) (pmetric.Metrics, error)
}

// concurrentMetricsScraper fans out a set of metric scraping queries across a
// bounded goroutine pool. Each child still owns its own query, sql.DB pool,
// and MetricsBuilder; this type only orchestrates concurrent execution and
// result aggregation.
type concurrentMetricsScraper struct {
	children    []metricsChild
	maxInFlight int
	logger      *zap.Logger
}

func newConcurrentMetricsScraper(children []*sqlServerScraperHelper, maxInFlight int, logger *zap.Logger) *concurrentMetricsScraper {
	wrapped := make([]metricsChild, len(children))
	for i, c := range children {
		wrapped[i] = c
	}
	return newConcurrentMetricsScraperFromChildren(wrapped, maxInFlight, logger)
}

func newConcurrentMetricsScraperFromChildren(children []metricsChild, maxInFlight int, logger *zap.Logger) *concurrentMetricsScraper {
	if maxInFlight < 1 {
		maxInFlight = 1
	}
	return &concurrentMetricsScraper{
		children:    children,
		maxInFlight: maxInFlight,
		logger:      logger,
	}
}

// Start opens each child scraper's database connection. Done serially because
// failures here mean a misconfiguration the user needs to see; parallelism
// would just race the error logs.
func (c *concurrentMetricsScraper) Start(ctx context.Context, host component.Host) error {
	var errs []error
	for _, ch := range c.children {
		if err := ch.Start(ctx, host); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Shutdown closes each child's database connection. Errors are joined and
// returned together so we never abandon a connection due to a sibling failure.
func (c *concurrentMetricsScraper) Shutdown(ctx context.Context) error {
	var errs []error
	for _, ch := range c.children {
		if err := ch.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ScrapeMetrics runs every child scraper concurrently with a semaphore cap.
// Per-child errors are aggregated; the returned Metrics merges all successful
// child results. Matches the upstream scraperhelper contract of partial
// results plus joined errors.
func (c *concurrentMetricsScraper) ScrapeMetrics(ctx context.Context) (pmetric.Metrics, error) {
	type childResult struct {
		md  pmetric.Metrics
		ok  bool
		err error
	}
	results := make([]childResult, len(c.children))

	sem := make(chan struct{}, c.maxInFlight)
	var wg sync.WaitGroup
	for i, child := range c.children {
		wg.Add(1)
		go func(idx int, s metricsChild) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx] = childResult{err: ctx.Err()}
				return
			}
			defer func() { <-sem }()

			md, err := s.ScrapeMetrics(ctx)
			results[idx] = childResult{md: md, ok: err == nil, err: err}
		}(i, child)
	}
	wg.Wait()

	merged := pmetric.NewMetrics()
	var errs []error
	for _, r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
		}
		if r.ok {
			r.md.ResourceMetrics().MoveAndAppendTo(merged.ResourceMetrics())
		}
	}

	return merged, errors.Join(errs...)
}
