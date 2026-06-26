// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

// fakeChild is a controllable metricsChild for unit testing the dispatcher.
type fakeChild struct {
	startErr    error
	shutdownErr error
	scrapeErr   error

	// resourceName lets each child produce a uniquely-identifiable
	// ResourceMetrics entry so merge order can be verified.
	resourceName string

	// delay sleeps inside ScrapeMetrics so we can observe concurrency.
	delay time.Duration

	// liveCounter tracks the number of in-flight ScrapeMetrics calls.
	liveCounter *atomic.Int32
	// peakLive records the high-water mark of liveCounter.
	peakLive *atomic.Int32

	startCalls    atomic.Int32
	shutdownCalls atomic.Int32
	scrapeCalls   atomic.Int32
}

func (f *fakeChild) Start(context.Context, component.Host) error {
	f.startCalls.Add(1)
	return f.startErr
}

func (f *fakeChild) Shutdown(context.Context) error {
	f.shutdownCalls.Add(1)
	return f.shutdownErr
}

func (f *fakeChild) ScrapeMetrics(ctx context.Context) (pmetric.Metrics, error) {
	f.scrapeCalls.Add(1)
	if f.liveCounter != nil {
		now := f.liveCounter.Add(1)
		if f.peakLive != nil {
			for {
				prev := f.peakLive.Load()
				if now <= prev {
					break
				}
				if f.peakLive.CompareAndSwap(prev, now) {
					break
				}
			}
		}
		defer f.liveCounter.Add(-1)
	}

	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return pmetric.Metrics{}, ctx.Err()
		case <-time.After(f.delay):
		}
	}

	if f.scrapeErr != nil {
		return pmetric.Metrics{}, f.scrapeErr
	}

	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("child.name", f.resourceName)
	return md, nil
}

func dispatcher(t *testing.T, maxInFlight int, children ...metricsChild) *concurrentMetricsScraper {
	t.Helper()
	return newConcurrentMetricsScraperFromChildren(children, maxInFlight, zap.NewNop())
}

func TestConcurrentMetricsScraper_MergesAllSuccessfulResults(t *testing.T) {
	a := &fakeChild{resourceName: "a"}
	b := &fakeChild{resourceName: "b"}
	c := &fakeChild{resourceName: "c"}
	d := dispatcher(t, 2, a, b, c)

	md, err := d.ScrapeMetrics(t.Context())
	require.NoError(t, err)
	require.Equal(t, 3, md.ResourceMetrics().Len())

	seen := map[string]bool{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		v, ok := md.ResourceMetrics().At(i).Resource().Attributes().Get("child.name")
		require.True(t, ok)
		seen[v.AsString()] = true
	}
	assert.Equal(t, map[string]bool{"a": true, "b": true, "c": true}, seen)
}

func TestConcurrentMetricsScraper_PartialFailuresProduceJoinedErrors(t *testing.T) {
	errA := errors.New("a failed")
	errC := errors.New("c failed")
	a := &fakeChild{resourceName: "a", scrapeErr: errA}
	b := &fakeChild{resourceName: "b"}
	c := &fakeChild{resourceName: "c", scrapeErr: errC}

	d := dispatcher(t, 4, a, b, c)
	md, err := d.ScrapeMetrics(t.Context())

	require.Error(t, err)
	assert.ErrorIs(t, err, errA)
	assert.ErrorIs(t, err, errC)
	require.Equal(t, 1, md.ResourceMetrics().Len())
	v, _ := md.ResourceMetrics().At(0).Resource().Attributes().Get("child.name")
	assert.Equal(t, "b", v.AsString())
}

func TestConcurrentMetricsScraper_RespectsSemaphoreCap(t *testing.T) {
	live := &atomic.Int32{}
	peak := &atomic.Int32{}

	const numChildren = 8
	const maxInFlight = 3
	children := make([]metricsChild, numChildren)
	for i := range children {
		children[i] = &fakeChild{
			resourceName: "c",
			delay:        50 * time.Millisecond,
			liveCounter:  live,
			peakLive:     peak,
		}
	}

	d := dispatcher(t, maxInFlight, children...)
	_, err := d.ScrapeMetrics(t.Context())
	require.NoError(t, err)
	assert.LessOrEqual(t, peak.Load(), int32(maxInFlight), "peak in-flight should never exceed cap")
	assert.Greater(t, peak.Load(), int32(1), "with delay we expect at least some concurrency")
}

func TestConcurrentMetricsScraper_RunsChildrenInParallel(t *testing.T) {
	const numChildren = 4
	const delay = 50 * time.Millisecond
	children := make([]metricsChild, numChildren)
	for i := range children {
		children[i] = &fakeChild{resourceName: "p", delay: delay}
	}

	start := time.Now()
	d := dispatcher(t, numChildren, children...)
	_, err := d.ScrapeMetrics(t.Context())
	require.NoError(t, err)

	elapsed := time.Since(start)
	assert.Less(t, elapsed, time.Duration(numChildren)*delay-10*time.Millisecond,
		"expected parallel execution to finish well under the sequential time")
}

func TestConcurrentMetricsScraper_ContextCancellation(t *testing.T) {
	const numChildren = 6
	children := make([]metricsChild, numChildren)
	for i := range children {
		children[i] = &fakeChild{resourceName: "x", delay: 200 * time.Millisecond}
	}

	d := dispatcher(t, 2, children...)
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_, err := d.ScrapeMetrics(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestConcurrentMetricsScraper_StartAndShutdownAggregateErrors(t *testing.T) {
	errStartB := errors.New("start b")
	errShutA := errors.New("shutdown a")

	a := &fakeChild{shutdownErr: errShutA}
	b := &fakeChild{startErr: errStartB}
	c := &fakeChild{}

	d := dispatcher(t, 4, a, b, c)
	err := d.Start(t.Context(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errStartB)
	assert.Equal(t, int32(1), a.startCalls.Load())
	assert.Equal(t, int32(1), b.startCalls.Load())
	assert.Equal(t, int32(1), c.startCalls.Load())

	err = d.Shutdown(t.Context())
	require.Error(t, err)
	assert.ErrorIs(t, err, errShutA)
}

func TestConcurrentMetricsScraper_ZeroCapIsClampedToOne(t *testing.T) {
	const n = 3
	live := &atomic.Int32{}
	peak := &atomic.Int32{}
	children := make([]metricsChild, n)
	for i := range children {
		children[i] = &fakeChild{
			resourceName: "z",
			delay:        20 * time.Millisecond,
			liveCounter:  live,
			peakLive:     peak,
		}
	}

	d := dispatcher(t, 0, children...)
	md, err := d.ScrapeMetrics(t.Context())
	require.NoError(t, err)
	assert.Equal(t, n, md.ResourceMetrics().Len())
	assert.Equal(t, int32(1), peak.Load(), "cap=0 must be clamped so only one child runs at a time")
}

func TestNewConcurrentMetricsScraper_AcceptsHelperSlice(t *testing.T) {
	var children []*sqlServerScraperHelper
	d := newConcurrentMetricsScraper(children, 4, zap.NewNop())
	require.NotNil(t, d)
	require.Empty(t, d.children)
	_ = sync.Mutex{}
}
