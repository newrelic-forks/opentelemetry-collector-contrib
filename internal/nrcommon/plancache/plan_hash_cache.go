// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package plancache provides TTL-based deduplication of database execution
// plan emissions. It is shared across all NR DB receivers (SQL Server, Oracle,
// PostgreSQL) so that each only emits a plan when its hash is new or the TTL
// has expired, rather than on every scrape cycle.
package plancache // import "github.com/newrelic-forks/opentelemetry-collector-contrib/internal/nrcommon/plancache"

import (
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// Cache deduplicates execution plan emissions by plan hash.
// A plan is suppressed while its hash is present in the cache (within the TTL
// window). After expiry the plan is re-emitted, keeping it queryable in NR.
type Cache struct {
	inner *ttlcache.Cache[string, struct{}]
	ttl   time.Duration
}

// New creates a Cache with the given TTL.
// TTL of 0 disables deduplication — ShouldEmit always returns true.
//
// ttlcache.Get checks expiry on every access, so the cache is correct without
// a background cleanup goroutine. Expired entries remain in memory until
// overwritten, which is acceptable given the bounded key space (unique plan
// hashes per instance). Call Stop if you explicitly Start the inner cache.
func New(ttl time.Duration) *Cache {
	c := &Cache{ttl: ttl}
	if ttl > 0 {
		c.inner = ttlcache.New[string, struct{}](
			// DisableTouchOnHit: TTL is fixed from Set time; reads do not extend it.
			// Without this, an active query scraped every 60s would never re-emit.
			ttlcache.WithDisableTouchOnHit[string, struct{}](),
		)
	}
	return c
}

// ShouldEmit returns true when the plan for planHash should be emitted —
// either because this hash has never been seen, or because the TTL has expired.
// On a cache miss it stamps the hash so subsequent calls within the TTL return false.
// An empty planHash always returns true without updating the cache.
func (c *Cache) ShouldEmit(planHash string) bool {
	if planHash == "" {
		return true
	}
	if c.ttl == 0 {
		return true
	}
	if c.inner.Get(planHash) != nil {
		return false
	}
	c.inner.Set(planHash, struct{}{}, c.ttl)
	return true
}

// Stop is a no-op retained for forward compatibility. If the inner cache's
// background goroutine is ever started explicitly, this will stop it cleanly.
func (c *Cache) Stop() {
	if c.inner != nil {
		c.inner.Stop()
	}
}
