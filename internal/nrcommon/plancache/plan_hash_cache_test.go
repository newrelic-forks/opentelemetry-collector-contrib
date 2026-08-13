// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package plancache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestShouldEmit_FirstCallEmits(t *testing.T) {
	c := New(time.Hour)
	defer c.Stop()
	assert.True(t, c.ShouldEmit("abc123"))
}

func TestShouldEmit_SecondCallWithinTTLSkips(t *testing.T) {
	c := New(time.Hour)
	defer c.Stop()
	c.ShouldEmit("abc123")
	assert.False(t, c.ShouldEmit("abc123"))
}

func TestShouldEmit_DifferentHashesAreIndependent(t *testing.T) {
	c := New(time.Hour)
	defer c.Stop()
	assert.True(t, c.ShouldEmit("hash1"))
	assert.True(t, c.ShouldEmit("hash2"))
	assert.False(t, c.ShouldEmit("hash1"))
	assert.False(t, c.ShouldEmit("hash2"))
}

func TestShouldEmit_EmitAfterTTLExpiry(t *testing.T) {
	c := New(50 * time.Millisecond)
	defer c.Stop()
	assert.True(t, c.ShouldEmit("abc123"))
	assert.False(t, c.ShouldEmit("abc123"))
	time.Sleep(100 * time.Millisecond)
	assert.True(t, c.ShouldEmit("abc123"), "should re-emit after TTL expiry")
}

func TestShouldEmit_EmptyHashAlwaysEmits(t *testing.T) {
	c := New(time.Hour)
	defer c.Stop()
	assert.True(t, c.ShouldEmit(""))
	assert.True(t, c.ShouldEmit(""))
}

func TestShouldEmit_ZeroTTLDisablesDedup(t *testing.T) {
	c := New(0)
	defer c.Stop()
	assert.True(t, c.ShouldEmit("abc123"))
	assert.True(t, c.ShouldEmit("abc123"), "zero TTL means dedup is disabled")
}

func TestShouldEmit_TTLNotExtendedOnRead(t *testing.T) {
	// WithDisableTouchOnHit: reading should NOT extend the TTL.
	c := New(80 * time.Millisecond)
	defer c.Stop()
	c.ShouldEmit("abc123")
	// Read repeatedly — should not extend TTL
	for i := 0; i < 5; i++ {
		c.ShouldEmit("abc123")
		time.Sleep(10 * time.Millisecond)
	}
	// After ~50ms total, if reads extended TTL entry would still be live.
	// After 80ms from Set, entry should be expired regardless of reads.
	time.Sleep(40 * time.Millisecond) // total ~90ms from Set
	assert.True(t, c.ShouldEmit("abc123"), "TTL should not be extended by reads")
}
