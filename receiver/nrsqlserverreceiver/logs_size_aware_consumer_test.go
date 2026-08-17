// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// makeTestLogs creates a plog.Logs with n records, each with a body of the given size.
func makeTestLogs(n, bodyBytes int) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("host.name", "test-host")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("nrsqlserver")
	for i := 0; i < n; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr(string(make([]byte, bodyBytes)))
		lr.Attributes().PutStr("sqlserver.node_id", "1")
	}
	return ld
}

func TestSplitByCompressedSize_EmptyInput(t *testing.T) {
	batches := splitByCompressedSize(plog.NewLogs(), defaultMaxCompressedBytes)
	assert.Empty(t, batches)
}

func TestSplitByCompressedSize_AllRecordsFitInOneBatch(t *testing.T) {
	ld := makeTestLogs(5, 100)
	batches := splitByCompressedSize(ld, defaultMaxCompressedBytes)
	require.Len(t, batches, 1)
	assert.Equal(t, 5, batches[0].LogRecordCount())
}

func TestSplitByCompressedSize_SplitsWhenLimitExceeded(t *testing.T) {
	// Limit of 1 byte forces every record into its own batch
	// (single record always emitted alone even if oversized).
	ld := makeTestLogs(5, 100)
	batches := splitByCompressedSize(ld, 1)
	assert.Len(t, batches, 5)

	total := 0
	for _, b := range batches {
		total += b.LogRecordCount()
	}
	assert.Equal(t, 5, total, "all records must arrive across batches")
}

func TestSplitByCompressedSize_OversizedSingleRecordEmittedAlone(t *testing.T) {
	// A single record larger than the limit must still be emitted, not dropped.
	ld := makeTestLogs(1, 500_000)
	batches := splitByCompressedSize(ld, 1)
	require.Len(t, batches, 1)
	assert.Equal(t, 1, batches[0].LogRecordCount())
}

func TestSplitByCompressedSize_PreservesResourceAndScope(t *testing.T) {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("host.name", "sql-host")
	rl.Resource().Attributes().PutStr("server.address", "10.0.0.1")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("nrsqlserver")
	sl.Scope().SetVersion("1.0")
	for i := 0; i < 3; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.Body().SetStr("plan node record")
	}

	batches := splitByCompressedSize(ld, defaultMaxCompressedBytes)
	require.Len(t, batches, 1)

	outRL := batches[0].ResourceLogs().At(0)
	hostVal, ok := outRL.Resource().Attributes().Get("host.name")
	assert.True(t, ok)
	assert.Equal(t, "sql-host", hostVal.AsString())
	assert.Equal(t, "nrsqlserver", outRL.ScopeLogs().At(0).Scope().Name())
	assert.Equal(t, 3, outRL.ScopeLogs().At(0).LogRecords().Len())
}

func TestSplitByCompressedSize_EachBatchUnderLimit(t *testing.T) {
	ld := makeTestLogs(10, 100)
	limit := defaultMaxCompressedBytes
	batches := splitByCompressedSize(ld, limit)

	for i, b := range batches {
		size := compressedProtoSize(b)
		if b.LogRecordCount() > 1 {
			assert.LessOrEqual(t, size, limit, "batch %d exceeds limit", i)
		}
	}
}

func TestSizeAwareBatchConsumer_ForwardsAllRecordsDownstream(t *testing.T) {
	sink := new(consumertest.LogsSink)
	c := newSizeAwareBatchConsumer(sink, defaultMaxCompressedBytes)

	ld := makeTestLogs(10, 100)
	require.NoError(t, c.ConsumeLogs(context.Background(), ld))

	assert.Equal(t, 10, sink.LogRecordCount())
}

func TestSizeAwareBatchConsumer_SplitsIntoMultipleConsumeLogsCalls(t *testing.T) {
	sink := new(consumertest.LogsSink)
	// Limit of 1 → every record forces its own ConsumeLogs call.
	c := newSizeAwareBatchConsumer(sink, 1)

	ld := makeTestLogs(5, 100)
	require.NoError(t, c.ConsumeLogs(context.Background(), ld))

	assert.Len(t, sink.AllLogs(), 5, "each record should produce a separate ConsumeLogs call")
	assert.Equal(t, 5, sink.LogRecordCount())
}

func TestSizeAwareBatchConsumer_Capabilities(t *testing.T) {
	sink := &capsSink{caps: consumer.Capabilities{MutatesData: true}}
	c := newSizeAwareBatchConsumer(sink, defaultMaxCompressedBytes)
	assert.True(t, c.Capabilities().MutatesData)
}

func TestSizeAwareBatchConsumer_ZeroLimitUsesDefault(t *testing.T) {
	sink := new(consumertest.LogsSink)
	c := newSizeAwareBatchConsumer(sink, 0)
	assert.Equal(t, defaultMaxCompressedBytes, c.(*sizeAwareBatchConsumer).maxCompressedBytes)
}

func TestAttrMapKey_DeterministicRegardlessOfInsertOrder(t *testing.T) {
	m1 := pcommon.NewMap()
	m1.PutStr("b", "2")
	m1.PutStr("a", "1")

	m2 := pcommon.NewMap()
	m2.PutStr("a", "1")
	m2.PutStr("b", "2")

	assert.Equal(t, attrMapKey(m1), attrMapKey(m2))
}

func TestAttrMapKey_DifferentAttributesProduceDifferentKeys(t *testing.T) {
	m1 := pcommon.NewMap()
	m1.PutStr("host.name", "host-a")

	m2 := pcommon.NewMap()
	m2.PutStr("host.name", "host-b")

	assert.NotEqual(t, attrMapKey(m1), attrMapKey(m2))
}

// capsSink is a minimal consumer.Logs that reports fixed Capabilities.
type capsSink struct{ caps consumer.Capabilities }

func (cs *capsSink) Capabilities() consumer.Capabilities              { return cs.caps }
func (cs *capsSink) ConsumeLogs(_ context.Context, _ plog.Logs) error { return nil }
