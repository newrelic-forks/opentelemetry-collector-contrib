// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsizeawarebatchprocessor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
)

// makeLogsWithEvent creates a plog.Logs with n records, each with the given
// event name and a body of bodyBytes zeros.
func makeLogsWithEvent(n int, eventName string, bodyBytes int) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("host.name", "sql-server-01")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("nrsqlserver")
	for i := 0; i < n; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetEventName(eventName)
		lr.Body().SetStr(string(make([]byte, bodyBytes)))
	}
	return ld
}

// makeMixedLogs creates a plog.Logs with both top_query and query_plan records.
func makeMixedLogs(nTop, nPlan int) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("host.name", "sql-server-01")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("nrsqlserver")
	for i := 0; i < nTop; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetEventName("db.server.top_query")
		lr.Body().SetStr("top query record")
	}
	for i := 0; i < nPlan; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetEventName("db.server.query_plan")
		lr.Body().SetStr("plan node record")
	}
	return ld
}

func TestProcessor_AllRecordsForwardedWithNoFilter(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{MaxCompressedBytes: DefaultMaxCompressedBytes, EventNames: []string{}}
	proc := newProcessor(cfg, sink)

	ld := makeLogsWithEvent(10, "db.server.query_plan", 100)
	require.NoError(t, proc.ConsumeLogs(context.Background(), ld))
	assert.Equal(t, 10, sink.LogRecordCount())
}

func TestProcessor_FilteredEventsGetSplit(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{
		MaxCompressedBytes: 1, // force every record into its own batch
		EventNames:         []string{"db.server.query_plan"},
	}
	proc := newProcessor(cfg, sink)

	ld := makeLogsWithEvent(5, "db.server.query_plan", 100)
	require.NoError(t, proc.ConsumeLogs(context.Background(), ld))

	assert.Equal(t, 5, sink.LogRecordCount(), "all records must arrive")
	assert.Len(t, sink.AllLogs(), 5, "each record should be its own ConsumeLogs call")
}

func TestProcessor_UnfilteredEventsPassThroughDirectly(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{
		MaxCompressedBytes: 1, // would split if applied
		EventNames:         []string{"db.server.query_plan"},
	}
	proc := newProcessor(cfg, sink)

	// top_query is NOT in EventNames — must pass through in ONE call, not split
	ld := makeLogsWithEvent(5, "db.server.top_query", 100)
	require.NoError(t, proc.ConsumeLogs(context.Background(), ld))

	assert.Equal(t, 5, sink.LogRecordCount())
	assert.Len(t, sink.AllLogs(), 1, "pass-through records must arrive in a single ConsumeLogs call")
}

func TestProcessor_MixedEvents_PlanSplitTopQueryPassThrough(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{
		MaxCompressedBytes: 1, // force split on query_plan
		EventNames:         []string{"db.server.query_plan"},
	}
	proc := newProcessor(cfg, sink)

	ld := makeMixedLogs(3 /* top_query */, 4 /* query_plan */)
	require.NoError(t, proc.ConsumeLogs(context.Background(), ld))

	assert.Equal(t, 7, sink.LogRecordCount(), "all 7 records must arrive")
	// 1 call for top_query pass-through + 4 calls for query_plan (one per record)
	assert.Len(t, sink.AllLogs(), 5)
}

func TestProcessor_OversizedSingleRecordEmittedAlone(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{
		MaxCompressedBytes: 1,
		EventNames:         []string{"db.server.query_plan"},
	}
	proc := newProcessor(cfg, sink)

	ld := makeLogsWithEvent(1, "db.server.query_plan", 500_000)
	require.NoError(t, proc.ConsumeLogs(context.Background(), ld))

	assert.Equal(t, 1, sink.LogRecordCount(), "oversized single record must not be dropped")
}

func TestProcessor_AllFitInOneBatch(t *testing.T) {
	sink := new(consumertest.LogsSink)
	cfg := &Config{
		MaxCompressedBytes: DefaultMaxCompressedBytes,
		EventNames:         []string{"db.server.query_plan"},
	}
	proc := newProcessor(cfg, sink)

	ld := makeLogsWithEvent(10, "db.server.query_plan", 100)
	require.NoError(t, proc.ConsumeLogs(context.Background(), ld))

	assert.Equal(t, 10, sink.LogRecordCount())
	assert.Len(t, sink.AllLogs(), 1, "all small records should fit in one batch")
}

func TestConfig_Validate(t *testing.T) {
	assert.NoError(t, (&Config{MaxCompressedBytes: 900_000}).Validate())
	assert.Error(t, (&Config{MaxCompressedBytes: 0}).Validate())
	assert.Error(t, (&Config{MaxCompressedBytes: -1}).Validate())
}

func TestFactory_CreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	require.NotNil(t, cfg)
	processorCfg := cfg.(*Config)
	assert.Equal(t, DefaultMaxCompressedBytes, processorCfg.MaxCompressedBytes)
	assert.Empty(t, processorCfg.EventNames)
}

func TestFactory_CreateLogsProcessor(t *testing.T) {
	factory := NewFactory()
	sink := new(consumertest.LogsSink)
	set := processor.Settings{}
	set.ID = component.NewID(component.MustNewType(typeStr))
	proc, err := factory.CreateLogs(context.Background(), set, factory.CreateDefaultConfig(), sink)
	require.NoError(t, err)
	require.NotNil(t, proc)
}
