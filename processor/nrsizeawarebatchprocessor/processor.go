// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsizeawarebatchprocessor // import "github.com/newrelic-forks/opentelemetry-collector-contrib/processor/nrsizeawarebatchprocessor"

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

// sizeAwareBatchProcessor implements processor.Logs. It splits incoming log
// batches into sub-batches whose gzip-compressed proto size stays below
// config.MaxCompressedBytes before forwarding to the next consumer.
//
// If config.EventNames is non-empty, only records with a matching event name
// are subject to size-aware splitting. All other records are forwarded in a
// single pass-through call to avoid unnecessary compression overhead.
type sizeAwareBatchProcessor struct {
	config     *Config
	next       consumer.Logs
	eventNames map[string]struct{} // empty map = apply to all events
}

func newProcessor(cfg *Config, next consumer.Logs) *sizeAwareBatchProcessor {
	names := make(map[string]struct{}, len(cfg.EventNames))
	for _, n := range cfg.EventNames {
		names[n] = struct{}{}
	}
	return &sizeAwareBatchProcessor{
		config:     cfg,
		next:       next,
		eventNames: names,
	}
}

func (p *sizeAwareBatchProcessor) Start(context.Context, component.Host) error { return nil }
func (p *sizeAwareBatchProcessor) Shutdown(context.Context) error               { return nil }

func (p *sizeAwareBatchProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeLogs splits ld into:
//   - passthrough: records NOT in the event name filter → forwarded in one call
//   - size-aware:  records IN the filter → split into ≤MaxCompressedBytes batches
func (p *sizeAwareBatchProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	if len(p.eventNames) == 0 {
		// No filter: apply size-aware splitting to everything.
		return p.sendSplit(ctx, ld)
	}

	passthrough, filtered := p.partitionByEventName(ld)

	var errs []error

	if passthrough.LogRecordCount() > 0 {
		if err := p.next.ConsumeLogs(ctx, passthrough); err != nil {
			errs = append(errs, err)
		}
	}

	if filtered.LogRecordCount() > 0 {
		if err := p.sendSplit(ctx, filtered); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// sendSplit splits ld into size-bounded sub-batches and forwards each.
func (p *sizeAwareBatchProcessor) sendSplit(ctx context.Context, ld plog.Logs) error {
	batches := splitByCompressedSize(ld, p.config.MaxCompressedBytes)
	var errs []error
	for _, batch := range batches {
		if err := p.next.ConsumeLogs(ctx, batch); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// partitionByEventName separates ld into two plog.Logs:
// passthrough = records NOT in p.eventNames
// filtered    = records IN p.eventNames
func (p *sizeAwareBatchProcessor) partitionByEventName(ld plog.Logs) (passthrough plog.Logs, filtered plog.Logs) {
	passthrough = plog.NewLogs()
	filtered = plog.NewLogs()

	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				lr := sl.LogRecords().At(k)
				_, inFilter := p.eventNames[lr.EventName()]
				if inFilter {
					appendLogRecord(filtered, rl.Resource(), sl.Scope(), lr)
				} else {
					appendLogRecord(passthrough, rl.Resource(), sl.Scope(), lr)
				}
			}
		}
	}
	return passthrough, filtered
}

// --- size-aware split logic (divide and conquer) ---

// planEntry is a flattened log record with its parent resource and scope.
type planEntry struct {
	resource pcommon.Resource
	scope    pcommon.InstrumentationScope
	record   plog.LogRecord
}

// splitByCompressedSize splits ld into sub-batches whose gzip-compressed proto
// size does not exceed maxBytes using a divide-and-conquer strategy:
//
//  1. Check if the whole batch fits → if yes, return immediately (1 measurement).
//  2. If not, split records in half and recurse on each half independently.
//  3. A single record that alone exceeds maxBytes is emitted alone — never dropped.
//
// This is far more efficient than the greedy per-record approach:
//   - Happy path (all fit): 1 measurement regardless of record count.
//   - Splits into K batches: O(K × log(N/K)) measurements instead of O(N).
func splitByCompressedSize(ld plog.Logs, maxBytes int) []plog.Logs {
	if ld.LogRecordCount() == 0 {
		return nil
	}

	// Fast path: entire batch fits — most common case after dedup is active.
	if compressedProtoSize(ld) <= maxBytes {
		return []plog.Logs{ld}
	}

	// Batch too large — flatten records and divide-and-conquer.
	var flat []planEntry
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				flat = append(flat, planEntry{rl.Resource(), sl.Scope(), sl.LogRecords().At(k)})
			}
		}
	}

	return divideAndSplit(flat, maxBytes)
}

// divideAndSplit recursively splits a flat record slice into sub-batches that
// each fit within maxBytes when gzip-compressed.
func divideAndSplit(records []planEntry, maxBytes int) []plog.Logs {
	if len(records) == 0 {
		return nil
	}

	// Build a plog.Logs from this slice and measure it.
	batch := buildBatch(records)

	// Fits within limit, or it is a single record that cannot be split further
	// (emit alone rather than dropping it).
	if compressedProtoSize(batch) <= maxBytes || len(records) == 1 {
		return []plog.Logs{batch}
	}

	// Too large — split in half and recurse on each half independently.
	mid := len(records) / 2
	left := divideAndSplit(records[:mid], maxBytes)
	right := divideAndSplit(records[mid:], maxBytes)
	return append(left, right...)
}

// buildBatch assembles a plog.Logs from a flat slice of planEntry records.
func buildBatch(records []planEntry) plog.Logs {
	batch := plog.NewLogs()
	for _, e := range records {
		appendLogRecord(batch, e.resource, e.scope, e.record)
	}
	return batch
}

// appendLogRecord copies record into dest under the matching resource+scope,
// creating ResourceLogs and ScopeLogs entries if they do not already exist.
func appendLogRecord(dest plog.Logs, resource pcommon.Resource, scope pcommon.InstrumentationScope, record plog.LogRecord) {
	resourceKey := attrMapKey(resource.Attributes())

	var targetRL plog.ResourceLogs
	found := false
	for i := 0; i < dest.ResourceLogs().Len(); i++ {
		rl := dest.ResourceLogs().At(i)
		if attrMapKey(rl.Resource().Attributes()) == resourceKey {
			targetRL = rl
			found = true
			break
		}
	}
	if !found {
		targetRL = dest.ResourceLogs().AppendEmpty()
		resource.CopyTo(targetRL.Resource())
	}

	scopeKey := scope.Name() + "/" + scope.Version() + "/" + attrMapKey(scope.Attributes())
	var targetSL plog.ScopeLogs
	found = false
	for j := 0; j < targetRL.ScopeLogs().Len(); j++ {
		sl := targetRL.ScopeLogs().At(j)
		if sl.Scope().Name()+"/"+sl.Scope().Version()+"/"+attrMapKey(sl.Scope().Attributes()) == scopeKey {
			targetSL = sl
			found = true
			break
		}
	}
	if !found {
		targetSL = targetRL.ScopeLogs().AppendEmpty()
		scope.CopyTo(targetSL.Scope())
	}

	newRecord := targetSL.LogRecords().AppendEmpty()
	record.CopyTo(newRecord)
}

// compressedProtoSize serializes ld as an OTLP proto export request, gzip-compresses
// it, and returns the byte count — the same measurement the OTLP exporter produces.
func compressedProtoSize(ld plog.Logs) int {
	req := plogotlp.NewExportRequestFromLogs(ld)
	b, err := req.MarshalProto()
	if err != nil {
		return 0
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Len()
}

// attrMapKey produces a deterministic string fingerprint of an attribute map.
func attrMapKey(attrs pcommon.Map) string {
	type kv struct{ k, v string }
	pairs := make([]kv, 0, attrs.Len())
	attrs.Range(func(k string, v pcommon.Value) bool {
		pairs = append(pairs, kv{k, v.AsString()})
		return true
	})
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p.k)
		sb.WriteByte('=')
		sb.WriteString(p.v)
		sb.WriteByte(';')
	}
	return sb.String()
}
