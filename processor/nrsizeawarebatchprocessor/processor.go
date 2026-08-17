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

// --- size-aware split logic ---

// splitByCompressedSize splits ld into sub-batches where each sub-batch's
// gzip-compressed proto size does not exceed maxBytes.
// A single record that alone exceeds maxBytes is emitted in its own batch
// rather than being dropped.
func splitByCompressedSize(ld plog.Logs, maxBytes int) []plog.Logs {
	type entry struct {
		resource pcommon.Resource
		scope    pcommon.InstrumentationScope
		record   plog.LogRecord
	}

	var flat []entry
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		rl := rls.At(i)
		for j := 0; j < rl.ScopeLogs().Len(); j++ {
			sl := rl.ScopeLogs().At(j)
			for k := 0; k < sl.LogRecords().Len(); k++ {
				flat = append(flat, entry{rl.Resource(), sl.Scope(), sl.LogRecords().At(k)})
			}
		}
	}
	if len(flat) == 0 {
		return nil
	}

	var batches []plog.Logs
	current := plog.NewLogs()

	for _, e := range flat {
		candidate := plog.NewLogs()
		current.CopyTo(candidate)
		appendLogRecord(candidate, e.resource, e.scope, e.record)

		size := compressedProtoSize(candidate)

		if size <= maxBytes || current.LogRecordCount() == 0 {
			current = candidate
		} else {
			batches = append(batches, current)
			current = plog.NewLogs()
			appendLogRecord(current, e.resource, e.scope, e.record)
		}
	}

	if current.LogRecordCount() > 0 {
		batches = append(batches, current)
	}
	return batches
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
