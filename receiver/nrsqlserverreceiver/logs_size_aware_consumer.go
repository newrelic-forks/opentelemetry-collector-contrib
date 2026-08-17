// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver"

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

// defaultMaxCompressedBytes is the threshold used when splitting batches.
// Set to 900 KB — a safe margin below New Relic's 1 MB per-request limit.
const defaultMaxCompressedBytes = 900_000

// sizeAwareBatchConsumer wraps a downstream consumer.Logs and splits incoming
// batches so that each sub-batch's gzip-compressed proto size stays below
// maxCompressedBytes before forwarding to the downstream consumer.
//
// This prevents HTTP 413 (Payload Too Large) from the New Relic OTLP ingest
// endpoint when a scrape produces many large db.server.query_plan records.
type sizeAwareBatchConsumer struct {
	next               consumer.Logs
	maxCompressedBytes int
}

func newSizeAwareBatchConsumer(next consumer.Logs, maxCompressedBytes int) consumer.Logs {
	if maxCompressedBytes <= 0 {
		maxCompressedBytes = defaultMaxCompressedBytes
	}
	return &sizeAwareBatchConsumer{next: next, maxCompressedBytes: maxCompressedBytes}
}

func (s *sizeAwareBatchConsumer) Capabilities() consumer.Capabilities {
	return s.next.Capabilities()
}

// ConsumeLogs splits ld into size-bounded sub-batches and forwards each to the
// downstream consumer. All sub-batches are attempted even if one returns an error.
func (s *sizeAwareBatchConsumer) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	batches := splitByCompressedSize(ld, s.maxCompressedBytes)
	var errs []error
	for _, batch := range batches {
		if err := s.next.ConsumeLogs(ctx, batch); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// splitByCompressedSize splits ld into sub-batches where each sub-batch's
// gzip-compressed proto size does not exceed maxBytes.
//
// Records are added one at a time to the current sub-batch. Before each
// addition we measure the compressed size of the candidate batch. If it
// exceeds maxBytes we flush the current batch and start a new one.
//
// A single record that exceeds maxBytes on its own is emitted alone — it is
// never dropped silently.
func splitByCompressedSize(ld plog.Logs, maxBytes int) []plog.Logs {
	type entry struct {
		resource pcommon.Resource
		scope    pcommon.InstrumentationScope
		record   plog.LogRecord
	}

	// Flatten all (resource, scope, record) triples from the nested plog structure.
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
		// Build a candidate that includes this record.
		candidate := plog.NewLogs()
		current.CopyTo(candidate)
		appendLogRecord(candidate, e.resource, e.scope, e.record)

		size := compressedProtoSize(candidate)

		if size <= maxBytes || current.LogRecordCount() == 0 {
			// Fits within limit — or it is the only record in a fresh batch
			// (single oversized record: emit alone rather than dropping it).
			current = candidate
		} else {
			// Would overflow — flush current batch, start fresh with this record.
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

// appendLogRecord copies record into dest under the matching resource + scope,
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

// compressedProtoSize serializes ld as an OTLP proto export request and
// gzip-compresses it, returning the compressed byte count.
// This is the same serialization path the OTLP exporter uses, so the
// measurement accurately predicts what New Relic's ingest endpoint receives.
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

// attrMapKey produces a deterministic string fingerprint of an attribute map
// for equality checks when grouping records under the same resource/scope.
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
