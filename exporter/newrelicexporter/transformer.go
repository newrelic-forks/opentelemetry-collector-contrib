// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package newrelicexporter

import (
	"errors"
	"math"
	"strings"
	"time"

	"github.com/newrelic/newrelic-telemetry-sdk-go/telemetry"
	"go.opentelemetry.io/collector/consumer/pdata"
	tracetranslator "go.opentelemetry.io/collector/translator/trace"
)

const (
	unitAttrKey               = "unit"
	descriptionAttrKey        = "description"
	collectorNameKey          = "collector.name"
	collectorVersionKey       = "collector.version"
	instrumentationNameKey    = "instrumentation.name"
	instrumentationVersionKey = "instrumentation.version"
	statusCodeKey             = "otel.status_code"
	statusDescriptionKey      = "otel.status_description"
	spanKindKey               = "span.kind"
)

type transformer struct {
	ResourceAttributes map[string]interface{}
}

func newTransformer(resource pdata.Resource, lib pdata.InstrumentationLibrary) *transformer {
	t := &transformer{
		ResourceAttributes: tracetranslator.AttributeMapToMap(
			resource.Attributes(),
		),
	}

	if n := lib.Name(); n != "" {
		t.ResourceAttributes[instrumentationNameKey] = n
		if v := lib.Version(); v != "" {
			t.ResourceAttributes[instrumentationVersionKey] = v
		}
	}
	return t
}

var (
	errInvalidSpanID  = errors.New("SpanID is invalid")
	errInvalidTraceID = errors.New("TraceID is invalid")
)

func (t *transformer) Span(span pdata.Span) (telemetry.Span, error) {
	startTime := span.StartTime().AsTime()
	sp := telemetry.Span{
		// HexString validates the IDs, it will be an empty string if invalid.
		ID:         span.SpanID().HexString(),
		TraceID:    span.TraceID().HexString(),
		ParentID:   span.ParentSpanID().HexString(),
		Name:       span.Name(),
		Timestamp:  startTime,
		Duration:   span.EndTime().AsTime().Sub(startTime),
		Attributes: t.SpanAttributes(span),
		Events:     t.SpanEvents(span),
	}

	if sp.ID == "" {
		return sp, errInvalidSpanID
	}
	if sp.TraceID == "" {
		return sp, errInvalidTraceID
	}

	return sp, nil
}

func (t *transformer) Log(log pdata.LogRecord) (telemetry.Log, error) {
	var message string

	if bodyString := log.Body().StringVal(); bodyString != "" {
		message = bodyString
	} else {
		message = log.Name()
	}

	attributes := tracetranslator.AttributeMapToMap(log.Attributes())

	for k, v := range t.ResourceAttributes {
		attributes[k] = v
	}

	attributes["name"] = log.Name()

	if !log.TraceID().IsEmpty() {
		attributes["trace.id"] = log.TraceID().HexString()
	}

	if !log.SpanID().IsEmpty() {
		attributes["span.id"] = log.SpanID().HexString()
	}

	if log.SeverityText() != "" {
		attributes["log.level"] = log.SeverityText()
	}

	return telemetry.Log{
		Message:    message,
		Timestamp:  log.Timestamp().AsTime(),
		Attributes: attributes,
	}, nil
}

func (t *transformer) Metric(m pdata.Metric) ([]telemetry.Metric, error) {
	var output []telemetry.Metric
	baseAttributes := t.BaseMetricAttributes(m)

	switch m.DataType() {
	case pdata.MetricDataTypeIntGauge:
		// "StartTimeUnixNano" is ignored for all data points.
		gauge := m.IntGauge()
		points := gauge.DataPoints()
		output = make([]telemetry.Metric, 0, points.Len())
		for l := 0; l < points.Len(); l++ {
			point := points.At(l)
			attributes := MetricAttributes(baseAttributes, point.LabelsMap())

			nrMetric := telemetry.Gauge{
				Name:       m.Name(),
				Attributes: attributes,
				Value:      float64(point.Value()),
				Timestamp:  point.Timestamp().AsTime(),
			}
			output = append(output, nrMetric)
		}
	case pdata.MetricDataTypeDoubleGauge:
		// "StartTimeUnixNano" is ignored for all data points.
		gauge := m.DoubleGauge()
		points := gauge.DataPoints()
		output = make([]telemetry.Metric, 0, points.Len())
		for l := 0; l < points.Len(); l++ {
			point := points.At(l)
			attributes := MetricAttributes(baseAttributes, point.LabelsMap())

			nrMetric := telemetry.Gauge{
				Name:       m.Name(),
				Attributes: attributes,
				Value:      point.Value(),
				Timestamp:  point.Timestamp().AsTime(),
			}
			output = append(output, nrMetric)
		}
	case pdata.MetricDataTypeIntSum:
		// aggregation_temporality describes if the aggregator reports delta changes
		// since last report time, or cumulative changes since a fixed start time.
		sum := m.IntSum()
		if sum.AggregationTemporality() != pdata.AggregationTemporalityDelta {
			// TODO: record error
			break
		}

		points := sum.DataPoints()
		output = make([]telemetry.Metric, 0, points.Len())
		for l := 0; l < points.Len(); l++ {
			point := points.At(l)
			attributes := MetricAttributes(baseAttributes, point.LabelsMap())

			nrMetric := telemetry.Count{
				Name:       m.Name(),
				Attributes: attributes,
				Value:      float64(point.Value()),
				Timestamp:  point.StartTime().AsTime(),
				Interval:   time.Duration(point.Timestamp() - point.StartTime()),
			}
			output = append(output, nrMetric)
		}
	case pdata.MetricDataTypeDoubleSum:
		sum := m.DoubleSum()
		if sum.AggregationTemporality() != pdata.AggregationTemporalityDelta {
			// TODO: record error
			break
		}

		points := sum.DataPoints()
		output = make([]telemetry.Metric, 0, points.Len())
		for l := 0; l < points.Len(); l++ {
			point := points.At(l)
			attributes := MetricAttributes(baseAttributes, point.LabelsMap())

			nrMetric := telemetry.Count{
				Name:       m.Name(),
				Attributes: attributes,
				Value:      point.Value(),
				Timestamp:  point.StartTime().AsTime(),
				Interval:   time.Duration(point.Timestamp() - point.StartTime()),
			}
			output = append(output, nrMetric)
		}
	case pdata.MetricDataTypeIntHistogram:
		histogram := m.IntHistogram()
		if histogram.AggregationTemporality() != pdata.AggregationTemporalityDelta {
			// TODO: record error
			break
		}
	case pdata.MetricDataTypeDoubleHistogram:
		histogram := m.DoubleHistogram()
		if histogram.AggregationTemporality() != pdata.AggregationTemporalityDelta {
			// TODO: record error
			break
		}
	case pdata.MetricDataTypeDoubleSummary:
		summary := m.DoubleSummary()
		points := summary.DataPoints()
		output = make([]telemetry.Metric, 0, points.Len())
		name := m.Name()
		for l := 0; l < points.Len(); l++ {
			point := points.At(l)
			quantiles := point.QuantileValues()
			minQuantile := math.NaN()
			maxQuantile := math.NaN()

			if quantiles.Len() > 0 {
				quantileA := quantiles.At(0)
				if quantileA.Quantile() == 0 {
					minQuantile = quantileA.Value()
				}
				if quantiles.Len() > 1 {
					quantileB := quantiles.At(quantiles.Len() - 1)
					if quantileB.Quantile() == 1 {
						maxQuantile = quantileB.Value()
					}
				} else if quantileA.Quantile() == 1 {
					maxQuantile = quantileA.Value()
				}
			}

			attributes := MetricAttributes(baseAttributes, point.LabelsMap())
			nrMetric := telemetry.Summary{
				Name:       name,
				Attributes: attributes,
				Count:      float64(point.Count()),
				Sum:        point.Sum(),
				Min:        minQuantile,
				Max:        maxQuantile,
				Timestamp:  point.StartTime().AsTime(),
				Interval:   time.Duration(point.Timestamp() - point.StartTime()),
			}

			output = append(output, nrMetric)
		}
	}
	return output, nil
}

func (t *transformer) SpanAttributes(span pdata.Span) map[string]interface{} {

	length := 2 + len(t.ResourceAttributes) + span.Attributes().Len()

	var hasStatusCode, hasStatusDesc bool
	s := span.Status()
	if s.Code() != pdata.StatusCodeUnset {
		hasStatusCode = true
		length++
		if s.Message() != "" {
			hasStatusDesc = true
			length++
		}
	}

	validSpanKind := span.Kind() != pdata.SpanKindUNSPECIFIED
	if validSpanKind {
		length++
	}

	attrs := make(map[string]interface{}, length)

	if hasStatusCode {
		code := strings.TrimPrefix(span.Status().Code().String(), "STATUS_CODE_")
		attrs[statusCodeKey] = code
	}
	if hasStatusDesc {
		attrs[statusDescriptionKey] = span.Status().Message()
	}

	// Add span kind if it is set
	if validSpanKind {
		kind := strings.TrimPrefix(span.Kind().String(), "SPAN_KIND_")
		attrs[spanKindKey] = strings.ToLower(kind)
	}

	for k, v := range t.ResourceAttributes {
		attrs[k] = v
	}

	for k, v := range tracetranslator.AttributeMapToMap(span.Attributes()) {
		attrs[k] = v
	}

	// Default attributes to tell New Relic about this collector.
	// (overrides any existing)
	attrs[collectorNameKey] = name
	attrs[collectorVersionKey] = version

	return attrs
}

// SpanEvents transforms the recorded events of span into New Relic tracing events.
func (t *transformer) SpanEvents(span pdata.Span) []telemetry.Event {
	length := span.Events().Len()
	if length == 0 {
		return nil
	}

	events := make([]telemetry.Event, length)

	for i := 0; i < length; i++ {
		event := span.Events().At(i)
		events[i] = telemetry.Event{
			EventType:  event.Name(),
			Timestamp:  event.Timestamp().AsTime(),
			Attributes: tracetranslator.AttributeMapToMap(event.Attributes()),
		}
	}
	return events
}

func (t *transformer) BaseMetricAttributes(metric pdata.Metric) map[string]interface{} {
	length := len(t.ResourceAttributes)

	if metric.Unit() != "" {
		length++
	}

	if metric.Description() != "" {
		length++
	}

	attrs := make(map[string]interface{}, length)

	for k, v := range t.ResourceAttributes {
		attrs[k] = v
	}

	if metric.Unit() != "" {
		attrs[unitAttrKey] = metric.Unit()
	}

	if metric.Description() != "" {
		attrs[descriptionAttrKey] = metric.Description()
	}
	return attrs
}

func MetricAttributes(baseAttributes map[string]interface{}, attrMap pdata.StringMap) map[string]interface{} {
	rawMap := make(map[string]interface{}, len(baseAttributes)+attrMap.Len()+2)
	for k, v := range baseAttributes {
		rawMap[k] = v
	}
	attrMap.ForEach(func(k string, v string) {
		rawMap[k] = v
	})

	rawMap[collectorNameKey] = name
	rawMap[collectorVersionKey] = version
	return rawMap
}
