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
	"encoding/json"
	"errors"
	"testing"
	"time"

	metricspb "github.com/census-instrumentation/opencensus-proto/gen-go/metrics/v1"
	resourcepb "github.com/census-instrumentation/opencensus-proto/gen-go/resource/v1"
	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/newrelic/newrelic-telemetry-sdk-go/cumulative"
	"github.com/newrelic/newrelic-telemetry-sdk-go/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/internaldata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewTraceTransformerInstrumentation(t *testing.T) {
	ilm := pdata.NewInstrumentationLibrary()
	ilm.SetName("test name")
	ilm.SetVersion("test version")

	transform := newTraceTransformer(pdata.NewResource(), ilm)
	require.Contains(t, transform.ResourceAttributes, instrumentationNameKey)
	require.Contains(t, transform.ResourceAttributes, instrumentationVersionKey)
	assert.Equal(t, transform.ResourceAttributes[instrumentationNameKey], "test name")
	assert.Equal(t, transform.ResourceAttributes[instrumentationVersionKey], "test version")
}

func defaultAttrFunc(res map[string]interface{}) func(map[string]interface{}) map[string]interface{} {
	return func(add map[string]interface{}) map[string]interface{} {
		full := make(map[string]interface{}, 2+len(res)+len(add))
		full[collectorNameKey] = name
		full[collectorVersionKey] = version
		for k, v := range res {
			full[k] = v
		}
		for k, v := range add {
			full[k] = v
		}
		return full
	}
}

func TestTransformSpan(t *testing.T) {
	now := time.Unix(100, 0)
	rattr := map[string]interface{}{
		serviceNameKey: "test-service",
		"resource":     "R1",
	}
	transform := &traceTransformer{ResourceAttributes: rattr}
	withDefaults := defaultAttrFunc(rattr)

	tests := []struct {
		name     string
		err      error
		spanFunc func() pdata.Span
		want     telemetry.Span
	}{
		{
			name: "invalid TraceID",
			spanFunc: func() pdata.Span {
				s := pdata.NewSpan()
				s.SetSpanID(pdata.NewSpanID([...]byte{0, 0, 0, 0, 0, 0, 0, 1}))
				s.SetName("invalid TraceID")
				return s
			},
			err: errInvalidTraceID,
			want: telemetry.Span{
				ID:         "0000000000000001",
				Name:       "invalid TraceID",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: withDefaults(nil),
			},
		},
		{
			name: "invalid SpanID",
			spanFunc: func() pdata.Span {
				s := pdata.NewSpan()
				s.SetTraceID(pdata.NewTraceID([...]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
				s.SetName("invalid SpanID")
				return s
			},
			err: errInvalidSpanID,
			want: telemetry.Span{
				TraceID:    "01010101010101010101010101010101",
				Name:       "invalid SpanID",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: withDefaults(nil),
			},
		},
		{
			name: "root",
			spanFunc: func() pdata.Span {
				s := pdata.NewSpan()
				s.SetTraceID(pdata.NewTraceID([...]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
				s.SetSpanID(pdata.NewSpanID([...]byte{0, 0, 0, 0, 0, 0, 0, 1}))
				s.SetName("root")
				return s
			},
			want: telemetry.Span{
				ID:         "0000000000000001",
				TraceID:    "01010101010101010101010101010101",
				Name:       "root",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: withDefaults(nil),
				Events:     nil,
			},
		},
		{
			name: "client",
			spanFunc: func() pdata.Span {
				s := pdata.NewSpan()
				s.SetTraceID(pdata.NewTraceID([...]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
				s.SetSpanID(pdata.NewSpanID([...]byte{0, 0, 0, 0, 0, 0, 0, 2}))
				s.SetParentSpanID(pdata.NewSpanID([...]byte{0, 0, 0, 0, 0, 0, 0, 1}))
				s.SetName("client")
				return s
			},
			want: telemetry.Span{
				ID:         "0000000000000002",
				TraceID:    "01010101010101010101010101010101",
				Name:       "client",
				ParentID:   "0000000000000001",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: withDefaults(nil),
				Events:     nil,
			},
		},
		{
			name: "error code",
			spanFunc: func() pdata.Span {
				// There is no setter method for a Status so convert instead.
				return internaldata.OCToTraces(
					nil, nil, []*tracepb.Span{
						{
							TraceId: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
							SpanId:  []byte{0, 0, 0, 0, 0, 0, 0, 3},
							Name:    &tracepb.TruncatableString{Value: "error code"},
							Status:  &tracepb.Status{Code: 1},
						},
					}).ResourceSpans().At(0).InstrumentationLibrarySpans().At(0).Spans().At(0)
			},
			want: telemetry.Span{
				ID:        "0000000000000003",
				TraceID:   "01010101010101010101010101010101",
				Name:      "error code",
				Timestamp: time.Unix(0, 0).UTC(),
				Attributes: withDefaults(map[string]interface{}{
					statusCodeKey: "ERROR",
				}),
				Events: nil,
			},
		},
		{
			name: "error message",
			spanFunc: func() pdata.Span {
				// There is no setter method for a Status so convert instead.
				return internaldata.OCToTraces(
					nil, nil, []*tracepb.Span{
						{
							TraceId: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
							SpanId:  []byte{0, 0, 0, 0, 0, 0, 0, 3},
							Name:    &tracepb.TruncatableString{Value: "error message"},
							Status:  &tracepb.Status{Code: 1, Message: "error message"},
						},
					}).ResourceSpans().At(0).InstrumentationLibrarySpans().At(0).Spans().At(0)
			},
			want: telemetry.Span{
				ID:        "0000000000000003",
				TraceID:   "01010101010101010101010101010101",
				Name:      "error message",
				Timestamp: time.Unix(0, 0).UTC(),
				Attributes: withDefaults(map[string]interface{}{
					statusCodeKey:        "ERROR",
					statusDescriptionKey: "error message",
				}),
				Events: nil,
			},
		},
		{
			name: "attributes",
			spanFunc: func() pdata.Span {
				// There is no setter method for Attributes so convert instead.
				return internaldata.OCToTraces(
					nil, nil, []*tracepb.Span{
						{
							TraceId: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
							SpanId:  []byte{0, 0, 0, 0, 0, 0, 0, 4},
							Name:    &tracepb.TruncatableString{Value: "attrs"},
							Status:  &tracepb.Status{},
							Attributes: &tracepb.Span_Attributes{
								AttributeMap: map[string]*tracepb.AttributeValue{
									"prod": {
										Value: &tracepb.AttributeValue_BoolValue{
											BoolValue: true,
										},
									},
									"weight": {
										Value: &tracepb.AttributeValue_IntValue{
											IntValue: 10,
										},
									},
									"score": {
										Value: &tracepb.AttributeValue_DoubleValue{
											DoubleValue: 99.8,
										},
									},
									"user": {
										Value: &tracepb.AttributeValue_StringValue{
											StringValue: &tracepb.TruncatableString{Value: "alice"},
										},
									},
								},
							},
						},
					}).ResourceSpans().At(0).InstrumentationLibrarySpans().At(0).Spans().At(0)
			},
			want: telemetry.Span{
				ID:        "0000000000000004",
				TraceID:   "01010101010101010101010101010101",
				Name:      "attrs",
				Timestamp: time.Unix(0, 0).UTC(),
				Attributes: withDefaults(map[string]interface{}{
					"prod":   true,
					"weight": int64(10),
					"score":  99.8,
					"user":   "alice",
				}),
				Events: nil,
			},
		},
		{
			name: "with timestamps",
			spanFunc: func() pdata.Span {
				s := pdata.NewSpan()
				s.SetTraceID(pdata.NewTraceID([...]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
				s.SetSpanID(pdata.NewSpanID([...]byte{0, 0, 0, 0, 0, 0, 0, 5}))
				s.SetName("with time")
				s.SetStartTime(pdata.TimestampFromTime(now))
				s.SetEndTime(pdata.TimestampFromTime(now.Add(time.Second * 5)))
				return s
			},
			want: telemetry.Span{
				ID:         "0000000000000005",
				TraceID:    "01010101010101010101010101010101",
				Name:       "with time",
				Timestamp:  now.UTC(),
				Duration:   time.Second * 5,
				Attributes: withDefaults(nil),
				Events:     nil,
			},
		},
		{
			name: "span kind server",
			spanFunc: func() pdata.Span {
				s := pdata.NewSpan()
				s.SetTraceID(pdata.NewTraceID([...]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
				s.SetSpanID(pdata.NewSpanID([...]byte{0, 0, 0, 0, 0, 0, 0, 6}))
				s.SetName("span kind server")
				s.SetKind(pdata.SpanKindSERVER)
				return s
			},
			want: telemetry.Span{
				ID:        "0000000000000006",
				TraceID:   "01010101010101010101010101010101",
				Name:      "span kind server",
				Timestamp: time.Unix(0, 0).UTC(),
				Attributes: withDefaults(map[string]interface{}{
					spanKindKey: "server",
				}),
				Events: nil,
			},
		},
		{
			name: "with events",
			spanFunc: func() pdata.Span {
				s := pdata.NewSpan()
				s.SetTraceID(pdata.NewTraceID([...]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
				s.SetSpanID(pdata.NewSpanID([...]byte{0, 0, 0, 0, 0, 0, 0, 7}))
				s.SetName("with events")

				ev := pdata.NewSpanEventSlice()
				ev.Resize(1)
				event := ev.At(0)
				event.SetName("this is the event name")
				event.SetTimestamp(pdata.TimestampFromTime(now))
				s.Events().Append(event)
				return s
			},
			want: telemetry.Span{
				ID:         "0000000000000007",
				TraceID:    "01010101010101010101010101010101",
				Name:       "with events",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: withDefaults(nil),
				Events: []telemetry.Event{
					{
						EventType:  "this is the event name",
						Timestamp:  now.UTC(),
						Attributes: map[string]interface{}{},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := transform.Span(test.spanFunc())
			if test.err != nil {
				assert.True(t, errors.Is(err, test.err))
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.want, got)
		})
	}
}

func TestMergeAttributesIncompatibleLenghts(t *testing.T) {
	transform := &metricTransformer{}
	lk := make([]*metricspb.LabelKey, 2)
	lv := make([]*metricspb.LabelValue, 3)
	_, err := transform.MergeAttributes(nil, lk, lv)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errIncompatibleLabels))
}

func TestTransformEmptyMetric(t *testing.T) {
	transform := &metricTransformer{}
	_, err := transform.Metric(nil)
	assert.Error(t, err, "nil metric should return an error")
	_, err = transform.Metric(&metricspb.Metric{})
	assert.Error(t, err, "nil metric descriptor should return an error")
}

func testTransformMetric(t *testing.T, metric *metricspb.Metric, want []telemetry.Metric) {
	transform := &metricTransformer{
		DeltaCalculator: cumulative.NewDeltaCalculator(),
		ServiceName:     "test-service",
		Resource: &resourcepb.Resource{
			Labels: map[string]string{
				"resource": "R1",
			},
		},
	}
	got, err := transform.Metric(metric)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestTransformMetricRequiredAttributes(t *testing.T) {
	ts := &timestamppb.Timestamp{Seconds: 1}
	expected := []telemetry.Metric{
		telemetry.Gauge{
			Name:      "gauge",
			Value:     42.0,
			Timestamp: time.Unix(1, 0),
			Attributes: map[string]interface{}{
				collectorNameKey:           name,
				collectorVersionKey:        version,
				serviceNameKey:             "test-service",
				instrumentationNameKey:     "opentelemetry",
				instrumentationVersionKey:  "1.0.1",
				instrumentationLanguageKey: "java",
			},
		},
	}

	metric := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name: "gauge",
			Type: metricspb.MetricDescriptor_GAUGE_DOUBLE,
		},
		Timeseries: []*metricspb.TimeSeries{
			{
				Points: []*metricspb.Point{
					{
						Timestamp: ts,
						Value: &metricspb.Point_DoubleValue{
							DoubleValue: 42.0,
						},
					},
				},
			},
		},
	}

	transform := &metricTransformer{
		DeltaCalculator: cumulative.NewDeltaCalculator(),
		ServiceName:     "test-service",
		Language:        "java",
		Resource: &resourcepb.Resource{
			Labels: map[string]string{
				collectorNameKey:          name,
				collectorVersionKey:       version,
				serviceNameKey:            "test-service",
				instrumentationNameKey:    "opentelemetry",
				instrumentationVersionKey: "1.0.1",
			},
		},
	}
	got, err := transform.Metric(metric)
	require.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestTransformGuage(t *testing.T) {
	ts := &timestamppb.Timestamp{Seconds: 1}
	expected := []telemetry.Metric{
		telemetry.Gauge{
			Name:      "gauge",
			Value:     42.0,
			Timestamp: time.Unix(1, 0),
			Attributes: map[string]interface{}{
				collectorNameKey:    name,
				collectorVersionKey: version,
				"resource":          "R1",
				"service.name":      "test-service",
			},
		},
	}

	gd := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name: "gauge",
			Type: metricspb.MetricDescriptor_GAUGE_DOUBLE,
		},
		Timeseries: []*metricspb.TimeSeries{
			{
				Points: []*metricspb.Point{
					{
						Timestamp: ts,
						Value: &metricspb.Point_DoubleValue{
							DoubleValue: 42.0,
						},
					},
				},
			},
		},
	}
	t.Run("Double", func(t *testing.T) { testTransformMetric(t, gd, expected) })

	gi := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name: "gauge",
			Type: metricspb.MetricDescriptor_GAUGE_INT64,
		},
		Timeseries: []*metricspb.TimeSeries{
			{
				Points: []*metricspb.Point{
					{
						Timestamp: ts,
						Value: &metricspb.Point_Int64Value{
							Int64Value: 42,
						},
					},
				},
			},
		},
	}
	t.Run("Int64", func(t *testing.T) { testTransformMetric(t, gi, expected) })
}

func TestTransformDeltaSummary(t *testing.T) {
	start := &timestamppb.Timestamp{Seconds: 1}
	ts := &timestamppb.Timestamp{Seconds: 2}
	expected := []telemetry.Metric{
		telemetry.Summary{
			Name:      "summary",
			Count:     2.0,
			Sum:       7.0,
			Timestamp: time.Unix(1, 0),
			Interval:  time.Second,
			Attributes: map[string]interface{}{
				collectorNameKey:    name,
				collectorVersionKey: version,
				"resource":          "R1",
				"service.name":      "test-service",
			},
		},
	}

	gd := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name: "summary",
			Type: metricspb.MetricDescriptor_GAUGE_DISTRIBUTION,
		},
		Timeseries: []*metricspb.TimeSeries{
			{
				StartTimestamp: start,
				Points: []*metricspb.Point{
					{
						Timestamp: ts,
						Value: &metricspb.Point_DistributionValue{
							DistributionValue: &metricspb.DistributionValue{
								Count: 2,
								Sum:   7,
							},
						},
					},
				},
			},
		},
	}
	t.Run("Distribution", func(t *testing.T) {
		testTransformMetric(t, gd, expected)
		// Should be a delta, running twice should not change state.
		testTransformMetric(t, gd, expected)
	})

	/* Remove only dependency on wrapperspb.
	s := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name: "summary",
			Type: metricspb.MetricDescriptor_SUMMARY,
		},
		Timeseries: []*metricspb.TimeSeries{
			{
				StartTimestamp: start,
				Points: []*metricspb.Point{
					{
						Timestamp: ts,
						Value: &metricspb.Point_SummaryValue{
							SummaryValue: &metricspb.SummaryValue{
								Count: &wrapperspb.Int64Value{Value: 2},
								Sum:   &wrapperspb.DoubleValue{Value: 7},
							},
						},
					},
				},
			},
		},
	}
	t.Run("Summary", func(t *testing.T) {
		testTransformMetric(t, s, expected)
		// Should be a delta, running twice should not change state.
		testTransformMetric(t, s, expected)
	})
	*/
}

func TestTransformCumulativeCount(t *testing.T) {
	start := &timestamppb.Timestamp{Seconds: 1}
	ts1 := &timestamppb.Timestamp{Seconds: 2}
	ts2 := &timestamppb.Timestamp{Seconds: 3}
	attrs := map[string]interface{}{
		collectorNameKey:    name,
		collectorVersionKey: version,
		"resource":          "R1",
		"service.name":      "test-service",
	}
	jsonAttrs, err := json.Marshal(attrs)
	require.NoError(t, err)
	expected := []telemetry.Metric{
		telemetry.Count{
			Name:       "count",
			Value:      5.0,
			Timestamp:  time.Unix(1, 0),
			Interval:   time.Second,
			Attributes: attrs,
		},
		telemetry.Count{
			Name:           "count",
			Value:          2.0,
			Timestamp:      time.Unix(2, 0),
			Interval:       time.Second,
			AttributesJSON: jsonAttrs,
		},
	}

	cd := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name: "count",
			Type: metricspb.MetricDescriptor_CUMULATIVE_DOUBLE,
		},
		Timeseries: []*metricspb.TimeSeries{
			{
				StartTimestamp: start,
				Points: []*metricspb.Point{
					{
						Timestamp: ts1,
						Value: &metricspb.Point_DoubleValue{
							DoubleValue: 5.0,
						},
					},
					{
						Timestamp: ts2,
						Value: &metricspb.Point_DoubleValue{
							DoubleValue: 7.0,
						},
					},
				},
			},
		},
	}
	t.Run("Double", func(t *testing.T) { testTransformMetric(t, cd, expected) })

	ci := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name: "count",
			Type: metricspb.MetricDescriptor_CUMULATIVE_INT64,
		},
		Timeseries: []*metricspb.TimeSeries{
			{
				StartTimestamp: start,
				Points: []*metricspb.Point{
					{
						Timestamp: ts1,
						Value: &metricspb.Point_Int64Value{
							Int64Value: 5,
						},
					},
					{
						Timestamp: ts2,
						Value: &metricspb.Point_Int64Value{
							Int64Value: 7,
						},
					},
				},
			},
		},
	}
	t.Run("Int64", func(t *testing.T) { testTransformMetric(t, ci, expected) })
}

func TestTransformCumulativeSummary(t *testing.T) {
	start := &timestamppb.Timestamp{Seconds: 1}
	ts1 := &timestamppb.Timestamp{Seconds: 2}
	ts2 := &timestamppb.Timestamp{Seconds: 3}
	attrs := map[string]interface{}{
		collectorNameKey:    name,
		collectorVersionKey: version,
		"resource":          "R1",
		"service.name":      "test-service",
	}
	expected := []telemetry.Metric{
		telemetry.Summary{
			Name:       "summary",
			Sum:        5.0,
			Count:      53.0,
			Timestamp:  time.Unix(1, 0),
			Interval:   time.Second,
			Attributes: attrs,
		},
		telemetry.Summary{
			Name:       "summary",
			Sum:        3.0,
			Count:      3.0,
			Timestamp:  time.Unix(2, 0),
			Interval:   time.Second,
			Attributes: attrs,
		},
	}

	cd := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name: "summary",
			Type: metricspb.MetricDescriptor_CUMULATIVE_DISTRIBUTION,
		},
		Timeseries: []*metricspb.TimeSeries{
			{
				StartTimestamp: start,
				Points: []*metricspb.Point{
					{
						Timestamp: ts1,
						Value: &metricspb.Point_DistributionValue{
							DistributionValue: &metricspb.DistributionValue{
								Count: 53,
								Sum:   5,
							},
						},
					},
					{
						Timestamp: ts2,
						Value: &metricspb.Point_DistributionValue{
							DistributionValue: &metricspb.DistributionValue{
								Count: 56,
								Sum:   8,
							},
						},
					},
				},
			},
		},
	}
	t.Run("Distribution", func(t *testing.T) { testTransformMetric(t, cd, expected) })
}

func TestLogTransformer_Log(t *testing.T) {
	emptyResource := pdata.NewResource()
	emptyInstrumentationLibrary := pdata.NewInstrumentationLibrary()

	attributeResource := pdata.NewResource()
	attributeResource.Attributes().InitFromMap(map[string]pdata.AttributeValue{
		"str":    pdata.NewAttributeValueString("str"),
		"bool":   pdata.NewAttributeValueBool(true),
		"double": pdata.NewAttributeValueDouble(8.2),
		"int":    pdata.NewAttributeValueInt(42),
		"map":    pdata.NewAttributeValueMap(),
		"array":  pdata.NewAttributeValueArray(),
		"null":   pdata.NewAttributeValueNull(),
	})
	withResourceAttributes := func(attributes map[string]interface{}) map[string]interface{} {
		expectedResourceAttributes := map[string]interface{}{
			"str":    "str",
			"bool":   true,
			"double": 8.2,
			"int":    int64(42),
			"map":    map[string]interface{}{},
			"array":  []interface{}{},
			"null":   nil,
		}
		for k, v := range attributes {
			expectedResourceAttributes[k] = v
		}
		return expectedResourceAttributes
	}

	namedInstrumentationLibrary := pdata.NewInstrumentationLibrary()
	namedInstrumentationLibrary.SetName("bleepbloop")

	versionedInstrumentationLibrary := pdata.NewInstrumentationLibrary()
	versionedInstrumentationLibrary.SetName("bleepbloop")
	versionedInstrumentationLibrary.SetVersion("1.2.3")

	withNamedLibraryAttributes := func(attributes map[string]interface{}) map[string]interface{} {
		expected := map[string]interface{}{
			"instrumentation.name": "bleepbloop",
		}
		for k, v := range attributes {
			expected[k] = v
		}
		return expected
	}
	withVersionedLibraryAttributes := func(attributes map[string]interface{}) map[string]interface{} {
		expected := map[string]interface{}{
			"instrumentation.name":    "bleepbloop",
			"instrumentation.version": "1.2.3",
		}
		for k, v := range attributes {
			expected[k] = v
		}
		return expected
	}

	tests := []struct {
		Resource               pdata.Resource
		InstrumentationLibrary pdata.InstrumentationLibrary
		name                   string
		logFunc                func() pdata.LogRecord
		want                   telemetry.Log
	}{
		{
			Resource:               emptyResource,
			InstrumentationLibrary: emptyInstrumentationLibrary,
			name:                   "Basic Conversion",
			logFunc: func() pdata.LogRecord {
				log := pdata.NewLogRecord()
				timestamp := pdata.TimestampFromTime(time.Unix(0, 0).UTC())
				log.SetTimestamp(timestamp)
				return log
			},
			want: telemetry.Log{
				Message:    "",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: map[string]interface{}{"name": ""},
			},
		},
		{
			Resource:               attributeResource,
			InstrumentationLibrary: emptyInstrumentationLibrary,
			name:                   "Resource Attributes",
			logFunc: func() pdata.LogRecord {
				log := pdata.NewLogRecord()
				timestamp := pdata.TimestampFromTime(time.Unix(0, 0).UTC())
				log.SetTimestamp(timestamp)
				return log
			},
			want: telemetry.Log{
				Message:    "",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: withResourceAttributes(map[string]interface{}{"name": ""}),
			},
		},
		{
			Resource:               emptyResource,
			InstrumentationLibrary: namedInstrumentationLibrary,
			name:                   "Named Library",
			logFunc: func() pdata.LogRecord {
				return pdata.NewLogRecord()
			},
			want: telemetry.Log{
				Message:    "",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: withNamedLibraryAttributes(map[string]interface{}{"name": ""}),
			},
		},
		{
			Resource:               emptyResource,
			InstrumentationLibrary: versionedInstrumentationLibrary,
			name:                   "Versioned Library",
			logFunc: func() pdata.LogRecord {
				return pdata.NewLogRecord()
			},
			want: telemetry.Log{
				Message:    "",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: withVersionedLibraryAttributes(map[string]interface{}{"name": ""}),
			},
		},
		{
			Resource:               emptyResource,
			InstrumentationLibrary: emptyInstrumentationLibrary,
			name:                   "With Log Attributes",
			logFunc: func() pdata.LogRecord {
				log := pdata.NewLogRecord()
				log.SetName("bloopbleep")
				log.Attributes().InsertString("foo", "bar")
				log.Body().SetStringVal("Hello World")
				return log
			},
			want: telemetry.Log{
				Message:    "Hello World",
				Timestamp:  time.Unix(0, 0).UTC(),
				Attributes: map[string]interface{}{"foo": "bar", "name": "bloopbleep"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transform := newLogTransformer(test.Resource, test.InstrumentationLibrary)
			got, _ := transform.Log(test.logFunc())
			assert.EqualValues(t, test.want, got)
		})
	}
}
