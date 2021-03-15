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
	"context"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"strconv"
	"time"
)

var (
	tagResponseCode, _        = tag.NewKey("grpc_response_code")
	tagTraceHTTPStatusCode, _ = tag.NewKey("trace_http_status_code")
	tagRequestUserAgent, _    = tag.NewKey("user_agent")
	tagApiKey, _              = tag.NewKey("api_key")
	tagKeys                   = []tag.Key{tagResponseCode, tagTraceHTTPStatusCode, tagRequestUserAgent, tagApiKey}

	statTraceRequests        = stats.Int64("newrelicexporter_trace_requests", "Number of trace requests processed", stats.UnitDimensionless)
	statTraceResourceSpans   = stats.Int64("newrelicexporter_trace_resource_spans", "Number of resource spans processed", stats.UnitDimensionless)
	statTraceExternalSpans   = stats.Int64("newrelicexporter_trace_external_spans", "Number of spans sent to trace API", stats.UnitDimensionless)
	statTraceProcessSeconds  = stats.Float64("newrelicexporter_trace_process_duration_seconds", "Seconds spent processing requests", stats.UnitSeconds)
	statTraceExternalSeconds = stats.Float64("newrelicexporter_trace_external_duration_seconds", "Seconds spent sending data to the trace API", stats.UnitSeconds)
)

// MetricViews return metric views for Kafka receiver.
func MetricViews() []*view.View {
	return []*view.View{
		buildView(tagKeys, statTraceRequests, view.Sum()),
		buildView(tagKeys, statTraceResourceSpans, view.Sum()),
		buildView(tagKeys, statTraceExternalSpans, view.Sum()),
		buildView(tagKeys, statTraceProcessSeconds, view.Sum()),
		buildView(tagKeys, statTraceExternalSeconds, view.Sum()),
	}
}

func buildView(tagKeys []tag.Key, m stats.Measure, a *view.Aggregation) *view.View {
	return &view.View{
		Name:        m.Name(),
		Measure:     m,
		Description: m.Description(),
		TagKeys:     tagKeys,
		Aggregation: a,
	}
}

type traceDetails struct {
	// Metric tags
	responseCode        codes.Code // The gRPC response code
	traceHTTPStatusCode int        // The HTTP response status code form the trace API
	apiKey              string     // The API key from the request
	userAgent           string     // The User-Agent from the request
	// Metric values
	resourceSpanCount int           // Number of resource spans in the request
	processDuration   time.Duration // Total time spent in the newrelic exporter
	traceSpanCount    int           // Number of spans sent to the trace API
	externalDuration  time.Duration // Time spent sending to the trace API
}

func newTraceDetails(ctx context.Context) *traceDetails {
	userAgent := "not_present"
	if md, ctxOk := metadata.FromIncomingContext(ctx); ctxOk {
		if values, headerOk := md["user-agent"]; headerOk {
			userAgent = values[0]
		}
	}

	return &traceDetails{userAgent: userAgent, apiKey: "not_present"}
}

func (d *traceDetails) recordPushTraceData(ctx context.Context) error {
	tags := []tag.Mutator{
		tag.Insert(tagResponseCode, d.responseCode.String()),
		tag.Insert(tagTraceHTTPStatusCode, strconv.Itoa(d.traceHTTPStatusCode)),
		tag.Insert(tagRequestUserAgent, d.userAgent),
		tag.Insert(tagApiKey, d.apiKey),
	}

	return stats.RecordWithTags(ctx, tags,
		statTraceRequests.M(1),
		statTraceResourceSpans.M(int64(d.resourceSpanCount)),
		statTraceExternalSpans.M(int64(d.traceSpanCount)),
		statTraceProcessSeconds.M(d.processDuration.Seconds()),
		statTraceExternalSeconds.M(d.externalDuration.Seconds()),
	)
}

func sanitizeApiKeyForLogging(apiKey string) string {
	if len(apiKey) <= 8 {
		return apiKey
	}
	return apiKey[:8]
}