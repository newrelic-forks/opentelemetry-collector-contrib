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
	tagGrpcStatusCode, _   = tag.NewKey("grpc_response_code")
	tagHttpStatusCode, _   = tag.NewKey("http_status_code")
	tagRequestUserAgent, _ = tag.NewKey("user_agent")
	tagApiKey, _           = tag.NewKey("api_key")
	tagDataType, _         = tag.NewKey("data_type")
	tagKeys                = []tag.Key{tagGrpcStatusCode, tagHttpStatusCode, tagRequestUserAgent, tagApiKey, tagDataType}

	statRequestCount         = stats.Int64("newrelicexporter_request_count", "Number of requests processed", stats.UnitDimensionless)
	statOutputDatapointCount = stats.Int64("newrelicexporter_output_datapoint_count", "Number of data points sent to the HTTP API", stats.UnitDimensionless)
	statExporterTime         = stats.Float64("newrelicexporter_exporter_time", "Wall clock time (seconds) spent in the exporter", stats.UnitSeconds)
	statExternalTime         = stats.Float64("newrelicexporter_external_time", "Wall clock time (seconds) spent sending data to the HTTP API", stats.UnitSeconds)
)

// MetricViews return metric views for Kafka receiver.
func MetricViews() []*view.View {
	return []*view.View{
		buildView(tagKeys, statRequestCount, view.Sum()),
		buildView(tagKeys, statOutputDatapointCount, view.Sum()),
		buildView(tagKeys, statExporterTime, view.Sum()),
		buildView(tagKeys, statExternalTime, view.Sum()),
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

type exportMetadata struct {
	// Metric tags
	grpcResponseCode codes.Code // The gRPC response code
	httpStatusCode   int        // The HTTP response status code form the HTTP API
	apiKey           string     // The API key from the request
	userAgent        string     // The User-Agent from the request
	dataType         string     // The type of data being recorded

	// Metric values
	dataInputCount   int           // Number of resource spans in the request
	dataOutputCount  int           // Number of spans sent to the trace API
	exporterTime     time.Duration // Total time spent in the newrelic exporter
	externalDuration time.Duration // Time spent sending to the trace API
}

func newTraceMetadata(ctx context.Context) *exportMetadata {
	return initMetadata(ctx, "trace")
}

func newLogMetadata(ctx context.Context) *exportMetadata {
	return initMetadata(ctx, "log")
}

func initMetadata(ctx context.Context, dataType string) *exportMetadata {
	userAgent := "not_present"
	if md, ctxOk := metadata.FromIncomingContext(ctx); ctxOk {
		if values, headerOk := md["user-agent"]; headerOk {
			userAgent = values[0]
		}
	}

	return &exportMetadata{userAgent: userAgent, apiKey: "not_present", dataType: dataType}
}

func (d *exportMetadata) recordMetrics(ctx context.Context) error {
	tags := []tag.Mutator{
		tag.Insert(tagGrpcStatusCode, d.grpcResponseCode.String()),
		tag.Insert(tagHttpStatusCode, strconv.Itoa(d.httpStatusCode)),
		tag.Insert(tagRequestUserAgent, d.userAgent),
		tag.Insert(tagApiKey, d.apiKey),
		tag.Insert(tagDataType, d.dataType),
	}

	return stats.RecordWithTags(ctx, tags,
		statRequestCount.M(1),
		statOutputDatapointCount.M(int64(d.dataOutputCount)),
		statExporterTime.M(d.exporterTime.Seconds()),
		statExternalTime.M(d.externalDuration.Seconds()),
	)
}

func sanitizeApiKeyForLogging(apiKey string) string {
	if len(apiKey) <= 8 {
		return apiKey
	}
	return apiKey[:8]
}
