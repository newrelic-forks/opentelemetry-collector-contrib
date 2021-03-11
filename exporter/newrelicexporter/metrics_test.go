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
	"github.com/stretchr/testify/assert"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"strings"
	"testing"
)

func TestMetricViews(t *testing.T) {
	metricViews := MetricViews()

	assert.True(t, len(metricViews) > 0)
	for _, curView := range metricViews {
		assert.True(t, strings.HasPrefix(curView.Name, "newrelicexporter_"))
		assert.NotNil(t, curView.Aggregation)
		assert.NotNil(t, curView.Description)
		assert.Equal(t, tagKeys, curView.TagKeys)
		assert.NotNil(t, curView.Aggregation)
	}
}

func TestRecordPushTraceData(t *testing.T) {
	if err := view.Register(MetricViews()...); err != nil {
		t.Fail()
	}

	generator := func(ctx context.Context, mutator func(details *traceDetails)) *traceDetails {
		td := newTraceDetails(ctx)
		td.responseCode = codes.OK
		td.traceHTTPStatusCode = 200
		td.resourceSpanCount = 2
		td.processDuration = 100
		td.traceSpanCount = 20
		td.externalDuration = 50
		td.apiKey = "foo"
		mutator(td)
		return td
	}

	userAgentCtx := metadata.NewIncomingContext(context.Background(), map[string][]string{"user-agent": {"grpc-dummy-agent-1"}})
	noUserAgentCtx := metadata.NewIncomingContext(context.Background(), make(map[string][]string))
	details := []traceDetails{
		// A request that completes normally
		*generator(userAgentCtx, func(td *traceDetails) {}),
		// A request that completes normally, but without a user-agent header
		*generator(noUserAgentCtx, func(td *traceDetails) {}),
		// A request that receives 403 status code from trace API
		*generator(userAgentCtx, func(td *traceDetails) {
			td.responseCode = codes.Unauthenticated
			td.traceHTTPStatusCode = 403
		}),
		// A request experiences a url.Error while sending to trace API
		*generator(userAgentCtx, func(td *traceDetails) {
			td.responseCode = codes.DataLoss
			td.traceHTTPStatusCode = 0
		}),
	}

	for _, traceDetails := range details {
		if err := traceDetails.recordPushTraceData(userAgentCtx); err != nil {
			t.Fail()
		}
	}

	measurements := []stats.Measure{
		statTraceRequests,
		statTraceResourceSpans,
		statTraceExternalSpans,
		statTraceProcessSeconds,
		statTraceExternalSeconds,
	}

	for _, measurement := range measurements {
		rows, err := view.RetrieveData(measurement.Name())
		if err != nil {
			t.Fail()
		}
		// Check that each measurement has a number of rows corresponding to the tag set produced by the interactions
		assert.Equal(t, 4, len(rows))
		for _, row := range rows {
			// Confirm each row has data and has the required tag keys
			assert.True(t, row.Data != nil)
			assert.Equal(t, len(tagKeys), len(row.Tags))
			for _, rowTag := range row.Tags {
				assert.Contains(t, tagKeys, rowTag.Key)
			}
		}
	}
}

func TestSanitizeApiKeyForLogging(t *testing.T) {
	assert.Equal(t, "", sanitizeAPIKeyForLogging(""))
	assert.Equal(t, "foo", sanitizeAPIKeyForLogging("foo"))
	assert.Equal(t, "foobarba", sanitizeAPIKeyForLogging("foobarbazqux"))
}
