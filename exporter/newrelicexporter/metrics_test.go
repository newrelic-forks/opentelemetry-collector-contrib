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

func TestRecordMetrics(t *testing.T) {
	if err := view.Register(MetricViews()...); err != nil {
		t.Fail()
	}

	details := []exportMetadata{
		// A request that completes normally
		{
			grpcResponseCode: codes.OK,
			httpStatusCode:   200,
			apiKey:           "shhh",
			userAgent:        "secret agent",
			dataType:         "data",
			dataInputCount:   2,
			exporterTime:     100,
			dataOutputCount:  20,
			externalDuration: 50,
		},
		// A request that receives 403 status code from the HTTP API
		{
			grpcResponseCode: codes.Unauthenticated,
			httpStatusCode:   403,
			apiKey:           "shhh",
			userAgent:        "secret agent",
			dataType:         "data",
			dataInputCount:   2,
			exporterTime:     100,
			dataOutputCount:  20,
			externalDuration: 50,
		},
		// A request experiences a url.Error while sending to the HTTP API
		{
			grpcResponseCode: codes.DataLoss,
			httpStatusCode:   0,
			apiKey:           "shhh",
			userAgent:        "secret agent",
			dataType:         "data",
			dataInputCount:   2,
			exporterTime:     100,
			dataOutputCount:  20,
			externalDuration: 50,
		},
	}

	for _, traceDetails := range details {
		if err := traceDetails.recordMetrics(context.TODO()); err != nil {
			t.Fail()
		}
	}

	measurements := []stats.Measure{
		statRequestCount,
		statOutputDatapointCount,
		statExporterTime,
		statExternalTime,
	}

	for _, measurement := range measurements {
		rows, err := view.RetrieveData(measurement.Name())
		if err != nil {
			t.Fail()
		}
		// Check that each measurement has a number of rows corresponding to the tag set produced by the interactions
		assert.Equal(t, len(details), len(rows))
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
	assert.Equal(t, "", sanitizeApiKeyForLogging(""))
	assert.Equal(t, "foo", sanitizeApiKeyForLogging("foo"))
	assert.Equal(t, "foobarba", sanitizeApiKeyForLogging("foobarbazqux"))
}
