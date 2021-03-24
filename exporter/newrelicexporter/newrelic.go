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
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	"github.com/newrelic/newrelic-telemetry-sdk-go/telemetry"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

const (
	name    = "opentelemetry-collector"
	version = "0.0.0"
	product = "NewRelic-Collector-OpenTelemetry"
)

// exporter exports OpenTelemetry Collector data to New Relic.
type exporter struct {
	requestFactory telemetry.RequestFactory
	apiKeyHeader   string
	logger         *zap.Logger
}

type factoryBuilder func(options ...telemetry.ClientOption) (telemetry.RequestFactory, error)
type batchBuilder func() (telemetry.PayloadEntry, error)

func clientOptions(apiKey string, apiKeyHeader string, hostOverride string, insecure bool) []telemetry.ClientOption {
	options := []telemetry.ClientOption{telemetry.WithUserAgent(product + "/" + version)}
	if apiKey != "" {
		options = append(options, telemetry.WithInsertKey(apiKey))
	} else if apiKeyHeader != "" {
		options = append(options, telemetry.WithNoDefaultKey())
	}

	if hostOverride != "" {
		options = append(options, telemetry.WithEndpoint(hostOverride))
	}

	if insecure {
		options = append(options, telemetry.WithInsecure())
	}
	return options
}

func newExporter(l *zap.Logger, nrConfig endpointConfig, createFactory factoryBuilder) (exporter, error) {
	options := clientOptions(
		nrConfig.APIKey,
		nrConfig.APIKeyHeader,
		nrConfig.HostOverride,
		nrConfig.insecure,
	)
	f, err := createFactory(options...)
	if nil != err {
		return exporter{}, err
	}
	return exporter{
		requestFactory: f,
		apiKeyHeader:   strings.ToLower(nrConfig.APIKeyHeader),
		logger:         l,
	}, nil
}

func (e exporter) extractInsertKeyFromHeader(ctx context.Context) string {
	if e.apiKeyHeader == "" {
		return ""
	}

	// right now, we only support looking up attributes from requests that have gone through the gRPC server
	// in that case, it will add the HTTP headers as context metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	// we have gRPC metadata in the context but does it have our key?
	values, ok := md[e.apiKeyHeader]
	if !ok {
		return ""
	}

	return values[0]
}

func (e exporter) pushTraceData(ctx context.Context, td pdata.Traces) (outputErr error) {
	details := newTraceMetadata(ctx)
	details.dataInputCount = td.SpanCount()
	builder := func() (telemetry.PayloadEntry, error) { return e.buildTracePayload(&details, td) }
	return e.export(ctx, &details, builder)

}

func (e exporter) buildTracePayload(details *exportMetadata, td pdata.Traces) (telemetry.PayloadEntry, error) {
	var (
		errs  []error
		batch telemetry.SpanBatch
	)

	batch.Spans = make([]telemetry.Span, 0, details.dataInputCount)

	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rspans := td.ResourceSpans().At(i)
		resource := rspans.Resource()
		for j := 0; j < rspans.InstrumentationLibrarySpans().Len(); j++ {
			ispans := rspans.InstrumentationLibrarySpans().At(j)
			transform := newTransformer(resource, ispans.InstrumentationLibrary())
			for k := 0; k < ispans.Spans().Len(); k++ {
				span := ispans.Spans().At(k)
				nrSpan, err := transform.Span(span)
				if err != nil {
					e.logger.Debug("Transform of span failed.", zap.Error(err))
					errs = append(errs, err)
					continue
				}

				details.dataOutputCount++
				batch.Spans = append(batch.Spans, nrSpan)
			}
		}
	}
	return &batch, consumererror.CombineErrors(errs)
}

func (e exporter) pushLogData(ctx context.Context, ld pdata.Logs) (outputErr error) {
	details := newLogMetadata(ctx)
	details.dataInputCount = ld.LogRecordCount()
	builder := func() (telemetry.PayloadEntry, error) { return e.buildLogPayload(&details, ld) }
	return e.export(ctx, &details, builder)
}

func (e exporter) buildLogPayload(details *exportMetadata, ld pdata.Logs) (telemetry.PayloadEntry, error) {
	var (
		errs  []error
		batch telemetry.LogBatch
	)

	batch.Logs = make([]telemetry.Log, 0, details.dataInputCount)

	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		resourceLogs := ld.ResourceLogs().At(i)
		resource := resourceLogs.Resource()

		for j := 0; j < resourceLogs.InstrumentationLibraryLogs().Len(); j++ {
			instrumentationLibraryLogs := resourceLogs.InstrumentationLibraryLogs().At(j)

			transformer := newTransformer(resource, instrumentationLibraryLogs.InstrumentationLibrary())
			for k := 0; k < instrumentationLibraryLogs.Logs().Len(); k++ {
				log := instrumentationLibraryLogs.Logs().At(k)
				nrLog, err := transformer.Log(log)
				if err != nil {
					e.logger.Error("Transform of log failed.", zap.Error(err))
					errs = append(errs, err)
					continue
				}

				details.dataOutputCount++
				batch.Logs = append(batch.Logs, nrLog)
			}
		}
	}

	return &batch, consumererror.CombineErrors(errs)
}

func (e exporter) pushMetricData(ctx context.Context, md pdata.Metrics) (outputErr error) {
	details := newMetricMetadata(ctx)
	_, details.dataInputCount = md.MetricAndDataPointCount()
	builder := func() (telemetry.PayloadEntry, error) { return e.buildMetricPayload(&details, md) }
	return e.export(ctx, &details, builder)
}

func (e exporter) buildMetricPayload(details *exportMetadata, md pdata.Metrics) (telemetry.PayloadEntry, error) {
	var (
		errs  []error
		batch telemetry.MetricBatch
	)

	batch.Metrics = make([]telemetry.Metric, 0, details.dataInputCount)

	rms := md.ResourceMetrics()
	for i := 0; i < rms.Len(); i++ {
		rm := rms.At(i)
		ilms := rm.InstrumentationLibraryMetrics()
		for j := 0; j < ilms.Len(); j++ {
			ilm := ilms.At(j)
			ms := ilm.Metrics()
			transform := newTransformer(rm.Resource(), ilm.InstrumentationLibrary())
			for k := 0; k < ms.Len(); k++ {
				m := ms.At(k)
				nrMetrics, err := transform.Metric(m)
				if err != nil {
					e.logger.Debug("Transform of metric failed.", zap.Error(err))
					errs = append(errs, err)
					continue
				}
				details.dataOutputCount += len(nrMetrics)
				batch.Metrics = append(batch.Metrics, nrMetrics...)
			}
		}
	}

	return &batch, consumererror.CombineErrors(errs)
}

func (e exporter) export(ctx context.Context, details *exportMetadata, buildBatch batchBuilder) (outputErr error) {
	startTime := time.Now()
	insertKey := e.extractInsertKeyFromHeader(ctx)
	defer func() {
		details.apiKey = sanitizeAPIKeyForLogging(insertKey)
		details.exporterTime = time.Since(startTime)
		details.grpcResponseCode = status.Code(outputErr)
		err := details.recordMetrics(ctx)
		if err != nil {
			e.logger.Error("An error occurred recording metrics.", zap.Error(err))
		}
	}()

	batch, batchErrors := buildBatch()

	payloadEntries := []telemetry.PayloadEntry{batch}

	var options []telemetry.ClientOption
	if insertKey != "" {
		options = append(options, telemetry.WithInsertKey(insertKey))
	}
	req, err := e.requestFactory.BuildRequest(payloadEntries, options...)
	if err != nil {
		e.logger.Error("Failed to build batch", zap.Error(err))
		return err
	}

	if err := e.doRequest(details, req); err != nil {
		return err
	}

	return batchErrors
}

func (e exporter) doRequest(details *exportMetadata, req *http.Request) error {
	startTime := time.Now()
	defer func() { details.externalDuration = time.Since(startTime) }()
	// Execute the http request and handle the response
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		e.logger.Error("Error making HTTP request.", zap.Error(err))
		return &urlError{Err: err}
	}
	defer response.Body.Close()
	io.Copy(ioutil.Discard, response.Body)
	details.httpStatusCode = response.StatusCode

	// Check if the http payload has been accepted, if not record an error
	if response.StatusCode != http.StatusAccepted {
		// Log the error at an appropriate level based on the status code
		if response.StatusCode >= 500 {
			// The data has been lost, but it is due to a server side error
			e.logger.Warn("Server HTTP error", zap.String("Status", response.Status))
		} else if response.StatusCode == http.StatusForbidden {
			// The data has been lost, but it is due to an invalid api key
			e.logger.Debug("HTTP Forbidden response", zap.String("Status", response.Status))
		} else {
			// The data has been lost due to an error in our payload
			details.dataOutputCount = 0
			e.logger.Error("Client HTTP error.", zap.String("Status", response.Status))
		}

		return &httpError{Response: response}
	}
	return nil
}
