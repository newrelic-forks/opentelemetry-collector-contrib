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
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/status"

	"github.com/newrelic/newrelic-telemetry-sdk-go/cumulative"
	"github.com/newrelic/newrelic-telemetry-sdk-go/telemetry"
	"go.opentelemetry.io/collector/config/configmodels"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/consumer/pdata"
	"go.opentelemetry.io/collector/translator/internaldata"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/metadata"
)

const (
	name    = "opentelemetry-collector"
	version = "0.0.0"
	product = "NewRelic-Collector-OpenTelemetry"
)

var _ io.Writer = logWriter{}

// logWriter wraps a zap.Logger into an io.Writer.
type logWriter struct {
	logf func(string, ...zapcore.Field)
}

// Write implements io.Writer
func (w logWriter) Write(p []byte) (n int, err error) {
	w.logf(string(p))
	return len(p), nil
}

// exporter exporters OpenTelemetry Collector data to New Relic.
type exporter struct {
	deltaCalculator    *cumulative.DeltaCalculator
	harvester          *telemetry.Harvester
	spanRequestFactory telemetry.RequestFactory
	logRequestFactory  telemetry.RequestFactory
	apiKeyHeader       string
	logger             *zap.Logger
}

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

func newMetricsExporter(l *zap.Logger, c configmodels.Exporter) (*exporter, error) {
	nrConfig, ok := c.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config: %#v", c)
	}

	opts := []func(*telemetry.Config){
		nrConfig.HarvestOption,
		telemetry.ConfigBasicErrorLogger(logWriter{l.Error}),
		telemetry.ConfigBasicDebugLogger(logWriter{l.Info}),
		telemetry.ConfigBasicAuditLogger(logWriter{l.Debug}),
	}

	h, err := telemetry.NewHarvester(opts...)
	if nil != err {
		return nil, err
	}

	return &exporter{
		deltaCalculator: cumulative.NewDeltaCalculator(),
		harvester:       h,
	}, nil
}

func newTraceExporter(l *zap.Logger, c configmodels.Exporter) (*exporter, error) {
	nrConfig, ok := c.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config: %#v", c)
	}

	options := clientOptions(
		nrConfig.APIKey,
		nrConfig.APIKeyHeader,
		nrConfig.SpansHostOverride,
		nrConfig.spansInsecure,
	)
	s, err := telemetry.NewSpanRequestFactory(options...)
	if nil != err {
		return nil, err
	}

	return &exporter{
		spanRequestFactory: s,
		apiKeyHeader:       strings.ToLower(nrConfig.APIKeyHeader),
		logger:             l,
	}, nil
}

func newLogsExporter(logger *zap.Logger, c configmodels.Exporter) (*exporter, error) {
	nrConfig, ok := c.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config: %#v", c)
	}

	options := clientOptions(
		nrConfig.APIKey,
		nrConfig.APIKeyHeader,
		nrConfig.LogsHostOverride,
		nrConfig.logsInsecure,
	)
	logRequestFactory, err := telemetry.NewLogRequestFactory(options...)
	if err != nil {
		return nil, err
	}

	return &exporter{
		logRequestFactory: logRequestFactory,
		apiKeyHeader:      strings.ToLower(nrConfig.APIKeyHeader),
		logger:            logger,
	}, nil
}

func (e *exporter) extractInsertKeyFromHeader(ctx context.Context) string {
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

func (e *exporter) pushTraceData(ctx context.Context, td pdata.Traces) (outputErr error) {
	var (
		errs      []error
		sentCount int
	)

	startTime := time.Now()
	insertKey := e.extractInsertKeyFromHeader(ctx)

	details := newTraceMetadata(ctx)
	defer func() {
		apiKey := sanitizeApiKeyForLogging(insertKey)
		if apiKey != "" {
			details.apiKey = apiKey
		}
		details.dataOutputCount = sentCount
		details.exporterTime = time.Now().Sub(startTime)
		details.grpcResponseCode = status.Code(outputErr)
		err := details.recordMetrics(ctx)
		if err != nil {
			e.logger.Error("An error occurred recording metrics.", zap.Error(err))
		}
	}()

	var batch telemetry.SpanBatch

	for i := 0; i < td.ResourceSpans().Len(); i++ {
		rspans := td.ResourceSpans().At(i)
		resource := rspans.Resource()
		for j := 0; j < rspans.InstrumentationLibrarySpans().Len(); j++ {
			ispans := rspans.InstrumentationLibrarySpans().At(j)
			transform := newTraceTransformer(resource, ispans.InstrumentationLibrary())
			spans := make([]telemetry.Span, 0, ispans.Spans().Len())
			for k := 0; k < ispans.Spans().Len(); k++ {
				span := ispans.Spans().At(k)
				nrSpan, err := transform.Span(span)
				if err != nil {
					e.logger.Error("Transform of span failed.", zap.Error(err))
					errs = append(errs, err)
					continue
				}

				spans = append(spans, nrSpan)
				sentCount++
			}
			batch.Spans = append(batch.Spans, spans...)
		}
	}
	batches := []telemetry.PayloadEntry{&batch}
	var req *http.Request
	var err error

	if insertKey != "" {
		req, err = e.spanRequestFactory.BuildRequest(batches, telemetry.WithInsertKey(insertKey))
	} else {
		req, err = e.spanRequestFactory.BuildRequest(batches)
	}
	if err != nil {
		sentCount = 0
		e.logger.Error("Failed to build batch", zap.Error(err))
		return err
	}

	// Execute the http request and handle the response
	httpStatusCode, err := e.doRequest(details, req)
	if err != nil {
		// We also treat downstream service unavailability as successful for our purposes
		if httpStatusCode != http.StatusForbidden && httpStatusCode != http.StatusServiceUnavailable {
			sentCount = 0
		}
		return err
	}

	return consumererror.CombineErrors(errs)

}

func (e *exporter) pushLogData(ctx context.Context, ld pdata.Logs) (outputErr error) {
	var (
		errs      []error
		sentCount int
		batch     telemetry.LogBatch
	)

	startTime := time.Now()
	insertKey := e.extractInsertKeyFromHeader(ctx)

	details := newLogMetadata(ctx)
	defer func() {
		apiKey := sanitizeApiKeyForLogging(insertKey)
		if apiKey != "" {
			details.apiKey = apiKey
		}
		details.dataInputCount = ld.ResourceLogs().Len()
		details.dataOutputCount = sentCount
		details.exporterTime = time.Now().Sub(startTime)
		details.grpcResponseCode = status.Code(outputErr)
		err := details.recordMetrics(ctx)
		if err != nil {
			e.logger.Error("An error occurred recording metrics.", zap.Error(err))
		}
	}()

	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		resourceLogs := ld.ResourceLogs().At(i)
		resource := resourceLogs.Resource()

		for j := 0; j < resourceLogs.InstrumentationLibraryLogs().Len(); j++ {
			instrumentationLibraryLogs := resourceLogs.InstrumentationLibraryLogs().At(j)

			transformer := newLogTransformer(resource, instrumentationLibraryLogs.InstrumentationLibrary())
			for k := 0; k < instrumentationLibraryLogs.Logs().Len(); k++ {
				log := instrumentationLibraryLogs.Logs().At(k)
				nrLog, err := transformer.Log(log)
				if err != nil {
					e.logger.Error("Transform of log failed.", zap.Error(err))
					errs = append(errs, err)
					continue
				}

				sentCount++
				batch.Logs = append(batch.Logs, nrLog)
			}
		}
	}

	batches := []telemetry.PayloadEntry{&batch}
	var options []telemetry.ClientOption
	if insertKey != "" {
		options = append(options, telemetry.WithInsertKey(insertKey))
	}
	req, err := e.logRequestFactory.BuildRequest(batches, options...)
	if err != nil {
		sentCount = 0
		e.logger.Error("Failed to build batch", zap.Error(err))
		return err
	}

	httpStatusCode, err := e.doRequest(details, req)
	if err != nil {
		// We treat data that is sent with an incorrect API key as successful for our purposes
		// We also treat downstream service unavailability as successful for our purposes
		if httpStatusCode != http.StatusForbidden && httpStatusCode != http.StatusServiceUnavailable {
			sentCount = 0
		}
		return err
	}

	return nil
}

func (e *exporter) pushMetricData(ctx context.Context, md pdata.Metrics) error {
	var errs []error

	ocmds := internaldata.MetricsToOC(md)
	for index, ocmd := range ocmds {
		var srv string

		if ocmd.Node != nil && ocmd.Node.ServiceInfo != nil {
			srv = ocmd.Node.ServiceInfo.Name
		}

		language, _ := md.ResourceMetrics().At(index).Resource().Attributes().Get(instrumentationLanguageKey)

		transform := &metricTransformer{
			DeltaCalculator: e.deltaCalculator,
			ServiceName:     srv,
			Resource:        ocmd.Resource,
			Language:        language.StringVal(),
		}

		for _, metric := range ocmd.Metrics {
			nrMetrics, err := transform.Metric(metric)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			// TODO: optimize this, RecordMetric locks each call.
			for _, m := range nrMetrics {
				e.harvester.RecordMetric(m)
			}
		}
	}

	e.harvester.HarvestNow(ctx)

	return consumererror.CombineErrors(errs)
}

func (e *exporter) doRequest(details *exportMetadata, req *http.Request) (statusCode int, err error) {

	startTime := time.Now()
	// Execute the http request and handle the response
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		e.logger.Error("Error making HTTP request.", zap.Error(err))
		return 0, &urlError{Err: err}
	}
	defer response.Body.Close()
	io.Copy(ioutil.Discard, response.Body)
	details.externalDuration = time.Now().Sub(startTime)
	details.httpStatusCode = response.StatusCode

	// Check if the http payload has been accepted, if not record an error
	if response.StatusCode != http.StatusAccepted {
		// Log the error at an appropriate level based on the status code
		if response.StatusCode >= 500 {
			e.logger.Error("Error on HTTP response.", zap.String("Status", response.Status))
		} else {
			e.logger.Debug("Error on HTTP response.", zap.String("Status", response.Status))
		}

		return response.StatusCode, &httpError{Response: response}
	}

	return response.StatusCode, nil
}

func (e *exporter) Shutdown(ctx context.Context) error {
	e.harvester.HarvestNow(ctx)
	return nil
}
