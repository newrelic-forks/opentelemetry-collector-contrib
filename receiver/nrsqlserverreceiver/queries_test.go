// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryContents(t *testing.T) {
	queryTests := []struct {
		name                     string
		instanceName             string
		getQuery                 func(string) string
		expectedQueryValFilename string
	}{
		{
			name:                     "Test database IO query without instance name",
			instanceName:             "",
			getQuery:                 getSQLServerDatabaseIOQuery,
			expectedQueryValFilename: "databaseIOQueryWithoutInstanceName.txt",
		},
		{
			name:                     "Test database IO query with instance name",
			instanceName:             "instanceName",
			getQuery:                 getSQLServerDatabaseIOQuery,
			expectedQueryValFilename: "databaseIOQueryWithInstanceName.txt",
		},
		{
			name:                     "Test perf counter query without instance name",
			instanceName:             "",
			getQuery:                 getSQLServerPerformanceCounterQuery,
			expectedQueryValFilename: "perfCounterQueryWithoutInstanceName.txt",
		},
		{
			name:                     "Test perf counter query with instance name",
			instanceName:             "instanceName",
			getQuery:                 getSQLServerPerformanceCounterQuery,
			expectedQueryValFilename: "perfCounterQueryWithInstanceName.txt",
		},
		{
			name:                     "Test properties query without instance name",
			instanceName:             "",
			getQuery:                 getSQLServerPropertiesQuery,
			expectedQueryValFilename: "propertyQueryWithoutInstanceName.txt",
		},
		{
			name:                     "Test properties query with instance name",
			instanceName:             "instanceName",
			getQuery:                 getSQLServerPropertiesQuery,
			expectedQueryValFilename: "propertyQueryWithInstanceName.txt",
		},
		{
			name:                     "Test wait stats query without instance name",
			instanceName:             "",
			getQuery:                 getSQLServerWaitStatsQuery,
			expectedQueryValFilename: "waitStatsQueryWithoutInstanceName.txt",
		},
		{
			name:                     "Test wait stats query with instance name",
			instanceName:             "instanceName",
			getQuery:                 getSQLServerWaitStatsQuery,
			expectedQueryValFilename: "waitStatsQueryWithInstanceName.txt",
		},
	}

	for _, tt := range queryTests {
		t.Run(tt.name, func(t *testing.T) {
			expectedBytes, err := os.ReadFile(path.Join("./testdata", tt.expectedQueryValFilename))
			require.NoError(t, err)
			// Replace all will fix newlines when testing on Windows
			expected := strings.ReplaceAll(string(expectedBytes), "\r\n", "\n")

			actual := tt.getQuery(tt.instanceName)
			require.Equal(t, expected, actual)
		})
	}
}

func TestQueryTextAndPlanQueryContents(t *testing.T) {
	queryTests := []struct {
		name                     string
		instanceName             string
		maxQuerySampleCount      uint
		lookbackTime             uint
		getQuery                 func() string
		expectedQueryValFilename string
	}{
		{
			name:                     "Test query text and query plan",
			instanceName:             "",
			maxQuerySampleCount:      1000,
			lookbackTime:             60,
			getQuery:                 getSQLServerQueryTextAndPlanQuery,
			expectedQueryValFilename: "databaseTopQueryWithoutInstanceName.txt",
		},
	}

	for _, tt := range queryTests {
		t.Run(tt.name, func(t *testing.T) {
			expected, err := os.ReadFile(path.Join("./testdata", tt.expectedQueryValFilename))
			require.NoError(t, err)
			actual := tt.getQuery()
			require.NoError(t, err)
			require.Equal(t, strings.TrimSpace(string(expected)), strings.TrimSpace(actual))
		})
	}
}

func TestGetSQLServerQuerySamplesQuery(t *testing.T) {
	queryTests := []struct {
		name                     string
		instanceName             string
		getQuery                 func() string
		expectedQueryValFilename string
		maxRowsPerQuery          uint64
	}{
		{
			name:                     "Test query sample query",
			instanceName:             "",
			maxRowsPerQuery:          1000,
			getQuery:                 getSQLServerQuerySamplesQuery,
			expectedQueryValFilename: "testQuerySampleQuery.txt",
		},
	}

	for _, tt := range queryTests {
		t.Run(tt.name, func(t *testing.T) {
			expectedBytes, err := os.ReadFile(path.Join("./testdata", tt.expectedQueryValFilename))
			require.NoError(t, err)
			// Replace all will fix newlines when testing on Windows
			expected := strings.ReplaceAll(string(expectedBytes), "\r\n", "\n")
			actual := strings.ReplaceAll(tt.getQuery(), "\r\n", "\n")
			require.Equal(t, expected, actual)
		})
	}
}

func TestGetSQLServerIdleBlockingSessionsQuery(t *testing.T) {
	expectedBytes, err := os.ReadFile(path.Join(".", "testdata", "testIdleBlockerQuerySampleQuery.txt"))
	require.NoError(t, err)

	expected := strings.ReplaceAll(string(expectedBytes), "\r\n", "\n")
	actual := strings.ReplaceAll(getSQLServerIdleBlockingSessionsQuery(), "\r\n", "\n")
	require.Equal(t, expected, actual)
}

// TestDirectConnectionQueriesIgnoreInstanceName guards against reintroducing the
// @@SERVERNAME filter: for a named instance (e.g. "SQL04\DB13"), @@SERVERNAME never
// equals the configured instance_name, so the predicate silently filtered out every
// row on a direct connection. A direct connection is already scoped to one instance,
// so instance_name must not filter these queries at all.
func TestDirectConnectionQueriesIgnoreInstanceName(t *testing.T) {
	queryFuncs := map[string]func(string) string{
		"getSQLServerDatabaseIOQuery":                     getSQLServerDatabaseIOQuery,
		"getSQLServerPerformanceCounterQuery":             getSQLServerPerformanceCounterQuery,
		"getSQLServerPropertiesQuery":                     getSQLServerPropertiesQuery,
		"getSQLServerTopProcedureQuery":                   getSQLServerTopProcedureQuery,
		"getSQLServerWaitStatsQuery":                      getSQLServerWaitStatsQuery,
		"getSQLServerDatabaseSizeQuery":                   getSQLServerDatabaseSizeQuery,
		"getSQLServerOSMemoryQuery":                       getSQLServerOSMemoryQuery,
		"getSQLServerOSDiskQuery":                         getSQLServerOSDiskQuery,
		"getSQLServerOSSchedulerRunnableTasksQuery":       getSQLServerOSSchedulerRunnableTasksQuery,
		"getSQLServerProcessCountQuery":                   getSQLServerProcessCountQuery,
		"getSQLServerThreadPoolQuery":                     getSQLServerThreadPoolQuery,
		"getSQLServerWorkerThreadsQuery":                  getSQLServerWorkerThreadsQuery,
		"getSQLServerTempDBQuery":                         getSQLServerTempDBQuery,
		"getSQLServerTempDBFileQuery":                     getSQLServerTempDBFileQuery,
		"getSQLServerFailoverClusterAGQuery":              getSQLServerFailoverClusterAGQuery,
		"getSQLServerFailoverClusterReplicaQuery":         getSQLServerFailoverClusterReplicaQuery,
		"getSQLServerFailoverClusterReplicaDatabaseQuery": getSQLServerFailoverClusterReplicaDatabaseQuery,
		"getSQLServerLongestRunningTransactionQuery":      getSQLServerLongestRunningTransactionQuery,
		"getSQLServerIndexPhysicalStatsQuery":             getSQLServerIndexPhysicalStatsQuery,
		"getSQLServerAvailabilityGroupQuery":              getSQLServerAvailabilityGroupQuery,
		"getSQLServerCPUMemoryQuery":                      getSQLServerCPUMemoryQuery,
		"getSQLServerDiskIOQuery":                         getSQLServerDiskIOQuery,
	}

	for name, fn := range queryFuncs {
		t.Run(name, func(t *testing.T) {
			withInstance := fn(`SQL04\DB13`)
			withoutInstance := fn("")
			require.Equal(t, withoutInstance, withInstance,
				"instance_name must not change the generated SQL for a direct connection")
			require.NotContains(t, withInstance, "@@SERVERNAME =",
				"a named instance's @@SERVERNAME never matches instance_name, so this predicate would silently filter out every row")
		})
	}
}

func TestFormatSQLServerSessionIDsParam(t *testing.T) {
	actual := formatSQLServerSessionIDsParam(map[int64]struct{}{
		91: {},
		60: {},
		77: {},
	})
	require.Equal(t, "60,77,91", actual)
}
