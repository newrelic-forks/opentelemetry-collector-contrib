# SQL Server Receiver - Validation Scripts

Standalone PowerShell scripts to validate the sqlserver receiver's debug output against real SQL Server values. Runs on the same Windows VM as the collector — no extra dependencies needed.

## Scripts

### 1. `Validate-SqlServerMetrics.ps1` — Single Snapshot

Parses the debug log file and compares values against current SQL Server state.

**What it checks:**
- Delta values are non-negative
- Delta values don't exceed cumulative totals
- Database names match
- String attribute correctness

```powershell
.\Validate-SqlServerMetrics.ps1 `
    -DebugLogPath "C:\ProgramData\OpenTelemetry\Collector\Logs\otelcol.log" `
    -Server "MssqlOtel" `
    -Port 1433 `
    -Username "sa" `
    -Password "YourPassword"
```

### 2. `Validate-Deltas.ps1` — Two-Snapshot Delta Validation

Takes two SQL Server snapshots with a wait in between, then compares the computed delta against what the collector reported.

**What it checks:**
- Collector's delta values match actual SQL Server changes (T2 - T1)
- Unit conversions are correct (microseconds → seconds)
- All delta fields: execution_count, total_elapsed_time, total_worker_time, logical_reads, physical_reads, logical_writes, total_rows, total_grant_kb

```powershell
.\Validate-Deltas.ps1 `
    -Server "MssqlOtel" `
    -Port 1433 `
    -Username "sa" `
    -Password "YourPassword" `
    -DebugLogPath "C:\ProgramData\OpenTelemetry\Collector\Logs\otelcol.log" `
    -WaitSeconds 65
```

**Important:** Set `-WaitSeconds` to be >= your `top_query_collection.collection_interval` (default 60s).

## Prerequisites

- Windows VM with PowerShell 5.1+ (pre-installed on Windows)
- SQL Server accessible with VIEW SERVER STATE permission
- OTel Collector running with `debug` exporter (`verbosity: detailed`)
- Collector logs written to file via `service.telemetry.logs.output_paths`

## Collector Config Required

```yaml
exporters:
  debug:
    verbosity: detailed

service:
  telemetry:
    logs:
      output_paths:
        - ${ProgramData}\OpenTelemetry\Collector\Logs\otelcol.log
```

## Query Covered

Currently validates: `dbQueryAndTextQuery.tmpl` (top query / `db.server.top_query` log events)

Fields validated:
| Field | Type | Unit Conversion |
|-------|------|-----------------|
| execution_count | delta (int) | none |
| total_elapsed_time | delta (double) | microseconds → seconds |
| total_worker_time | delta (double) | microseconds → seconds |
| total_logical_reads | delta (int) | none |
| total_physical_reads | delta (int) | none |
| total_logical_writes | delta (int) | none |
| total_rows | delta (int) | none |
| total_grant_kb | delta (int) | none |
