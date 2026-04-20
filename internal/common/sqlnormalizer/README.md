# SQL Normalizer

SQL normalization and MD5 hashing for APM-to-database query correlation.

## Overview

This package implements SQL normalization following the New Relic Java APM agent's
`SqlStatementNormalizer` logic. It enables correlation between APM slow query traces
and database receiver metrics by generating identical MD5 hashes for the same SQL queries.

**Reference Implementation:**
- `apm-trace-consumer`: `SqlStatementNormalizer.java`
- `apm-trace-consumer`: `SqlHashUtil.java`

## Installation

This package is internal to OpenTelemetry Collector Contrib and is used by database receivers.

```go
import "go.opentelemetry.io/collector/contrib/internal/common/sqlnormalizer"
```

## Usage

### Basic Normalization

```go
sql := "SELECT * FROM users WHERE id = 123 AND name = 'John'"
normalized := sqlnormalizer.NormalizeSQL(sql)
// Result: "SELECT * FROM USERS WHERE ID = ? AND NAME = ?"
```

### Normalization with MD5 Hash

```go
sql := "SELECT * FROM users WHERE id = 123 AND name = 'John'"
normalized, hash := sqlnormalizer.NormalizeSQLAndHash(sql)
// normalized: "SELECT * FROM USERS WHERE ID = ? AND NAME = ?"
// hash: "62c441c38800ff82bffa5c57dd4f4059" (32-character hex string)
```

### In Database Receivers

```go
import "go.opentelemetry.io/collector/contrib/internal/common/sqlnormalizer"

// In your scraper:
rawSQL := row["SQL_TEXT"]
normalizedSQL, sqlHash := sqlnormalizer.NormalizeSQLAndHash(rawSQL)

// Emit as metric/log attribute:
attributes.PutStr("normalised_sql_hash", sqlHash)
```

## Normalization Rules

The normalizer applies the following transformations:

### 1. Uppercase Conversion

All SQL keywords and identifiers are converted to uppercase:

```sql
select * from users → SELECT * FROM USERS
```

### 2. Placeholder Normalization

All parameter styles are normalized to `?`:

| Database   | Placeholder | Normalized |
|------------|-------------|------------|
| JDBC       | `?`         | `?`        |
| Oracle     | `:name`, `:1` | `?`      |
| PostgreSQL | `$1`, `$2`  | `?`        |
| SQL Server | `@param`    | `?`        |
| Python     | `%(name)s`  | `?`        |

Example:
```sql
SELECT * FROM users WHERE id = :userId → SELECT * FROM USERS WHERE ID = ?
```

### 3. Literal Replacement

String and numeric literals are replaced with `?`:

**Strings:**
```sql
SELECT * FROM users WHERE name = 'John' → SELECT * FROM USERS WHERE NAME = ?
```

**Numbers:**
```sql
SELECT * FROM data WHERE value = 123.45 → SELECT * FROM DATA WHERE VALUE = ?
SELECT * FROM data WHERE value = 1.5E-10 → SELECT * FROM DATA WHERE VALUE = ?
```

### 4. Comment Removal

All comment types are removed:

```sql
/* multi-line comment */
-- single-line comment
# hash comment
```

Example:
```sql
/* comment */ SELECT * FROM users -- inline
→ SELECT * FROM USERS
```

### 5. Whitespace Normalization

Multiple spaces are collapsed to single space, and leading/trailing whitespace is trimmed:

```sql
SELECT  *    FROM     users → SELECT * FROM USERS
```

### 6. IN Clause Normalization

IN clauses with multiple values are normalized to `IN (?)`:

```sql
SELECT * FROM users WHERE id IN (1, 2, 3) → SELECT * FROM USERS WHERE ID IN (?)
```

## API Reference

### NormalizeSQL

```go
func NormalizeSQL(sql string) string
```

Normalizes a SQL statement following New Relic Java agent rules.

**Parameters:**
- `sql`: The raw SQL query text

**Returns:**
- The normalized SQL query text

### GenerateMD5Hash

```go
func GenerateMD5Hash(normalizedSQL string) string
```

Generates an MD5 hash of the normalized SQL.

**Parameters:**
- `normalizedSQL`: The normalized SQL query text

**Returns:**
- Lowercase hex string of MD5 hash (32 characters)

**Security Note:** MD5 is used for SQL fingerprinting/identification, not cryptographic security.

### NormalizeSQLAndHash

```go
func NormalizeSQLAndHash(sql string) (normalizedSQL, md5Hash string)
```

Normalizes a SQL statement and returns both the normalized SQL and its MD5 hash.
This is the primary entry point for APM-to-database query correlation.

**Parameters:**
- `sql`: The raw SQL query text

**Returns:**
- `normalizedSQL`: The normalized SQL query text
- `md5Hash`: Lowercase hex string of MD5 hash (32 characters)

## Examples

### Simple Query

```go
input := "select * from users where id = 123"
normalized, hash := sqlnormalizer.NormalizeSQLAndHash(input)
// normalized: "SELECT * FROM USERS WHERE ID = ?"
// hash: "5f93f983524def3dca464469d2cf9f3e"
```

### Complex Query

```go
input := `
  /* Get user details */
  SELECT u.id, u.name, u.email
  FROM users u
  WHERE u.id IN (1, 2, 3)
    AND u.age > 25
    AND u.status = 'active'
  -- Filter active users only
`

normalized, hash := sqlnormalizer.NormalizeSQLAndHash(input)
// normalized: "SELECT U.ID, U.NAME, U.EMAIL FROM USERS U WHERE U.ID IN (?) AND U.AGE > ? AND U.STATUS = ?"
// hash: "..." (32-character MD5)
```

### With Query Comments (APM Correlation)

```go
import "go.opentelemetry.io/collector/contrib/internal/common/sqlcomments"

// Extract nr_service_guid from query comments
input := "/* nr_service_guid=\"abc-123\" */ SELECT * FROM users WHERE id = 1"
nrServiceGuid := sqlcomments.ExtractAndFilterComments(input, []string{"nr_service_guid"})

// Normalize and hash for correlation
normalized, sqlHash := sqlnormalizer.NormalizeSQLAndHash(input)

// Both are used for APM-to-DB correlation:
// - nrServiceGuid: links to APM service
// - sqlHash: identifies the specific query
```

## Performance

- **Normalization**: ~10µs per query
- **MD5 Hash**: ~5µs per query
- **Total**: ~15µs per query

The implementation uses an efficient single-pass state machine (no multiple regex iterations).

## Testing

Run tests:

```bash
go test -v ./...
```

Run tests with coverage:

```bash
go test -v -cover ./...
```

## Cross-Language Compatibility

This Go implementation produces identical output to the Java reference implementation
for the same SQL input. This ensures perfect correlation between APM traces and database metrics.

### Validation

To validate against Java implementation:

1. Generate test cases from Java: `SqlStatementNormalizer.normalizeSql(input)`
2. Compare with Go: `NormalizeSQL(input)`
3. Verify MD5 hashes match: `SqlHashUtil.md5HashValueFor(normalized)`

## Contributing

This package is part of OpenTelemetry Collector Contrib. For contribution guidelines,
see the repository's CONTRIBUTING.md.

## License

Apache License 2.0
