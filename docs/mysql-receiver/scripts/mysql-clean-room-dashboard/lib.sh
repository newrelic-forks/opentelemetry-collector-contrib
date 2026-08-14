#!/usr/bin/env bash
# Shared NerdGraph helper for the clean-room MySQL dashboard build.
set -euo pipefail

ENV_FILE="/Users/atiwari/Desktop/Projects/db-test-lab-nrmysql/.env"
NERDGRAPH_URL="https://staging-api.newrelic.com/graphql"

nrgraphql() {
  local body_file="$1"
  set -a; source "$ENV_FILE"; set +a
  curl -s "$NERDGRAPH_URL" \
    -H "Content-Type: application/json" \
    -H "API-Key: ${NEW_RELIC_API_KEY}" \
    -d @"$body_file"
}
