#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh

DASHBOARD_NAME="MySQL Query Performance Monitoring — nrmysqlreceiver (clean-room)"

python3 - "$DASHBOARD_NAME" <<'PYEOF' > /tmp/dashboard-create.json
import json, sys

name = sys.argv[1]
pages = []
for f in [
    "page-1-overview.json",
    "page-2-top-queries.json",
    "page-3-live-sessions.json",
    "page-4-wait-blocking.json",
    "page-5-execution-plans.json",
    "page-6-storage-capacity.json",
]:
    with open(f) as fh:
        pages.append(json.load(fh))

dashboard = {
    "name": name,
    "permissions": "PUBLIC_READ_WRITE",
    "pages": pages,
    "variables": [],
}

mutation = {
    "query": (
        "mutation($accountId: Int!, $dashboard: DashboardInput!) { "
        "dashboardCreate(accountId: $accountId, dashboard: $dashboard) { "
        "entityResult { guid name } errors { description type } } }"
    ),
    "variables": {"accountId": 754495, "dashboard": dashboard},
}
json.dump(mutation, sys.stdout)
PYEOF

nrgraphql /tmp/dashboard-create.json | tee /tmp/dashboard-create-response.json
