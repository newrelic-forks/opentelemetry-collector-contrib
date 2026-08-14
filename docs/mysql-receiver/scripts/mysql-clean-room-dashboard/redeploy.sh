#!/usr/bin/env bash
# Update-in-place redeploy: pushes the current 6 page-*.json files to the
# existing dashboard GUID via dashboardUpdate, instead of creating a new
# dashboard (which is what assemble-and-create.sh does).
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh

GUID="$(cat dashboard-guid.txt)"
DASHBOARD_NAME="MySQL Query Performance Monitoring — nrmysqlreceiver (clean-room)"

python3 - "$DASHBOARD_NAME" "$GUID" <<'PYEOF' > /tmp/dashboard-update.json
import json, sys

name, guid = sys.argv[1], sys.argv[2]
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
        "mutation($guid: EntityGuid!, $dashboard: DashboardInput!) { "
        "dashboardUpdate(guid: $guid, dashboard: $dashboard) { "
        "entityResult { guid name } errors { description type } } }"
    ),
    "variables": {"guid": guid, "dashboard": dashboard},
}
json.dump(mutation, sys.stdout)
PYEOF

nrgraphql /tmp/dashboard-update.json | tee /tmp/dashboard-update-response.json
