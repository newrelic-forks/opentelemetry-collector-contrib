#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh

# Two dashboard-wide variables: {{endpoint}} applied to every page (empty
# isMultiSelection list = global), {{queryHash}} applies only where the
# widget itself references it (NerdGraph scopes variables by usage, not by
# an explicit page list).
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
    "variables": [
        {
            "name": "endpoint",
            "title": "MySQL Instance Endpoint",
            "type": "STRING",
            "isMultiSelection": False,
            "replacementStrategy": "DEFAULT",
            "nrqlQuery": {
                "accountIds": [754495],
                "query": "FROM Metric SELECT uniques(`mysql.instance.endpoint`) SINCE 1 day ago",
            },
        },
        {
            "name": "queryHash",
            "title": "Query Hash (db.query.text.normalized.hash)",
            "type": "STRING",
            "isMultiSelection": False,
            "replacementStrategy": "DEFAULT",
            "nrqlQuery": {
                "accountIds": [754495],
                "query": "FROM Log SELECT uniques(`db.query.text.normalized.hash`) WHERE `event.name` = 'db.server.query_sample' SINCE 1 day ago",
            },
        },
    ],
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
