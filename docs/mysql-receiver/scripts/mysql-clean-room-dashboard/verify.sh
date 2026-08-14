#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./lib.sh

GUID="$(cat dashboard-guid.txt)"

cat > /tmp/verify-query.json <<EOF
{"query": "{ actor { entity(guid: \"${GUID}\") { guid name ... on DashboardEntity { pages { name widgets { title } } } } } } "}
EOF

nrgraphql /tmp/verify-query.json | tee /tmp/verify-response.json
echo
echo "Page/widget counts:"
jq '.data.actor.entity.pages[] | {name, widgetCount: (.widgets | length)}' /tmp/verify-response.json
