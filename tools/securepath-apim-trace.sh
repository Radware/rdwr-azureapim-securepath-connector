#!/usr/bin/env bash
# Radware SecurePath connector for Azure API Management — trace one request and read the result.
#
# Works without the Portal (private gateways, traffic through Front Door): obtains a one-hour debug
# token for the API, sends ONE request the way your clients do, fetches the trace by its id, saves
# it, redacts the credentials inside it, and prints what happened to that request.
#
# Runs in bash: Azure Cloud Shell, macOS, Linux, Git Bash. Needs: az (logged in, with rights on the
# API Management instance), curl. python3 is optional — with it, the trace is redacted and the
# readout comes from securepath-apim-lint.py --trace; without it, the key lines are grepped out
# of the trace and the file is NOT redacted (see the warning it prints).
#
# Usage — set the four values below (or export them), then run. Anything after the script name is
# passed to curl unchanged, so add whatever your API needs to accept the request:
#
#   RG=my-rg APIM=my-apim API_ID=orders-api URL=https://api.example.com/orders/1 \
#     ./securepath-apim-trace.sh -H "Authorization: Bearer eyJ..."
#
#   METHOD=POST ./securepath-apim-trace.sh -H "Content-Type: application/json" -d '{"q":1}'
#
# Output: trace.json (or $OUT) in the current directory, and the readout on screen. Exit code 0
# when the trace shows a completed inspection, 1 when it shows a problem, 2 when no trace could
# be captured (the message says why).
set -u

RG="${RG:-your-resource-group}"
APIM="${APIM:-your-apim-instance}"
API_ID="${API_ID:-your-api-resource-name}"
URL="${URL:-https://your-apim-instance.azure-api.net/your/api/path}"
METHOD="${METHOD:-GET}"
OUT="${OUT:-trace.json}"

missing=""
[ "$RG" = "your-resource-group" ] && missing="$missing RG"
[ "$APIM" = "your-apim-instance" ] && missing="$missing APIM"
[ "$API_ID" = "your-api-resource-name" ] && missing="$missing API_ID"
[ "$URL" = "https://your-apim-instance.azure-api.net/your/api/path" ] && missing="$missing URL"
if [ -n "$missing" ]; then echo "set$missing first (see the comment at the top of this script)" >&2; exit 2; fi
az account show -o none 2>/dev/null || { echo "az is not logged in: run az login" >&2; exit 2; }

SUB=$(az account show --query id -o tsv)
RES="/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ApiManagement/service/$APIM"
BASE="https://management.azure.com$RES"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

printf '{"credentialsExpireAfter":"PT1H","apiId":"%s/apis/%s","purposes":["tracing"]}' "$RES" "$API_ID" > "$TMP/debug-body.json"
TOKEN=$(az rest --method POST --uri "$BASE/gateways/managed/listDebugCredentials?api-version=2024-05-01" \
  --headers "Content-Type=application/json" --body @"$TMP/debug-body.json" --query token -o tsv 2>"$TMP/err" || true)
if [ -z "$TOKEN" ]; then
  echo "could not get a debug token for API '$API_ID' on $APIM ($RG):" >&2
  sed 's/^/  /' "$TMP/err" >&2
  echo "check the resource group, the instance name, the API resource name (az apim api list) and your role" >&2
  exit 2
fi

if ! curl -sS -X "$METHOD" -D "$TMP/headers" -o "$TMP/body" "$URL" -H "Apim-Debug-Authorization: $TOKEN" "$@" 2>"$TMP/curl-err"; then
  echo "the request to $URL failed before any response (curl exit $?):" >&2
  sed 's/^/  /' "$TMP/curl-err" >&2
  echo "check the URL, DNS and TLS from this machine; nothing reached API Management" >&2
  exit 2
fi
TRACE_ID=$(grep -i "^apim-trace-id:" "$TMP/headers" | awk '{print $2}' | tr -d '\r')
STATUS=$(head -1 "$TMP/headers" | awk '{print $2}')
echo "request: $METHOD $URL -> HTTP ${STATUS:-no response}"
if [ -z "$TRACE_ID" ]; then
  echo "no Apim-Trace-Id header in the response. Either the request never reached $APIM, it matched a" >&2
  echo "different API than '$API_ID' (the token is per API), or a proxy in front removed the debug header." >&2
  echo "response headers were:" >&2; sed 's/^/  /' "$TMP/headers" >&2
  exit 2
fi
echo "Apim-Trace-Id: $TRACE_ID"

printf '{"traceId":"%s"}' "$TRACE_ID" > "$TMP/trace-body.json"
if ! az rest --method POST --uri "$BASE/gateways/managed/listTrace?api-version=2024-05-01" \
  --headers "Content-Type=application/json" --body @"$TMP/trace-body.json" -o json > "$OUT" 2>"$TMP/err"; then
  echo "could not fetch trace $TRACE_ID:" >&2; sed 's/^/  /' "$TMP/err" >&2; exit 2
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
if command -v python3 >/dev/null 2>&1 && [ -f "$DIR/securepath-apim-lint.py" ]; then
  python3 "$DIR/securepath-apim-lint.py" --redact "$OUT" > /dev/null && echo "trace saved: $OUT (credentials inside it replaced with <redacted>)" || echo "trace saved: $OUT (NOT redacted: it contains your SecurePath API key and the request's credentials)"
  echo
  python3 "$DIR/securepath-apim-lint.py" --trace "$OUT"
  exit $?
fi

echo "trace saved: $OUT"
echo "WARNING: $OUT contains your SecurePath API key (x-rdwr-api-key), the debug token and the request's own"
echo "credentials. Do not attach it to a ticket or share it before removing those values."
echo "(python3 or securepath-apim-lint.py not available: showing the key lines instead)"
grep -o -i -E '.{0,80}(Entering policy fragment|rdwrAppEpAddr|request to |has been sent|error ignored|One way request|X-Rdwr-Diag|wrong-api-key|"rwStatus"|validate-jwt|check-header|ip-filter|rate-limit|return-response).{0,160}' "$OUT" | head -40
