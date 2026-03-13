#!/usr/bin/env bash
# E2E test: start GoSQLX MCP server, send JSON-RPC requests, verify responses.
# Requires: curl, jq, go
set -euo pipefail

PORT=18765
BINARY="./gosqlx-mcp"
ADDR="http://127.0.0.1:${PORT}/mcp"

echo "=== Building MCP server ==="
go build -o "$BINARY" ./cmd/gosqlx-mcp/

echo "=== Starting MCP server on port ${PORT} ==="
GOSQLX_MCP_PORT=$PORT "$BINARY" &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true; rm -f $BINARY" EXIT

# Wait for server to accept connections (POST required for streamable HTTP)
READY=false
for i in $(seq 1 30); do
  if curl -sf -X POST "$ADDR" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"probe","version":"0.1"},"capabilities":{}}}' \
    -o /dev/null 2>/dev/null; then
    READY=true
    break
  fi
  sleep 0.2
done
if [ "$READY" != "true" ]; then
  echo "FAIL: server never became ready"
  exit 1
fi

# --- Step 1: Initialize session and capture Mcp-Session-Id ---
echo "=== Initializing MCP session ==="
INIT_HEADERS=$(mktemp)
INIT=$(curl -sf -X POST "$ADDR" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -D "$INIT_HEADERS" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"e2e-test","version":"0.1"},"capabilities":{}}}')

SESSION_ID=$(grep -i 'Mcp-Session-Id' "$INIT_HEADERS" | tr -d '\r' | awk '{print $2}')
rm -f "$INIT_HEADERS"

if [ -z "$SESSION_ID" ]; then
  echo "FAIL: initialize did not return Mcp-Session-Id header"
  echo "Response: $INIT"
  exit 1
fi

SERVER_NAME=$(echo "$INIT" | jq -r '.result.serverInfo.name // empty')
if [ -z "$SERVER_NAME" ]; then
  echo "FAIL: initialize did not return serverInfo.name"
  echo "Response: $INIT"
  exit 1
fi
echo "PASS: initialized — server=$SERVER_NAME, session=$SESSION_ID"

# Send initialized notification (requires session ID)
curl -sf -X POST "$ADDR" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  -o /dev/null 2>/dev/null || true

# Helper: send a JSON-RPC request with session ID.
rpc() {
  local id="$1"
  local method="$2"
  local params="$3"
  curl -sf -X POST "$ADDR" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"${method}\",\"params\":${params}}"
}

# --- Step 2: List tools ---
echo "=== Listing tools ==="
TOOLS=$(rpc 2 "tools/list" '{}')
TOOL_COUNT=$(echo "$TOOLS" | jq '.result.tools | length')
if [ "$TOOL_COUNT" -ne 7 ]; then
  echo "FAIL: expected 7 tools, got $TOOL_COUNT"
  echo "Response: $TOOLS"
  exit 1
fi
echo "PASS: 7 tools listed"

# --- Step 3: Call validate_sql ---
echo "=== Testing validate_sql ==="
RESULT=$(rpc 3 "tools/call" '{"name":"validate_sql","arguments":{"sql":"SELECT id FROM users"}}')
VALID=$(echo "$RESULT" | jq -r '.result.content[0].text' | jq '.valid')
if [ "$VALID" != "true" ]; then
  echo "FAIL: expected valid=true, got $VALID"
  echo "Response: $RESULT"
  exit 1
fi
echo "PASS: validate_sql returned valid=true"

# --- Step 4: Call security_scan ---
echo "=== Testing security_scan ==="
RESULT=$(rpc 4 "tools/call" '{"name":"security_scan","arguments":{"sql":"SELECT * FROM users WHERE 1=1 OR '"'"''"'"'='"'"''"'"'"}}')
IS_CLEAN=$(echo "$RESULT" | jq -r '.result.content[0].text' | jq '.is_clean')
if [ "$IS_CLEAN" != "false" ]; then
  echo "FAIL: expected is_clean=false for injection, got $IS_CLEAN"
  echo "Response: $RESULT"
  exit 1
fi
echo "PASS: security_scan detected injection"

# --- Step 5: Call analyze_sql ---
echo "=== Testing analyze_sql ==="
RESULT=$(rpc 5 "tools/call" '{"name":"analyze_sql","arguments":{"sql":"SELECT id FROM users"}}')
INNER=$(echo "$RESULT" | jq -r '.result.content[0].text')
for KEY in format lint metadata parse security validate; do
  if ! echo "$INNER" | jq -e ".$KEY" > /dev/null 2>&1; then
    echo "FAIL: missing key $KEY in analyze result"
    echo "Response: $RESULT"
    exit 1
  fi
done
echo "PASS: analyze_sql returned all 6 sub-results"

echo ""
echo "=== All E2E tests passed ==="
