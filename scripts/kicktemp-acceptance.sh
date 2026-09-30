#!/usr/bin/env bash
# Acceptance tests from docs/kicktemp/SETUP.md section 5, against the sandbox
# container GTM-TNZ2LC8 ("KCM Test"). Needs the stack running (docker compose up -d).
#
#   scripts/kicktemp-acceptance.sh            # read-only checks
#   WRITE=1 scripts/kicktemp-acceptance.sh    # also creates a workspace, trigger, tag and version
#
# Writes only happen inside a new workspace "kt-acceptance-<timestamp>". Deleting is
# disabled on purpose, so remove that workspace in the GTM UI afterwards.
set -uo pipefail
cd "$(dirname "$0")/.."

BASE=${BASE:-http://127.0.0.1:8080}
SANDBOX=${SANDBOX:-GTM-TNZ2LC8}
# Alle Container, die list_containers zeigen darf (= KT_ALLOWED_CONTAINERS in docker-compose.yml)
EXPECTED=${EXPECTED:-GTM-TNZ2LC8,GTM-KVGB2N5L}
KEY=$(grep '^SERVICE_ACCOUNT_API_KEY=' .env | cut -d= -f2-)
[ -n "$KEY" ] || { echo "SERVICE_ACCOUNT_API_KEY missing in .env"; exit 2; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi; }
section(){ printf '\n== %s\n' "$1"; }
code()  { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# --- MCP helpers -------------------------------------------------------------
HDR=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")
AUTH=(-H "Authorization: Bearer $KEY")
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
ID=10

rpc() { # rpc '<json>' -> prints the JSON-RPC message from the SSE stream
  curl -s "${HDR[@]}" "${AUTH[@]}" ${SID:+-H "Mcp-Session-Id: $SID"} -X POST "$BASE/" -d "$1" | sed -n 's/^data: //p'
}
tool() { # tool <name> '<arguments json>' -> prints the tool result text (JSON); exit status 1 if the tool returned an error
  ID=$((ID+1))
  local out; out=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":$ID,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}")
  local IS_ERROR; IS_ERROR=$(printf '%s' "$out" | py 'r=d.get("result",{}); print("true" if r.get("isError") or "error" in d else "false")')
  printf '%s' "$out" | py 'r=d.get("result"); print(r["content"][0]["text"] if r else json.dumps(d.get("error")))'
  [ "$IS_ERROR" = false ]   # exit status 0 = tool succeeded (callers read it as RC=$?)
}
py() { python3 -c "import sys,json; d=json.load(sys.stdin); $1"; }
jget() { printf '%s' "$1" | py "print($2)"; }

# --- 1. HTTP surface ---------------------------------------------------------
section "HTTP: Auth und Routen"
check "GET /health ohne Auth" "$(code $BASE/health)" 200
check "ohne Bearer -> 401" "$(code -X POST $BASE/)" 401
check "falscher Bearer -> 401" "$(code -X POST -H 'Authorization: Bearer wrong' $BASE/)" 401
check "Bearer mit letztem Zeichen falsch -> 401" "$(code -X POST -H "Authorization: Bearer ${KEY%?}0" $BASE/)" 401
for p in authorize register token llms.txt .well-known/oauth-authorization-server mcp; do
  check "/$p -> 404" "$(code $BASE/$p)" 404
done

# --- 2. Session + Tool-Liste -------------------------------------------------
section "MCP: Handshake und Tool-Liste"
curl -s -D "$TMP/h" "${HDR[@]}" "${AUTH[@]}" -X POST "$BASE/" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"acceptance","version":"1"}}}' >/dev/null
SID=$(grep -i '^mcp-session-id' "$TMP/h" | awk '{print $2}' | tr -d '\r')
[ -n "$SID" ] && ok "Session aufgebaut" || { bad "Session aufgebaut"; exit 1; }
rpc '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
NAMES=$(rpc '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | py 'print(" ".join(t["name"] for t in d["result"]["tools"]))')
echo "  $(echo $NAMES | wc -w | tr -d ' ') Tools registriert"
for t in publish_version set_latest_version delete_tag delete_workspace combine_containers move_tag_id link_destination delete_container create_template update_template import_gallery_template; do
  case " $NAMES " in *" $t "*) bad "Tool $t darf nicht existieren";; *) ok "Tool $t nicht vorhanden";; esac
done

# --- 3. Lesen ----------------------------------------------------------------
section "Lesen: Account, Container, Workspaces, Tags, Trigger, Variablen"
OUT=$(tool list_accounts '{}'); RC=$?
[ $RC = 0 ] && ok "list_accounts" || bad "list_accounts" "$OUT"
echo "  $(jget "$OUT" 'len(d["accounts"])') Account(s) sichtbar"
VISIBLE=""; ACCOUNT=""; CONTAINER=""
for A in $(jget "$OUT" '" ".join(a["accountId"] for a in d["accounts"])'); do
  C=$(tool list_containers "{\"accountId\":\"$A\"}")
  VISIBLE="$VISIBLE $(jget "$C" '" ".join(c["publicId"] for c in d["containers"])')"
  ID=$(jget "$C" 'next((c["containerId"] for c in d["containers"] if c["publicId"]=="'$SANDBOX'"), "")')
  [ -n "$ID" ] && { ACCOUNT=$A; CONTAINER=$ID; }
done
GOT=$(printf '%s\n' $VISIBLE | sort | tr '\n' ',' | sed 's/,$//')
WANT=$(printf '%s\n' ${EXPECTED//,/ } | sort | tr '\n' ',' | sed 's/,$//')
check "list_containers zeigt genau die erlaubten Container (Allowlist-Filter)" "$GOT" "$WANT"
[ -n "$CONTAINER" ] || { bad "Sandbox $SANDBOX gefunden"; exit 1; }
echo "  Sandbox: Account $ACCOUNT, Container $CONTAINER"
OUT=$(tool list_workspaces "{\"accountId\":\"$ACCOUNT\",\"containerId\":\"$CONTAINER\"}"); RC=$?
WS=$(jget "$OUT" 'd["workspaces"][0]["workspaceId"]'); echo "  Container $CONTAINER, erster Workspace $WS"
[ $RC = 0 ] && ok "list_workspaces" || bad "list_workspaces" "$OUT"
BASEARGS="\"accountId\":\"$ACCOUNT\",\"containerId\":\"$CONTAINER\",\"workspaceId\":\"$WS\""
for t in list_tags list_triggers list_variables; do
  OUT=$(tool $t "{$BASEARGS}"); RC=$?; [ $RC = 0 ] && ok "$t" || bad "$t" "$OUT"
done

# --- 4. Ablehnungen ----------------------------------------------------------
section "Ablehnungen (Allowlist, Code-Gate, Pfad-Traversal)"
OUT=$(tool list_tags "{\"accountId\":\"$ACCOUNT\",\"containerId\":\"1\",\"workspaceId\":\"1\"}"); RC=$?
case "$OUT" in *KT_ALLOWED_CONTAINERS*) ok "fremde Container-ID abgelehnt";; *) bad "fremde Container-ID abgelehnt" "$OUT";; esac
OUT=$(tool list_tags "{\"accountId\":\"$ACCOUNT\",\"containerId\":\"$CONTAINER\",\"workspaceId\":\"$WS/../../containers/1/workspaces/1\"}"); RC=$?
case "$OUT" in *"not a valid ID"*) ok "Pfad-Traversal in workspaceId abgelehnt";; *) bad "Pfad-Traversal abgelehnt" "$OUT";; esac
OUT=$(tool create_tag "{$BASEARGS,\"name\":\"kt-html\",\"type\":\"html\",\"firingTriggerIds\":[\"1\"]}"); RC=$?
case "$OUT" in *"custom code is disabled"*) ok "Custom-HTML-Tag abgelehnt";; *) bad "Custom-HTML-Tag abgelehnt" "$OUT";; esac
OUT=$(tool create_variable "{$BASEARGS,\"name\":\"kt-js\",\"type\":\"jsm\"}"); RC=$?
case "$OUT" in *"custom code is disabled"*) ok "Custom-JavaScript-Variable abgelehnt";; *) bad "jsm-Variable abgelehnt" "$OUT";; esac
OUT=$(tool publish_version "{\"accountId\":\"$ACCOUNT\",\"containerId\":\"$CONTAINER\",\"versionId\":\"1\",\"confirm\":true}"); RC=$?
case "$OUT" in *KT_ALLOW_PUBLISH*|*"unknown tool"*|*Unknown*) ok "publish_version nicht ausfuehrbar";; *) bad "publish_version nicht ausfuehrbar" "$OUT";; esac

# --- 5. Schreiben (nur mit WRITE=1) -------------------------------------------
if [ "${WRITE:-0}" = 1 ]; then
  section "Schreiben im Sandbox-Container (neuer Workspace)"
  TS=$(date +%Y%m%d-%H%M%S)
  OUT=$(tool create_workspace "{\"accountId\":\"$ACCOUNT\",\"containerId\":\"$CONTAINER\",\"name\":\"kt-acceptance-$TS\"}"); RC=$?
  NW=$(jget "$OUT" 'd["workspace"]["workspaceId"]') && ok "Workspace kt-acceptance-$TS angelegt ($NW)" || bad "create_workspace" "$OUT"
  W="\"accountId\":\"$ACCOUNT\",\"containerId\":\"$CONTAINER\",\"workspaceId\":\"$NW\""

  OUT=$(tool create_trigger "{$W,\"name\":\"kt - All Pages\",\"type\":\"pageview\"}"); RC=$?
  TRG=$(jget "$OUT" 'd["trigger"]["triggerId"]') && ok "Trigger angelegt ($TRG)" || bad "create_trigger" "$OUT"

  PARAMS='[{\"type\":\"template\",\"key\":\"eventName\",\"value\":\"kt_acceptance\"},{\"type\":\"template\",\"key\":\"measurementIdOverride\",\"value\":\"G-KTTEST0000\"}]'
  OUT=$(tool create_tag "{$W,\"name\":\"kt - GA4 Event\",\"type\":\"gaawe\",\"firingTriggerIds\":[\"$TRG\"],\"parametersJson\":\"$PARAMS\"}"); RC=$?
  TAG=$(jget "$OUT" 'd["tag"]["tagId"]'); FP1=$(jget "$OUT" 'd["tag"]["fingerprint"]')
  [ $RC = 0 ] && ok "GA4-Tag angelegt ($TAG, fingerprint $FP1)" || bad "create_tag" "$OUT"

  OUT=$(tool update_tag "{$W,\"tagId\":\"$TAG\",\"name\":\"kt - GA4 Event (geaendert)\"}"); RC=$?
  FP2=$(jget "$OUT" 'd["tag"]["fingerprint"]')
  [ $RC = 0 ] && [ "$FP1" != "$FP2" ] && ok "Tag geaendert (neuer fingerprint $FP2)" || bad "update_tag" "$OUT"

  OUT=$(tool create_version "{$W,\"name\":\"kt-acceptance-$TS\",\"notes\":\"Abnahmetest, nicht veroeffentlichen\"}"); RC=$?
  [ $RC = 0 ] && ok "Version erstellt (nicht veroeffentlicht)" || bad "create_version" "$OUT"

  section "Audit-Log der Schreibaktionen"
  LOG=$(docker run --rm -v gtm-mcp-server_gtm-data:/data alpine:3.21 cat /data/audit.jsonl 2>/dev/null)
  for t in create_workspace create_trigger create_tag update_tag create_version; do
    N=$(printf '%s\n' "$LOG" | python3 -c "
import sys,json
s=e=0
for l in sys.stdin:
    try: r=json.loads(l)
    except: continue
    if r.get('tool')=='$t' and '$TS' and r.get('event')=='start': s+=1
    if r.get('tool')=='$t' and r.get('event')=='end' and r.get('result')=='ok': e+=1
print(s>0 and e>0)")
    check "audit: $t hat start+end" "$N" True
  done
  printf '%s\n' "$LOG" | python3 -c "
import sys,json
rows=[json.loads(l) for l in sys.stdin if l.strip()]
u=[r for r in rows if r.get('tool')=='update_tag' and r.get('event') in('start','end')][-2:]
print('  update_tag:', {r['event']:{k:r.get(k) for k in ('fingerprint_before','fingerprint_after','api_calls','identity')} for r in u})"
  echo "  Aufraeumen: Workspace kt-acceptance-$TS im GTM-UI loeschen (Delete ist im Server gesperrt)."
else
  echo; echo "(Schreibtests uebersprungen: WRITE=1 setzen)"
fi

printf '\n== %d bestanden, %d fehlgeschlagen\n' "$PASS" "$FAIL"
echo "Manuell: Publish per direktem API-Call mit dem SA muss an GTM-Rechten scheitern (siehe SETUP.md 5)."
[ "$FAIL" = 0 ]
