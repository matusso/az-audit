#!/usr/bin/env bash
# Offline regression test: runs the audit against a mock `az` (tests/mock-az/az)
# that serves canned ARM / Log Analytics / Graph responses. No Azure access.
# Requires: bash, jq, python3.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="$here/.out"
rm -rf "$out"; mkdir -p "$out/throttle"
fail=0
check() { # <description> <jq expression that must be true> <file>
  if jq -e "$2" "$3" >/dev/null 2>&1; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi
}

PATH="$here/mock-az:$PATH" MOCK_AZ_LOG="$out/calls.log" MOCK_THROTTLE_DIR="$out/throttle" \
  NO_COLOR=1 RETRY_BASE_DELAY=0 "$root/azure-logging-compliance-audit.sh" --output-dir "$out/run" --max-parallel 3 \
  > "$out/stdout.log" 2> "$out/stderr.log"
rc=$?
run="$(ls -d "$out"/run/*/ | head -1)"
s="$run/summary.json"

[ "$rc" -eq 0 ] && echo "ok   - exit code 0" || { echo "FAIL - exit code $rc"; fail=1; }
check "summary.json has findings"                     '.findings | length > 50' "$s"
check "403 on SQL database diag -> NOT_VERIFIABLE"     '[.findings[] | select(.control=="LOG-001" and .resourceName=="appdb")][0].status == "NOT_VERIFIABLE"' "$s"
check "unlocked WORM container -> ARC-005 FAIL"        '[.findings[] | select(.control=="ARC-005")][0].status == "FAIL"' "$s"
check "activity log container locked -> not FAIL"      '[.findings[] | select(.control=="ACT-002")][0].status != "FAIL"' "$s"
check "EH firewall w/o trusted services -> EH-002 FAIL" '[.findings[] | select(.control=="EH-002")][0].status == "FAIL"' "$s"
check "Cribl not configured -> EH-004 not PASS"        '[.findings[] | select(.control=="EH-004")][0].status != "PASS"' "$s"
check "Entra 403 -> no FAIL"                           '[.findings[] | select((.control|startswith("ENTRA")) and .status=="FAIL")] | length == 0' "$s"
check "UWWB never PASS"                                '[.findings[] | select(.control=="UWWB-001")][0].status == "NOT_VERIFIABLE"' "$s"
check "DATA group with Contributor -> RBAC-002 FAIL"   '[.findings[] | select(.control=="RBAC-002")][0].status == "FAIL"' "$s"
check "inaccessible subscription reported"             '[.findings[] | select(.control=="SUB-001" and .status=="NOT_VERIFIABLE")] | length == 1' "$s"
check "throttled request retried and succeeded"        '[.findings[] | select(.control=="LOG-001" and .resourceName=="kv-prod")][0].status == "PASS"' "$s"

if grep -rq 'secret-ikey-123' "$out/run"; then echo "FAIL - secret leaked into output"; fail=1; else echo "ok   - no secret in output"; fi
bad="$(python3 -c "
import json
for l in open('$out/calls.log'):
    a = json.loads(l)
    if a[0] == 'rest':
        m = a[a.index('--method') + 1].lower(); u = a[a.index('--url') + 1].lower()
        if m == 'get': continue
        if m == 'post' and ('/providers/microsoft.resourcegraph/resources?' in u or u.endswith('/query')): continue
        print(m, u)
    elif a[:2] not in (['account', 'show'], ['account', 'list'], ['cloud', 'show']) and a[:1] != ['version']:
        print(a)
")"
[ -z "$bad" ] && echo "ok   - only read-only calls issued" || { echo "FAIL - non-read-only calls: $bad"; fail=1; }
python3 - "$run" <<'EOF' && echo "ok   - all CSV files are valid RFC 4180" || { echo "FAIL - invalid CSV"; exit 1; }
import csv, glob, sys
for f in glob.glob(sys.argv[1] + "/*.csv"):
    rows = list(csv.reader(open(f, newline=""), strict=True))
    assert len({len(r) for r in rows}) == 1, f
EOF
[ $? -eq 0 ] || fail=1
exit $fail
