#!/usr/bin/env bash
# =============================================================================
# security_smoke_test.sh - black-box security checks against a RUNNING Evidence Vault.
#
# Start the app first (see README), then:
#   BASE=http://localhost:8080 ./scripts/security_smoke_test.sh
#
# It creates throwaway users named smoke_xxxx. Run it only against your own instance.
# Uses only curl and python3 (already on Kali). Exit code 0 = all checks passed.
# =============================================================================
set -u
BASE="${BASE:-http://localhost:8080}"
RUN_ID="$(date +%s)$RANDOM"
PASS=0
FAIL=0

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

# check "description" "regex of acceptable status codes" actual_code
check() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$actual" =~ ^($expected)$ ]]; then
        green "  PASS  $name (HTTP $actual)"; PASS=$((PASS + 1))
    else
        red   "  FAIL  $name (got HTTP $actual, expected $expected)"; FAIL=$((FAIL + 1))
    fi
}

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
json_field() {
    python3 -c "import sys,json
try:
    print(json.load(sys.stdin).get('$1',''))
except Exception:
    print('')"
}

register() { # user pass [extra-json-fields]
    curl -s -X POST "$BASE/api/auth/register" -H 'Content-Type: application/json' \
        -d "{\"username\":\"$1\",\"email\":\"$1@example.com\",\"password\":\"$2\"${3:-}}" > /dev/null
}
login_token() { # user pass
    curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
        -d "{\"username\":\"$1\",\"password\":\"$2\"}" | json_field token
}

echo "Evidence Vault smoke test against $BASE"
echo

USER_A="smoke_a_$RUN_ID"; USER_B="smoke_b_$RUN_ID"; PW='Correct-Horse-Battery-9'
CASE_BODY='{"caseNumber":"X","title":"x","description":"x"}'

echo "[1] Authentication required"
check "Admin endpoint without a token is rejected" "401|403" "$(code "$BASE/api/audit/chain")"

echo "[2] Privilege escalation via registration (the bug you fixed)"
register "$USER_A" "$PW" ',"role":"ADMIN"'
TOKEN_A="$(login_token "$USER_A" "$PW")"
if [ -z "$TOKEN_A" ]; then
    red "  FAIL  could not register/login test user A - is the app running, and are rate limits OK?"
    exit 2
fi
check "User who registered with role=ADMIN cannot reach admin endpoint" "403" \
    "$(code "$BASE/api/audit/chain" -H "Authorization: Bearer $TOKEN_A")"

echo "[3] Token tampering"
# Change the FIRST character of the signature. (The last base64url character of an HS256 signature has
# 2 unused padding bits, so changing it is silently ignored about 1 time in 16.)
SIG_PART="${TOKEN_A##*.}"; SIG_FIRST="${SIG_PART:0:1}"
if [[ "$SIG_FIRST" == "A" ]]; then SIG_NEW="B"; else SIG_NEW="A"; fi
BAD_SIG="${TOKEN_A%.*}.${SIG_NEW}${SIG_PART:1}"
check "JWT with modified signature is rejected" "401|403" \
    "$(code "$BASE/api/cases" -X POST -H "Authorization: Bearer $BAD_SIG" -H 'Content-Type: application/json' -d "$CASE_BODY")"
PAYLOAD="$(echo "$TOKEN_A" | cut -d. -f2)"
NONE_HDR="$(printf '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')"
check "JWT with alg=none is rejected" "401|403" \
    "$(code "$BASE/api/cases" -X POST -H "Authorization: Bearer $NONE_HDR.$PAYLOAD." -H 'Content-Type: application/json' -d "$CASE_BODY")"

echo "[4] Case isolation between users"
register "$USER_B" "$PW"
TOKEN_B="$(login_token "$USER_B" "$PW")"
CASE_ID="$(curl -s -X POST "$BASE/api/cases" -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' \
    -d "{\"caseNumber\":\"SMOKE-$RUN_ID\",\"title\":\"smoke\",\"description\":\"smoke test\"}" | json_field id)"
if [ -z "$CASE_ID" ]; then
    red "  FAIL  user A could not create a case"; FAIL=$((FAIL + 1))
else
    check "User B cannot freeze user A's case" "403|404" \
        "$(code "$BASE/api/cases/$CASE_ID/freeze" -X POST -H "Authorization: Bearer $TOKEN_B")"
    echo "sample evidence $RUN_ID" > /tmp/smoke_evidence.txt
    check "User B cannot upload evidence into user A's case" "403|404" \
        "$(code "$BASE/api/cases/$CASE_ID/evidence" -X POST -H "Authorization: Bearer $TOKEN_B" -F "file=@/tmp/smoke_evidence.txt")"
    rm -f /tmp/smoke_evidence.txt
fi

echo "[5] Logout revokes the token immediately"
code "$BASE/api/auth/logout" -X POST -H "Authorization: Bearer $TOKEN_A" > /dev/null
check "Token is rejected after logout" "401|403" \
    "$(code "$BASE/api/cases" -X POST -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' -d "$CASE_BODY")"

echo "[6] Brute-force protection"
LOCK_USER="smoke_lock_$RUN_ID"
register "$LOCK_USER" "$PW"
for i in 1 2 3 4 5 6 7 8 9 10; do
    code "$BASE/api/auth/login" -X POST -H 'Content-Type: application/json' \
        -d "{\"username\":\"$LOCK_USER\",\"password\":\"wrong-$i\"}" > /dev/null
done
AFTER="$(code "$BASE/api/auth/login" -X POST -H 'Content-Type: application/json' \
    -d "{\"username\":\"$LOCK_USER\",\"password\":\"$PW\"}")"
check "Correct password refused after 10 wrong attempts (lockout or rate limit)" "401|403|423|429" "$AFTER"

echo "[7] Security headers (informational only, not counted)"
HEADERS="$(curl -s -I "$BASE/api/auth/login")"
for h in "X-Content-Type-Options" "Cache-Control"; do
    if echo "$HEADERS" | grep -qi "^$h:"; then green "  INFO  $h header present"
    else echo "  INFO  $h header missing (consider adding)"; fi
done

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
