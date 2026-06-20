# Privilege escalation in WordPress XML-RPC `blogger.editPost` lets Contributor publish own drafts without `publish_posts` capability

## Summary

A user with the WordPress `Contributor` role (i.e., a user with `edit_posts` but without `publish_posts`) can publish their own draft posts by calling the legacy XML-RPC method `blogger.editPost` with the `publish` flag set to `1`. The capability gate in `blogger_editPost()` only enforces `publish_posts` when the post is **already** in `publish` status, so for a Contributor's draft the gate is bypassed and `wp_update_post()` persists `post_status = 'publish'`. The modern `wp.editPost` and the sibling `mt.publishPost` correctly reject the same operation, so this is a missed check on the legacy Blogger API surface only.

This breaks a core WordPress trust boundary. The Contributor role is defined as "can author content but cannot make it public"; the `publish_posts` capability is the documented gate for that distinction. This finding makes the gate ineffective for any user who can reach `xmlrpc.php`.

## Affected target

- WordPress core, branch `7.1-alpha-62533` (current `main`).
- File: `wp-includes/class-wp-xmlrpc-server.php`, function `WP_XMLRPC_Server::blogger_editPost()`, lines 5210 through 5269.

## Root cause

The method authorizes the edit operation but performs the publish check conditionally on the **existing** post status, not on the **requested** status transition.

```php
// wp-includes/class-wp-xmlrpc-server.php:5236
if ( ! current_user_can( 'edit_post', $post_id ) ) {
    return new IXR_Error( 401, __( 'Sorry, you are not allowed to edit this post.' ) );
}
if ( 'publish' === $actual_post['post_status'] && ! current_user_can( 'publish_posts' ) ) {
    return new IXR_Error( 401, __( 'Sorry, you are not allowed to publish this post.' ) );
}
// ...
$postdata['post_status'] = $publish ? 'publish' : 'draft';   // line 5250: requested transition

$result = wp_update_post( $postdata );                       // line 5252: persisted
```

For a Contributor editing their own draft:

1. `edit_post` passes because the Contributor owns the draft.
2. The publish check is skipped because `$actual_post['post_status']` is `'draft'`, not `'publish'`.
3. The `$publish` argument (request parameter, attacker controlled) is written directly to `post_status`.
4. `wp_update_post()` does not re-check `publish_posts` and accepts an explicit `'publish'` status from the caller.

Adjacent XML-RPC publishing paths enforce the intended gate by checking `publish_posts` on the requested transition rather than the existing status:

- `mt.publishPost` (line 6862) requires both `publish_posts` and `edit_post`.
- `wp.editPost` and `wp.newPost` route through `_insert_post()`, which requires `publish_posts` for `publish` and `future` statuses.

`blogger_editPost()` is the only legacy publishing endpoint that performs the post-status check against the existing record rather than against the requested transition.

## Steps to reproduce

1. Log in as any user with the **Contributor** role (or have any administrator create one).
2. Using `wp.newPost` (or the wp-admin editor), create a draft post as that Contributor. Note its post ID.
3. Send the following XML-RPC request to the target. Replace `<id>` with the draft ID, and supply the Contributor's username and password:

   ```xml
   POST /xmlrpc.php HTTP/1.1
   Host: target.tld
   Content-Type: text/xml

   <?xml version="1.0"?>
   <methodCall>
     <methodName>blogger.editPost</methodName>
     <params>
       <param><value><string>app</string></value></param>
       <param><value><string><id></string></value></param>
       <param><value><string><contributor-username></string></value></param>
       <param><value><string><contributor-password></string></value></param>
       <param><value><string>&lt;title&gt;PoC published by contributor&lt;/title&gt;PoC body.</string></value></param>
       <param><value><int>1</int></value></param>
     </params>
   </methodCall>
   ```

4. The response is `<boolean>1</boolean>` (success).
5. Fetch `/?p=<id>` anonymously and observe HTTP 200 with the published post rendered. The Contributor has published a post they were not authorized to publish.

## Proof of concept

A self contained reproduction script (`poc.py`) is included alongside this report. Given a Contributor account, the script creates a fresh draft, demonstrates that the modern XML-RPC paths correctly reject the publish transition, then calls `blogger.editPost` with `publish=1` and verifies the resulting post is publicly readable.

Run:

```bash
pip install requests
python3 poc.py --base http://target.tld --contributor-user <user> --contributor-pass '<password>'
```

A successful run prints `PASS` followed by:

1. The draft post ID created via `wp.newPost`.
2. The XML-RPC fault returned by `wp.editPost(post_status=publish)`: `faultCode 401`, `Sorry, you are not allowed to publish posts in this post type`.
3. The XML-RPC fault returned by `mt.publishPost`: `faultCode 401`, `Sorry, you are not allowed to publish this post`.
4. The exploit response from `blogger.editPost(..., publish=1)`: boolean `true`.
5. The HTTP status code (200) of anonymous `GET /?p=<id>` showing the post is publicly published.

## Impact

A Contributor, a role whose entire purpose is to author content that must be reviewed by an Editor or Administrator before going public, gets one request publishing of their own drafts. The `publish_posts` capability is the documented boundary between "can author drafts" and "can publish content visible to the world", and this finding renders that boundary ineffective whenever `xmlrpc.php` is reachable (the default on every WordPress installation). Any site that grants Contributor accounts to outside collaborators (guest authors, news desks with editor review, multi author blogs, academic and student blogs, marketing teams behind an editor) loses the moderation gate, and the attacker can publish material that the site never reviewed. Because a published post appears to readers and to downstream consumers (RSS, email digests, social syndication, search engines) as approved content from the site, this is a content trust breach with reputational and legal consequences. The bug also amplifies any author level XSS or SSRF primitive: a Contributor who would otherwise wait for an Editor to approve a malicious draft can now publish it themselves and immediately expose the payload to every visitor including the site Administrator.

## Severity

**CVSS 3.1 base score: 8.0 (High)**, `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | XML-RPC is exposed over HTTP(S). |
| Attack Complexity | Low | Single request, no timing, no race. |
| Privileges Required | Low | Contributor role, the lowest publishing related role in WordPress. |
| User Interaction | None | No victim interaction required. |
| Scope | Unchanged | Stays within the WordPress capability model on the same component. |
| Confidentiality | None | No data is read that the attacker could not already read. |
| Integrity | High | Attacker bypasses the documented publishing gate and changes site state (a new publicly published post under their authorship). |
| Availability | None | No availability impact. |

The score can rise to High Scope Changed when chained with an author level XSS or SSRF primitive that the Contributor authors and then immediately publishes through this bug. The chained CVSS is `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` = 8.7.

## Suggested remediation

The fix is to check `publish_posts` on the **requested** status transition, not on the existing status. Two equivalent options:

**Option A** (minimal change). Replace the existing publish check at line 5239 with a check that fires whenever the caller is requesting a `publish` transition:

```php
// Replace lines 5239 to 5241:
if ( $publish && ! current_user_can( 'publish_posts' ) ) {
    return new IXR_Error( 401, __( 'Sorry, you are not allowed to publish this post.' ) );
}
```

This matches the behavior of `mt.publishPost`.

**Option B** (defense in depth). Route `blogger_editPost()` through `wp.editPost` style logic so that the capability decisions are centralized in `_insert_post()`. This removes the duplicated state machine and prevents future divergence between XML-RPC endpoints.

Either fix closes the bug. Option B is preferable because the same class of "legacy XML-RPC path forgot to update its capability checks when the modern path was hardened" already applies to multiple other XML-RPC methods on this codebase.

## References

- WordPress developer reference for `WP_XMLRPC_Server::blogger_editPost()`: https://developer.wordpress.org/reference/classes/wp_xmlrpc_server/blogger_editpost/
- WordPress Codex, legacy Blogger XML-RPC API: https://codex.wordpress.org/XML-RPC_Blogger_API
- WordPress roles and capabilities, Contributor vs Author: https://wordpress.org/documentation/article/roles-and-capabilities/

I reviewed public WordPress security advisories, NVD, GitHub Security Advisories, and WordPress Trac and did not find a published report describing this specific Contributor to publish privilege break in `blogger.editPost`. If a private or yet to be disclosed advisory exists, please feel free to redirect this report.

## Disclosure preferences

I am happy to coordinate on a private fix and an embargo until WordPress ships a patched point release. The primitive is straightforward (a single XML-RPC request from a Contributor account), so a coordinated release is preferable to public disclosure. The PoC will not be shared outside of HackerOne until a fix ships.
