# Stored XSS in WordPress core via `<track label>` in `[video]` shortcode, exploitable by Author-role users

## Summary

Any user with the WordPress `Author` role (i.e., a user **without** the `unfiltered_html` capability) can inject and persist arbitrary JavaScript into a published post by abusing the `<track>` element permitted in KSES's post-content whitelist. The `label` attribute is preserved verbatim, including HTML-encoded entities. When the post is rendered with the bundled MediaElement player, `addTrackButton()` interpolates the browser-decoded `label` value into `innerHTML`, executing the payload in every visitor's browser, including administrators viewing the post.

This breaks a core WordPress trust boundary: users lacking `unfiltered_html` are not supposed to be able to embed executable HTML in post content. KSES is the mechanism that enforces it. Here, KSES's own whitelist provides the gadget.

## Affected target

- WordPress core, branch `7.1-alpha-62533` (current `main`).
- Files involved (all paths relative to repository root):
  - `wp-includes/kses.php:386-392`, `<track>` is in `$allowedposttags` with an unconstrained `label` attribute.
  - `wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php:1317`, REST API accepts the payload into `post_content`.
  - `wp-includes/media.php:3881`, `wp_video_shortcode()` emits the shortcode body verbatim into rendered HTML.
  - `wp-includes/js/mediaelement/mediaelement-and-player.js:2628`, `addTrackButton()` writes `label` into `innerHTML`.

## Root cause

KSES treats attribute values as opaque strings. When an Author submits the following as post content:

```
[video src="https://target.tld/wp-content/uploads/v.mp4"]<track kind="captions" src="https://target.tld/wp-content/uploads/c.vtt" srclang="en" label="&lt;img src=x onerror=alert(1)&gt;">[/video]
```

KSES sees `label` as a whitelisted attribute and leaves the entity-encoded value untouched. Server-side, `wp_video_shortcode()` then concatenates the shortcode body into the page (`media.php:3881`):

```php
if ( ! empty( $content ) ) {
    $content = str_replace( array( "\r\n", "\n", "\t" ), '', $content );
    $html .= trim( $content );
}
```

The browser, while parsing the resulting HTML, decodes the `label` attribute value (HTML attribute decoding turns `&lt;` into `<`). The DOM property `trackElement.label` therefore exposes the raw string `<img src=x onerror=alert(1)>`.

`mediaelement-and-player.js:2628` performs:

```js
addTrackButton: function addTrackButton(trackId, lang, label) {
    var t = this;
    if (label === '') {
        label = _i18n2.default.t(_mejs2.default.language.codes[lang]) || lang;
    }
    t.captionsButton.querySelector('ul').innerHTML += '<li class="' + t.options.classPrefix + 'captions-selector-list-item">'
        + '<input type="radio" ...>'
        + '<label ...>' + label + ' (loading)</label>'
        + '</li>';
}
```

`innerHTML +=` parses the concatenated string as HTML, materializing `<img onerror>` and executing the payload. The "double decoding", server passes through the entity-encoded string, browser decodes the attribute, MediaElement re-parses the decoded string via `innerHTML`, is what bypasses KSES.

The referenced `.mp4` and `.vtt` do **not** need to exist or be valid; `addTrackButton()` runs regardless.

## Steps to reproduce

<img width="1857" height="71" alt="image" src="https://github.com/user-attachments/assets/732cbf88-b201-4ca9-9ec6-5f19c395958a" />

1. Log in as any user with the **Author** role. 
2. Publish a post whose content is:

   ```
   [video src="http://target.tld/wp-content/uploads/missing.mp4"]<track kind="captions" src="http://target.tld/wp-content/uploads/missing.vtt" srclang="en" label="&lt;img src=x onerror=window.__poc_xss=1&gt;">[/video]
   ```

3. Visit the post's public URL in any modern browser.
4. Observe `window.__poc_xss === 1` in the DevTools console (or, with `alert(1)`, a visible popup). JavaScript ran in the visitor's session.

## Proof of concept

A self-contained reproduction script (`poc.py`) is included alongside this report. Given an Author account, it publishes the payload above via `POST /wp/v2/posts`, fetches the resulting public URL, and drives headless Chromium to confirm the JavaScript executed.

Run:

<img width="815" height="89" alt="image" src="https://github.com/user-attachments/assets/a7ae4a49-9695-4b57-ae56-e3cf2a2b5d2b" />

```bash
pip install requests
python3 poc.py --base http://target.tld --author-user <author> --author-pass '<password>'
```

<img width="2046" height="1468" alt="image" src="https://github.com/user-attachments/assets/788e7da5-c7ea-4417-b92a-c2fcc3f86205" />


## Impact

An Author, a role that is not supposed to be able to inject raw HTML, per the `unfiltered_html` capability boundary, gets persistent JavaScript execution in every visitor's browser on the post they publish. Because the post is served on the same origin as `/wp-admin/`, an Administrator (or Editor, or Super Admin) who views it has their authenticated session hijacked: the payload can read their REST nonce from `/wp-admin/profile.php`, create a new Administrator via `POST /wp/v2/users`, or install a malicious plugin for full RCE. Anonymous visitors are exposed to standard XSS abuse (phishing, redirect, fingerprinting). On Multisite the impact is amplified because site Administrators also lack `unfiltered_html`, only Super Admins do, so this finding lets any publishing user attack the network owner.
## Severity

**CVSS 3.1 base score: 8.7 (High)**, `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Exploitable via the public post URL. |
| Attack Complexity | Low | No timing, no race, no special conditions. |
| Privileges Required | Low | Author role; commonly granted to guest contributors. |
| User Interaction | Required | Victim must view the post. |
| Scope | Changed | Attacker (Author) compromises higher-privileged users' sessions. |
| Confidentiality | High | Admin session hijack → full read of site data, user PII, drafts. |
| Integrity | High | Admin session hijack → write access to all posts, settings, users; can install plugins → RCE. |
| Availability | None | No direct availability impact. |
