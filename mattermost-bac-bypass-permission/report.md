# Summary

Mattermost enforces `create_post` and `create_post_public` on the standard channel post path through `userCreatePostPermissionCheckWithContext`. The incoming-webhook handler `POST /hooks/{id}` does not run that check at execution time. `HandleIncomingWebhook` checks only `read_channel_content` for non-open channels, then calls `CreateWebhookPost`, which calls `App.CreatePost` directly. `App.CreatePost` itself does not gate on post permission because every non-webhook caller is expected to enforce it first. The webhook path silently violates that expectation.

Consequence. None of the following operator actions stop a user from publishing in a channel through a pre-existing webhook attributed to that user:

1. Removing `create_post` or `create_post_public` from any system, team, or channel role assigned to the user.
2. Channel Moderation toggling "Create Posts" off for Members or Guests on the channel.
3. Demoting the user from `channel_admin` to a role without post permission.
4. Setting Town Square to read-only via `ExperimentalTownSquareIsReadOnly` while the user still owns a hook bound to it.

Posts produced this way carry the target's `user_id`, display name, and avatar. The only visible marker is a small `BOT` badge next to the username, which is easy to miss in dense feeds.

# Affected Code Path

Routing (`server/channels/web/webhook.go:22`):

```go
w.MainRouter.Handle("/hooks/{id:[A-Za-z0-9]+}", w.APIHandlerTrustRequester(incomingWebhook)).Methods(http.MethodPost)
```

`HandleIncomingWebhook`, the missing-check sites (`server/channels/app/webhook.go:900` and `:946`):

```go
if channel.Type != model.ChannelTypeOpen {
    hasPermission, _ := a.HasPermissionToChannel(rctx, hook.UserId, channel.Id, model.PermissionReadChannelContent)
    restrictedChannel = !hasPermission
}
...
_, err := a.CreateWebhookPost(rctx, hook.UserId, channel, text, overrideUsername, overrideIconURL, req.IconEmoji, req.Props, webhookType, threadRootID, req.Priority)
```

`CreateWebhookPost` (`server/channels/app/webhook.go:316`) builds the `*model.Post` and calls `App.CreatePost`. `App.CreatePost` (`server/channels/app/post.go:161`) does not call any permission helper.

Standard path for comparison (`server/channels/api4/post.go:66`):

```go
userCreatePostPermissionCheckWithContext(c, post.ChannelId)
```

defined at `server/channels/app/post_permission_utils.go:100`, which returns `403 api.context.permissions.app_error` when the caller lacks `create_post` and (for open channels) `create_post_public`. There is no system_admin special case in that helper, so the webhook path is the only known way to bypass it.

# Live Reproduction (against `https://pocas142.cloud.mattermost.com`)

The researcher-owned workspace contains:

1. Workspace admin `pocas142` (`n7wc6msqmjbqxg1g1q5g1a34ue`, `system_user system_admin`).
2. Target user `pocas.cyber` (`f3g7j9qbf78o5bjxnytjw5oawa`, `system_user`), password `pocas.cyber`. Member of team `main` (`q38ncexhgpgb3cqff7ibqa6u7a`) and channel `town-square` (`rtu9tu4j1inbmr8tbfdttgc7kc`).
3. An incoming webhook attributed to `pocas.cyber` on `town-square`:
   ```
   https://pocas142.cloud.mattermost.com/hooks/fspgo118p7bzbnu7ugg858435e
   ```

Step 1, baseline. Log in to the web UI as `pocas.cyber/pocas.cyber`, open `town-square`, and post any message normally. It works.

Step 2, revoke post permission. As the workspace admin, strip `create_post` / `create_post_public` from every role that grants either. The complete set on a default Cloud workspace:

```
system_user            (remove create_post)
channel_user           (remove create_post)
channel_admin          (remove create_post)
team_user              (remove create_post)
team_admin             (remove create_post)
team_post_all          (remove create_post)
team_post_all_public   (remove create_post_public)
system_post_all        (remove create_post)
system_post_all_public (remove create_post_public)
```

Each role is patched with `PUT /api/v4/roles/{role_id}/patch` and a `{"permissions":[...filtered...]}` body. Equivalent UI actions: System Console role editing, plus Channel Moderation on the channel itself.

<img width="1791" height="1195" alt="image" src="https://github.com/user-attachments/assets/50d8a2c9-63fb-46b4-9523-41c4d4f17c81" />


(A turn-key script that performs this revoke and exposes a `restore` command is `block.py`, included with this report.)

Step 3, victim verifies blocked state. As `pocas.cyber`, in the web UI or via API:

```
POST /api/v4/posts
Authorization: Bearer <victim session token>
{"channel_id":"rtu9tu4j1inbmr8tbfdttgc7kc","message":"hello"}
```

Expected and observed: `403 api.context.permissions.app_error`. The web UI shows the standard "You do not have the appropriate permissions" red banner.

Step 4, webhook bypass. From any host, with no Mattermost authentication, just the hook URL:

```
curl -X POST -H 'Content-Type: application/json' \
     -d '{"text":"BAC bypass live PoC"}' \
     https://pocas142.cloud.mattermost.com/hooks/fspgo118p7bzbnu7ugg858435e
```

Observed: `HTTP 200 ok`. (A wrapper for repeat use is `write.py`, included with this report.)

<img width="1799" height="1190" alt="image" src="https://github.com/user-attachments/assets/3309e06b-d11b-49de-8f98-82291e239725" />


Step 5, confirm the post landed. As any authenticated session that can read `town-square`:

<img width="1700" height="349" alt="image" src="https://github.com/user-attachments/assets/19fad3bf-e611-4970-a4a5-eda4e3ab5323" />


```
GET /api/v4/channels/rtu9tu4j1inbmr8tbfdttgc7kc/posts?page=0&per_page=30
```

The newest post entry has `user_id` equal to `f3g7j9qbf78o5bjxnytjw5oawa` (the blocked target), `message` equal to the webhook payload, and `props.from_webhook` equal to `"true"`. In the channel UI it renders under `pocas.cyber`'s display name and avatar with the small `BOT` badge.



# Impact

1. Channel Moderation, a documented operator control marketed as the way to "restrict post creation" in a channel, is silently ineffective against any user holding a pre-existing incoming webhook bound to the moderated channel.

2. Role-based revocation of `create_post` and `create_post_public`, documented as the way to stop a user from posting, does not stop posts via a pre-existing webhook attributed to that user.


# Suggested Fix

Option A, preferred. In `HandleIncomingWebhook`, between the existing read-permission check and the call to `CreateWebhookPost`, run the equivalent of `userCreatePostPermissionCheckWithContext` using `hook.UserId` as the actor. Return `403` if the attributed user no longer has `create_post`, and `create_post_public` for open channels. This is a one-call addition next to `HasPermissionToChannel` already in the same block, preserves the unauthenticated webhook design for normal use, and aligns webhook posting with the standard path's authorisation model.

Option B. On any role mutation that removes `create_post` or `create_post_public` from a user's effective role set, automatically disable all incoming webhooks owned by that user. This is the "invalidate credentials on permission change" pattern and matches operator expectation more closely, at the cost of more code churn.

Option C, defensive, alongside A or B. Render the `BOT` badge such that it cannot be hidden by username and avatar overrides, so that webhook posts cannot be made visually indistinguishable from real user typing in dense feeds.
