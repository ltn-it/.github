# Cloud native review copy recovery

## Scope and implementation status

This repair supports one fixed incident: public repository
`ltn-it/ansible-collection-cloud` (ID `1318852819`), release PR `276`, base
`036df8aee1f9511154e62cc8c88294433da1ad70`, head
`471334b443d5aa258b9ee70fe217044160fbcb43`, and original native review
`40992197896/1`, job `123857300939`, Source015
`015233f4dfe0f95a6df0ea8a9e4ef8150dadc19f`.

The source modules implement the following boundaries:

- `workflow_review_restore.py`: authenticate the original native review and
  the two byte-preserved ZIP copies using original GitHub records and logs.
- `workflow_review_copy_producer.py`: prepare a read-only, inspectable custody
  plan; publish exactly that saved plan with one atomic Git ref comparison,
  then write an independently identified locator.
- `workflow_review_copy.py`: restrict the locator and private read credential,
  reauthenticate the original review, and compare independently reconstructed
  historical and current subjects without relabeling the historical request.
- `workflow_review_copy_grant.cjs`: observe the unchanged pinned App action's
  native grant response and retain only an allowlisted, token-bound receipt.

The complete local candidate includes common-control and YAML hooks composed
on protected Develop `498ad94e16dc852672c671e89f0c7acc7db57bc3`, preserving the
integrated Supplementary, Root ancestry and retained Source015 lineage repairs.
The hooks require current native identity and normal approval; their presence
does not activate a scope. `workflow_codex.py` and its native artifact reader are
unchanged. The candidate remains unpublished pending its complete code review.
No source PR, local test, locator or custody plan selects a verifier or grants a
release approval. Operational effects remain held by the central owner.

## Original evidence and identity

The untrusted original manifest has exactly `schema`, `repository`,
`repository_id`, `pull_request`, `run`, `attempt`, `job`, `source_sha`, and
`artifacts`. Schema is `native-review-copy/v1`; source must be Source015. Each
of the exactly two artifact descriptors has `id`, `name`, `bytes`, and
`sha256`. Local files are `operation.zip` and `receipt.zip`; their old native
artifact identities remain historical, never names or IDs of new artifacts.

The archive verifier reads GitHub's original job log itself. It authenticates
the numeric repository, open same-repository Release App PR, native Required
Workflow association, exact original successful job and all required export
and upload steps. The defining workflow and pinned upload-action sections must
match their immutable Source015 contracts. Upload size, ZIP SHA-256, ID, name,
finalization and same-repository run URL must form one unambiguous ordered
record. Missing, duplicate, contradictory or foreign records fail closed.

The complete original Python source asset inventory, prompt, schema,
authoritative protected instruction bundle and metadata must match immutable
Source015 assets and the original native export. Safe ZIP decoding admits only
the exact members, bounded expansion and regular files; it never extracts an
archive. Native record, complete original metadata, request fingerprint, raw
provider wire, completed response, model/response identity and original PASS
must agree. A copied PASS field alone has no authority. The verifier rereads the
original run/job and current PR before returning provenance.

Its output is a new `authenticated-native-review-copy/v1` report. It explicitly
states `native_artifact: false`, `current_gate_pass: false` and zero performed
provider requests. It does not restore original GitHub artifacts.

## Private custody and producer

Cloud is public. The original raw provider response includes instruction and
provider context; the ZIPs and full reports must stay private. They must never
be committed to public Source or uploaded to public Cloud Actions artifacts.

The proposed existing custody target is private `ltn-it/shared-assets-lit`
(ID `1120841013`), protected ref `refs/heads/lit-review-operations`, rule
`24526630`. The rule must remain active, prohibit deletion and non-fast-forward
updates, have no bypass actors and select exactly that ref. This reuses data
storage only; it does not reactivate any retired controller.

`prepare` performs reads only. It binds the actual eligible User (`litroc` or
`litdeg`), current protected Source Main, all four program hashes, creation
time, exact PR binding, original native descriptors/report digest and current
custody base commit. The existing root manifest is authenticated and preserved.
The emitted saved plan has a canonical SHA-256 and explicitly grants no
execution authorization. The coordinator has accepted this namespace and
private content design. Publication still requires protected Source Main,
a fresh final saved plan and an explicit coordinator operational window.

`publish` requires that exact saved plan and digest, rereads its live inputs,
and rejects an existing locator, existing namespace or stale custody head. It
uses GraphQL `createCommitOnBranch(expectedHeadOid)` once, adding only:

`review-copies/cloud-276/<plan-sha256>/{copy-manifest.json,operation.zip,receipt.zip}`

Every existing blob, root manifest and operation is preserved. No force update,
new ref, permission change, new App, service or workflow is created. Unknown
mutation outcomes and partial GraphQL errors are terminal, never retried.
Readback must show the actual eligible author, GitHub `web-flow` committer,
verified signature, expected single parent, exactly three added paths, and exact
committed bytes. Only then may the actual operator post the canonical locator
comment. A failed locator write does not undo or disguise a successful custody
commit; inspect native state before considering any further action.

The public locator contains only numeric Cloud identity, PR/base/head and
opaque immutable copy-commit, manifest and plan digests. Exactly one unedited
eligible User comment with marker `native-review-copy/v1` is accepted. It is
data, not human approval, review funding or source selection. The consumer
requires the signed copy commit to remain retained by the protected data ref,
checks its exact additive delta, and authenticates all private Git blobs before
reauthenticating the original native review itself.

## Bounded private read credential

The integration patch uses the existing Release App (ID `4355159`, client
`Iv23liSIvZRkHWKxczlb`, installation `148019054`, slug
`lightning-it-release-automation`). No installation permission change is part
of this repair. The pinned token action is
`actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1`.
It requests only `contents: read` for literal `shared-assets-lit`, owner
`ltn-it`, with normal post-job revocation. The pinned action has app-slug and
installation-id outputs, not an app-id output.

Pre-mint validation binds the configured client. Post-mint validation binds the
slug, installation, private repository ID and exact one-repository token
subset. The private reader whitelists only the required GET endpoints. Its
token exists solely in an explicit child environment with fresh CLI config,
never argv, output, artifact, model environment or a generic API child. Common
control removes it from the ambient environment before any public API work.
The finalizer obtains its own short-lived read token only after a successful
current review job. No token is minted for a missing/invalid locator or a
failed current review. These hooks have not been activated by this Draft.

The immutable source-owned preload is scoped to the mint action's `NODE_OPTIONS`
only. It clones only the exact native token-creation response at the fixed
GitHub host and installation endpoint, returning the original Response object
unchanged. It requires the actual complete permission map, selected repository
set and exact sole private repository identity, plus a future expiry no more
than 3660 seconds away. Its fresh mode-0600 receipt records those allowlisted
fields, token SHA-256 and actual source/run/attempt/job. It never logs the raw
response, token, JWT or key. The action's native installation ID and slug are
checked separately against the fixed configured client and accepted App identity.
Foreign hosts, installations and a second mint are blocked before the native
request; a second attempt invalidates the first receipt. Other invalid responses
produce no usable receipt. The action itself can still return success with
its unchanged response; the consumer must reject that missing receipt.

Before any private data read, the consumer opens the exact fresh receipt without
following links, checks ownership/mode and bounded strict JSON, binds it to the
actual action-output token and native generation, and unlinks it. Missing,
expired, foreign-token or overbroad grants fail closed. The existing pinned
action's post handler retains its original behavior; the observer does not
intercept it. The consumer explicitly revokes its token with `DELETE` status
204 and independently confirms subsequent authentication denial with status
401 before starting the original Source015 interpreter. A failed or unknown
revocation prevents interpretation. Private temporary copies are removed on
success and failure; always-run source-owned cleanup removes leftover grant
metadata. No `NODE_OPTIONS` reaches the consumer or historical child.

## Explicit historical/current compatibility

New source code changes `central_source_sha`, the complete `source_assets`
inventory and therefore `input_sha256`. An old review is not a byte-identical
review of the new complete request. No old metadata field or digest is rewritten.

The consumer fetches and authenticates original Source015 scripts against the
original logged asset hashes before executing only its historical data
materializer in a separate process. That process receives no private custody
token, model key or fabricated `NATIVE_JOB`. Its full metadata digest must equal
the original native review digest. The current materializer independently
constructs the current context using the actual executing source.

For this one fixed incident, the proposed source-owned compatibility contract
allows differences only in `central_source_sha`, `source_assets` and
`input_sha256`. Every other metadata field, including all instructions, prompt,
schema, integration tree and unknown future fields, must match exactly. Raw
patch bytes must also match. The original provider result is validated only
against the original complete request. Output separately identifies
`historical_review` and `current_verification`, each with its own full digest,
and records the current semantic-subject digest and actual native execution.
This is an explicitly scoped compatibility policy, not generic cross-source
Codex replay. It needs independent protected source admission.

## Current native control and normal approval

The isolated hooks route only this exact normal release to `review-copy`.
Missing, edited, ambiguous or invalid locators and copies fail closed; this
incident never falls back to a new Codex allocation. Other repositories and PRs
retain their existing routes. Copy verification invokes no gateway, model,
funding reservation, budget reset or additional provider request.

The current native review job must actually succeed. The finalizer repeats
copy verification and current source/run/attempt/job, locator and PR binding
checks. It also retains source common quality, product quality, conversation
checks and the existing genuine current normal Main approval. The unchanged
`workflow_collection_release.native_approval` requires the exact current
operation, normal job, eligible native User decision and prescribed first-line
purpose marker for that run/attempt. Historical approval, copied review, a
skipped job or budget approval cannot substitute for it. Historical acceptance
readers admit this route only for the fixed incident and its distinct-source
proof with current authorization.

## Qualification and operational completion

Deterministic tests run in the repository's digest-pinned Devtools environment.
Synthetic fixtures cover the actual producer/consumer protocol and rejection
boundaries. An isolated hook test exercises common-control entry points and
YAML conditions. Separately, a network-disabled qualification executed the real
old/current materializers over cached native Source015 assets and real Cloud
Git objects. It reproduced the complete original metadata digest and the same
3011 patch bytes with distinct current identity. These establish local data and
protocol behavior only, not successful current native release acceptance.

The actual immutable pinned action bundle (Git blob
`20b90dce8c14c24222d6552fac6a4d5e2866a7d6`) was separately exercised through its
real Octokit authentication/request code and Node 24 runtime, using generated
synthetic RSA keys and a network fake in the pinned offline Devtools runtime.
Thirteen cases exercise positive output-token/receipt binding and negative
boundaries. Received native responses retain their identity; forbidden calls
never reach the network adapter. These are action-runtime qualification tests,
not actual token minting or native operational evidence.

Before any release effect, complete the concurrent prerequisite integration,
review the whole source package normally, promote it to protected Source Main,
and qualify the actual producer and new consumer with positive and negative
native evidence. Management must then prepare and approve a concrete
hash-bound Cloud-only selector plan. Leave other Source015 selectors unchanged.
A new defining source needs a fresh native execution; rerunning the old source
cannot load this repair. Preserve all historical failed/unknown allocations.

Only fresh successful admitted native control permits the unchanged release PR
to follow its normal merge, immutable GitHub/Galaxy publication and Develop
back-sync. Read back exact commits, tags, package digests and installability.
Transition no-op evidence does not establish real Hetzner Heavy acceptance.
Until those steps are observed, the truthful result is a verified private copy
and a blocked release. Rollback retains the previously selected source and the
blocked state; it never overrides a failed gate or requests another review.
