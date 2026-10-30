# Archived native review copies

## Implemented boundary

`scripts/workflow_review_restore.py` authenticates a locally preserved copy of
one historical Cloud review. It performs GitHub reads and local decoding only.
It does not upload artifacts, allocate review funding, call a model, rerun a
workflow, change a verifier selector, authorize a release, or publish a check.
There are deliberately no hooks in `workflow_control.py` or `workflow_codex.py`.

The supported original producer is the protected common workflow at
`015233f4dfe0f95a6df0ea8a9e4ef8150dadc19f` (Source015), for the existing Cloud
repository identity only. Other sources and repositories are rejected. This is
an archive-verification boundary, not admission of another repository or source.

The operator supplies an untrusted `native-review-copy/v1` manifest and exactly
two local files named `operation.zip` and `receipt.zip`. The command emits a new
`authenticated-native-review-copy/v1` report to stdout. Its `original` section
retains the old run, attempt, job, source, artifact IDs, sizes and ZIP digests.
Its `copy` section describes local files and the verifier's own SHA-256. It
explicitly reports `native_artifact: false` and `current_gate_pass: false`.
It neither recreates nor impersonates an original GitHub artifact.

Run through the existing pinned Devtools boundary when qualifying the verifier.
The CLI requires an already authorized, read-only GitHub connection for live
reads; this change adds no credential forwarding or new runtime environment.
Private original copies and their reports must remain in the private consumer's
authorized storage. Do not commit them to this public source repository.

## Untrusted manifest

The manifest has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | `native-review-copy/v1` |
| `repository` | Existing canonical Cloud repository name |
| `repository_id` | Existing immutable Cloud repository ID |
| `pull_request` | Original and still-current release PR number |
| `run`, `attempt`, `job` | Original successful review producer |
| `source_sha` | Source015, without relabeling it as a newer source |
| `artifacts.operation` | Original operation artifact descriptor |
| `artifacts.receipt` | Original Codex receipt artifact descriptor |

Each artifact descriptor contains exactly `id`, `name`, `bytes`, and `sha256`.
Names must be `control-operation-N` and `codex-receipt-N` for the original
attempt N. Locators and declared digests confer no authority by themselves.

## Verification and rejection

The verifier obtains the original job log directly from GitHub. A supplied log
file cannot replace that read. It authenticates the numeric repository, exact
open same-repository Release App PR, native Required Workflow run, its exact
base/head/PR association and the unique successful original review job. All
required operation, materialization, collection, export and upload steps must
have actually succeeded in that original attempt.

The defining Source015 workflow is checked against its fixed byte digest.
The native export context must name Source015 and the same native job. The
original source's complete Python asset inventory, prompt and schema are read
at immutable revisions and compared with the original metadata. The complete
metadata digest, including `input_sha256`, remains unchanged.

For each original artifact, the exact pinned upload-action section must contain
one consistent, ordered size, ZIP SHA-256, artifact ID, name, finalization and
same-repository run URL. Missing, duplicate, contradictory, foreign-action or
ambiguous log records fail closed. The local ZIP bytes must match that native
size and digest before decoding. Member names are fixed; links, directories,
extra or duplicate members, encryption, unsupported compression and oversized
expanded files are denied. No archive is extracted to the filesystem.

The original operation must bind the exact current PR metadata. The native
record, raw provider wire, full metadata, request fingerprint, completed model
response, response ID/model and original PASS result must agree. SSE bytes are
retained, not reconstructed. A PASS string in a report is insufficient. The
run, original job and current PR are read again before returning copy
provenance. No missing or failed native evidence is treated as success.

Tests use synthetic source-owned fixtures and an API fake. They establish the
local verifier's rejection behavior, not a restored native workflow or a
published release. Tests also assert that no model request is performed.

## Producer and consumer still required for release recovery

The implemented verifier alone cannot unblock a Source015 release. Source015
loads only Source015 code. Its readers require original native artifacts; it
has no hook for a new copy. A changed source also changes `central_source_sha`
and the complete `source_assets` inventory, hence `input_sha256` and the actual
complete request. Installing this helper under a newer source does not make
that request byte-identical to the historical model request.

The following separate contract must be implemented and reviewed before an
operational window is requested:

1. **Copy producer and custody.** Preserve the two original ZIPs unchanged.
   Run the new verifier against live original native records. Any subsequent
   upload must use a new, explicitly named copy artifact, with its own actual
   producer run/attempt/job/source and copy-artifact ID. Bind its manifest and
   copied ZIP digests to that producer. Preserve the original identity as
   historical provenance; never upload under an original artifact name or ID.
   Keep transport within the private consumer and existing credential scope.
2. **Source-owned copy locator.** A reviewed consumer entry point must admit
   the copy's new immutable locator before reading it. Operator-supplied JSON,
   PR text, labels, or a locally verified report cannot select the defining
   source or grant a fallback. Reauthenticate the original native log and ZIPs
   in the consumer; the producer's report is data, not an acceptance signal.
3. **Explicit dual-source decision.** A separately reviewed Cloud-only policy
   must distinguish the historical review source from the current executing
   verifier. It must reconstruct the unchanged complete historical subject
   using authenticated original Source015 assets, and validate the original
   model result against those bytes. It must separately validate the current
   subject, current policy, product checks, native identity, and applicable
   conversation guard. Any permitted semantic compatibility between those two
   contexts needs an explicit protected, reviewed contract. Do not simply
   replace `source_sha`, omit `source_assets`, recompute the old input digest,
   or feed an old response to a different complete request. That compatibility
   and the consumer entry point are not implemented by this helper.
4. **Current normal approval.** Execute the real current native Main gate with
   the prescribed purpose marker for that exact run/attempt. A historical
   approval or an authenticated copied review does not approve a release.
   No funding slot, unknown outcome, or prior failed attempt is reset.
5. **Independent source admission.** Deliver the source repair normally to
   protected Source Main. Qualify the actual producer and new consumer with
   positive and negative native evidence before preparing a concrete,
   hash-bound Cloud-only selector plan. The Management owner controls that
   separate operational window and genuine native approval. Leave the other
   existing Source015 selectors unchanged. A source PR is not a rollout.
6. **Readback and completion.** Only after the admitted new consumer obtains
   fresh successful native evidence may the unchanged release PR follow the
   normal merge, immutable GitHub/Galaxy publication and Develop back-sync.
   Read back the exact commits, tags, package digests and native results.
   Central transition no-op evidence is not Hetzner Heavy acceptance.

Reject changed heads/bases or instructions, mismatched full metadata, expired
or unavailable original logs, ambiguous sources, invalid wire, failed original
exports, missing copies, unknown new custody, unadmitted compatibility and
concurrent generation changes. Rollback means retaining the previously
selected immutable source and the original blocked state; it does not mean
overriding a failed check or requesting another review.

Until this second contract is accepted, the truthful outcome is an
authenticated archived copy and a still-blocked release. No current artifact
restoration, current gate PASS or production acceptance is asserted.
