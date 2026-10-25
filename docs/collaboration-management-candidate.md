# Private Management Actions publication candidate

This is an inactive, locally executable candidate for owned Sync or Release
pull-request creation. It does not install a workflow, registration, journal,
credential, permission or service. Current selected R4 has no registration for
this protocol. Local fixtures are not an observed production OIDC identity.

The original content-policy acceptance criteria do not require a new permanent
host. This candidate uses the existing private Management Actions boundary and
its existing `terraform-github-management-state` concurrency group, with
`cancel-in-progress: false`. It adds no timer or independent controller. The
native artifact is operation evidence, not a distributed lock.

## Bound execution

`collaboration_management_candidate.py` accepts only a future externally
selected Root registration at `.lit/collaboration-owned-publisher.json`. The
registration binds the private Management Main commit, exact OIDC subject,
origin producer, actual publisher App actor, role, operation and journal rule.
It is read through the real Management Required-source ruleset. A library caller
cannot select its own source or turn a previous Main approval into publication
authority. The existing Root review issuer retains its original checks.

The private signed OIDC token binds the exact final-payload digest as audience.
The issuer verifies repository and owner IDs, private visibility, Main SHA,
workflow path, first run attempt, native running job, and completed preparation
step. It downloads the one bounded native operation artifact. Its canonical
`operation.json` contains version, role, operation, repository ID, run ID,
attempt, job ID, base/head refs and SHAs, and payload SHA-256. Unexpected members,
missing fields or drift fail closed. The payload is canonical JSON and passes
the existing final-byte content policy against fresh complete org inventory.
The source, private Main, run, target refs and running job are checked again.

This version supports only Root `pull.create` into `develop`, for the explicitly
registered `owned-sync` or `owned-release` role. It does not authorize edits,
reviews, comments, other repositories, hosted AI output or other writers. Its
operation identity includes target refs and SHAs but excludes text, token, run,
source and role: changing those cannot purchase another publication slot.
Existing open or closed PRs for the same head also block the operation.

## Durable intent before publication

The journal client has one fixed GitHub HTTPS Contents endpoint in private
Management and one fixed pre-existing branch,
`operation-data/collaboration-journal`. It sends create-only requests without a
replacement SHA, performs no redirect or retry, and accepts only a verified
201 result. Intent and response files are separate. Every result is read back
at its returned immutable commit, including the expected Git blob and parent.

Before a write, the client reads the actual full repository ruleset, including
bypass actors. The registered rule must protect exactly the journal ref against
deletion and non-fast-forward updates, with no bypass actors. A branch-rule
projection is insufficient authority. The complete path history must be empty
before creation; deleting the current file does not restore an operation slot.
No journal ref, rule or credential is created by this candidate.

The existing native single-writer group supplies serialization. This contract
must cover every admitted journal writer; a fixture or local context manager
does not establish production exclusivity. Unknown journal outcomes stop before
public publication. After a possible publication, uncertainty or a failed
response commit returns `unknown-readback-required` and never resends.

## Concrete adoption package

Use the normal protected development and source-admission path for these
specific changes. Keep previous review requests and budget consumption. This
document supplies no deployment, Ready, provider-request or Main approval.

1. Qualify the exact existing private Main workflow change: its publication job,
   final-payload preparation and bounded private artifact, fixed concurrency,
   and read-only job token plus OIDC permission. Observe its actual OIDC subject
   before binding that subject in a newly admitted immutable registration.
2. Assign real process and custody owners. Admit separate least-privilege read,
   private journal and public Root PR publisher credentials. Wire the existing
   `AppTokenPreparer` and `HTTPSOnceSender` after current authorization; this
   module's transport input does not itself prove token custody or narrowing.
   Producers receive no public write key. Constrain credential access and
   network egress, and prove alternate direct writes are denied.
3. Explicitly approve and provision the journal ref and exact rule through the
   existing management process. Preserve intent/history without replacing or
   deleting it. Define retention, private access and recovery ownership from
   the actual operation requirements; no seven-year retention requirement is
   inferred from the separate Collection documentation issue.
4. Bind the selected content policy, protected-value corpus, complete inventory,
   private evidence sink and named-owner notification. Qualify the current
   private Main and Root sources together. This includes actual credential,
   isolation, durable journal and notification evidence, not callback fixtures.
5. Only under a concrete live-effect authorization, exercise one bounded real
   operation with exact target and payload. Read back the actual publisher App,
   original object ID and identical bytes. Verify replay, unknown outcome,
   changed text, stale generation, concurrent attempt and denied alternate
   write paths. Do not introduce a security scan or unbudgeted AI request.

For an unknown outcome, inspect the original native run, private intent/response
records and original object identifiers. Do not reset the journal, mint a new
operation for changed text, retry a request or use equal-text search as proof.
Escalate only the specific unresolved outcome for an explicit disposition.

## Remaining issue acceptance

This package does not demonstrate installed operation, source admission, live
credentials, monitoring or complete writer coverage. Hosted Copilot, automatic
Security, Renovate, installed Apps and interactive managed publishers each need
their own proven prepublication path or a legitimate protected replacement.
The two automatic Security settings remain ON / On PR open. Their documented
direct-publication gap does not block local owned-adapter development, and a
successful owned canary would not close issue #556 by itself.
