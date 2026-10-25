# Native issuer integration pilot

`scripts/collaboration_native_issuer.py` implements the read-only issuer side
for one Root Develop `review.create` operation from an authenticated native
Required job. This is executable local preparation, with real RSA verification
and the existing native generation, operation-artifact and funding readers.
It is not an installed issuer or an accepted replacement for native reviews.
The private Ops approval envelope is not an input or a prerequisite.

## Authentication and actual authorization

The broker verifies an RS256 JWT using keys fetched once from GitHub's fixed
OIDC JWKS endpoint over verified TLS. Unknown or duplicate keys, alternate
algorithms, contributor key URLs, malformed claims and expired tokens block.
The exact audience binds operation, PR, final payload hash, accepted-policy
hash and inventory hash. Repository and owner numeric identities, visibility,
event, exact subject, source workflow reference and SHA must match admission.
The documented GitHub claims are described in the
[OIDC reference](https://docs.github.com/en/actions/reference/security/oidc).
The initiating user's `actor_id` is not treated as the publisher or origin.

Registration comes exclusively from
`.lit/collaboration-publisher-registration.json` at the SHA in active Root Main
organization ruleset 25154946. Its exact Root/main conditions and sole Required
workflow selector are authenticated. Neither candidate HEAD, a user-supplied
registry, an Evaluate-only rule, nor a mutable Main file can admit this issuer.
The registry file contains these fields:

| Field | Contract |
| --- | --- |
| version | Integer 1 |
| repository_id | Root numeric ID 1112629689 |
| principal_kind | `github-actions-job` |
| origin_producer_id | Independently registered numeric principal for this exact job/source; not an invented GitHub bot identity |
| publisher_actor_id | Independently verified actual credential-bearing GitHub publisher actor |
| subject | Exact actually observed and admitted GitHub OIDC subject |
| workflow_ref | `ltn-it/.github/.github/workflows/change-control-required.yml@refs/heads/main` |
| operation | `review.create` |
| job | `Protected current revision` |

The independently selected commit supplies `source_sha` after the immutable
file read. A file cannot contain its own Git commit hash. There is deliberately
no proposed live registry with guessed subject, principal or actor values.
The existing selected R4 source has no such registry; live use must reject.
Registration is read again before the final generation verification.

The content policy is read from the same immutable accepted source. Its hash
must match the submitted policy. The actual complete organization inventory
reader authenticates organization metadata, owner membership and repository
counts; its exact repository identity/visibility/archive rows must match the
hash-bound fresh inventory supplied for publication. A selected App's partial
view cannot replace this reader. The private protected-value corpus and complete
writer inventory still require their own actual operating evidence.

## Native proof, existing budget and last read

The signed run/attempt/check-run claims must identify the real in-progress
Required workflow and its actual job, repository, source and current PR tuple.
The immutable native operation artifact must bind the same complete subject.
The native reservation step, actual Codex action and protected receipt-collection
step must all have completed successfully. A started reservation alone is not
a model result. A result containing findings can still be published; publishing
it grants no passing review or Main approval.

The reader rejects a previously funded attempt or earlier applicable funded
generation. It neither allocates another provider request nor implements the
separately governed recovery exception. Recovery requires separate real native
proof support; an old consumed allocation is never reset or silently ignored.

After artifact, policy, inventory, registration, target and budget reads, the
existing `revalidate_native_generation` performs the final I/O. Its last run
list catches a generation started during earlier evidence reads. Expiry is
checked again after that I/O. The returned immutable facts bind the full native
generation, source, registered origin and independent publisher actor.

The operation ID depends on repository/run/attempt/job/PR/operation, **not**
payload hash or JWT identifier. New bytes or another token cannot obtain a new
write slot. `NativeReviewIssuer.attest` independently recomputes the entire
authorization, including its final-byte hash; forged dataclasses do not confer
authority. `Publisher` calls it before the durable claim and again immediately
before the one fixed transport effect. The actual private ledger is still
required across all issuer instances and crashes.

## Concrete remaining operating integration

The proposed producer insertion point is after `Collect and verify the protected
model receipt`, before any public raw-result upload and before acceptance of
the review. An accepted immutable source must render from the root-owned bounded
gateway receipt through `collaboration_review_result`, request a short-lived
operation-bound OIDC audience, and send those frozen bytes to the private broker.
The broker constructs the issuer and publisher internally; callers cannot supply
the API, JWKS implementation, admission map, credential, attestor or sender.
The current source lacks this call, its required job-scoped `id-token:write`
permission, registry and admitted broker. None has been enabled by preparation.

Run and job source claims must be observed in a real authorized native pilot;
GitHub documents different additional claims for reusable workflows. A missing
or different claim is a rejected operation, never a guessed fallback. The
actual publisher credential must be authenticated separately and isolated from
the producer, validator and response renderer. Its process, trust store,
network egress and alternate-write denial are deployment requirements.

Store raw gateway/provider results only in actual private custody. The existing
public Actions raw-response artifact is not that custody. A private exact-effect
observer must reconstruct ambiguous outcomes without resending. The pilot
does not mediate hosted Copilot, automatic Security, Renovate, other Apps or
interactive writers. Those actual integrations, complete credential coverage,
private monitoring/owner notification and current clean scope readback remain
necessary for full #556 completion. Existing protected reviews and consumed
budgets remain in force during development; no generic bootstrap ban applies.

Offline tests use generated test RSA keys, native API response edges and a
temporary native operation artifact. They execute the real signature, artifact,
budget and shared final-generation readers and the actual private ledger chain.
They prove rejection of forged signatures/facts, wrong or stale subjects,
missing policy/source/visibility/capture/budget state, changed registration,
token expiry during artifact reads and a new generation at the last read.
They do not establish live admission or a deployed trust boundary.
