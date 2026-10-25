# Collection candidates and validated Galaxy promotion

This target contract applies to every current and future Lightning IT Ansible
Collection. Nexus is the development/candidate Galaxy V3 registry;
`galaxy.ansible.com` is the production registry. Size, role family and the
existence of an older direct publisher do not exempt a Collection.

The [observed Collection inventory](collection-promotion-inventory.md) separates
the current transition from this target. Documentation and source code alone
do not prove deployment, a validated candidate or a completed cutover.

## One immutable candidate, two registries

Build a semantic-versioned Collection exactly once from the authenticated source
commit. Bind its repository, source commit, version, artifact filename and
SHA-256 to its signature, SBOM, provenance, dependency/security scan results and
the exact policy identity. Stage and read back those same bytes in Nexus before
central validation. A mutable tag or version lookup without the expected digest
cannot select the validation input.

The central validator downloads the candidate by its exact digest and verifies
every binding before executing affected Heavy role families. Application
Acceptance follows successful Heavy execution. The producer declares impact;
the reviewed central impact policy selects actual cells. Missing or ambiguous
impact expands to the required supported coverage or blocks; it never silently
becomes an empty successful matrix.

Promotion consumes only complete, authentic, unexpired evidence for this exact
candidate. It never rebuilds or repacks the tarball. After Galaxy publication,
download the production artifact, verify its signature and prove that its
SHA-256 equals the original Nexus candidate. Install that downloaded artifact
in a clean path and execute the supported FQCN smoke test. The signed final
receipt records actual source/run/attempt identities, digests, executed cells,
cleanup, approval route and post-publication readback. A skipped or failed
mandatory cell never creates release eligibility.

## Exact-version development and customer debugging

Use the privately supplied candidate server configuration and read-only Nexus
credentials. Keep them outside the repository and shell history. Select only
that candidate server for a reproduction, use the exact semantic version and
an isolated collection path, and verify the downloaded digest against the
candidate record before installation. Do not resolve the latest version or
silently fall back to production if the candidate is unavailable.

The client configuration and installation syntax are documented by
[Ansible](https://docs.ansible.com/projects/ansible/latest/collections_guide/collections_installing.html).
For example, after the private server alias `candidate` has been configured:

```bash
ansible-galaxy collection download 'lit.foundational:1.2.3' --server candidate --download-path ./candidate-download
```

`1.2.3` is illustrative. Substitute the exact recorded candidate version, verify
the downloaded artifact's SHA-256, then install that local tarball into a fresh
collection path. Resolve and pin dependencies through their own approved source
policy. Access to a development candidate does not certify production support
or authorize the customer to publish it to Galaxy.

## Transition and release acceptance

The existing central `transition-noop` accepts a source/artifact locator, prints
a future promotion command and records `validated=false` and
`release_eligible=false`. It executes no Heavy or Application Acceptance tests
and performs no Galaxy publication. Green completion proves only that this
transition job completed; it cannot satisfy release acceptance.

Some installed source publishers still build and publish directly to Galaxy.
That is the operating transition, not evidence that the Nexus target is active.
Supplementary additionally contains a distinct Security candidate path; its
source presence does not establish a successful current-head operational run
or extend that path to another Collection.

A manual workflow start grants no production publication authority. In the
target, ordinary promotion requires the existing genuine one-person approval;
the same authorized person may approve an operation they started. The separately
admitted Security route remains reviewer-free with `humanActions=0` and must
prove its own exact producer/consumer identity and native Security gates.
Neither route may bypass protection, fabricate a review or reuse a stale head.

## Role-family scheduling, cancellation and deadlines

The source Fast lane remains unprivileged and impact-selected. Central
validation owns Heavy/Application runners, temporary resources, cleanup and
evidence. Source repositories retain reusable tests, not parallel privileged
schedules. Stable source check names remain `Collection / Fast` and, where
required, `Collection / Release Evidence`; a no-op never uses a name implying
Heavy or Application Acceptance execution.

Use one concurrency identity for repository, candidate and role family.
Superseded pending validation can be canceled. Cancellation of a running cell
must still execute cleanup and record the actual canceled result; neither its
old evidence nor an unfinished successor can be promoted. Never cancel a
publication operation with an unknown outcome and blindly publish again.

The currently observed central generic Collection and runbook Heavy cells each
have an explicit 180-minute limit. The central transition job lacks an explicit
job timeout; several legacy source publishers do too. Those are cutover gaps,
not permission to inherit the platform's implicit deadline.

Before cutover, the reviewed execution policy must bind explicit numeric
timeouts for build, Nexus stage/readback, every selected Heavy/Application cell,
cleanup, promotion, Galaxy readback and any evidence wait. Reuse 180 minutes only
for those existing supported central cells; define other values with the owning
execution profile. Record the applied values in the final receipt. An expired
deadline fails closed and does not renew on another polling step. Evidence
freshness defaults to at most 36 hours; any changed bound identity invalidates
reuse even within that period.

## App, credential and operational ownership

| Responsibility | Existing identity/configuration surface | Required boundary |
| --- | --- | --- |
| Source PR and dispatch automation | Release Automation App; `RELEASE_AUTOMATION_APP_CLIENT_ID` and `RELEASE_AUTOMATION_APP_PRIVATE_KEY` | Exact consumer repository and only the operation's permissions; no personal access token in Actions. |
| Dedicated Supplementary tag creation | `RELEASE_TAG_APP_ID`, `RELEASE_TAG_APP_CLIENT_ID`, `RELEASE_TAG_APP_INSTALLATION_ID`, `RELEASE_TAG_APP_PRIVATE_KEY` | Prove actual App/install/repository identity; workflow-token identity is not a substitute. |
| Nexus candidate stage/readback | `NEXUS_GALAXY_REPOSITORY`, `NEXUS_GALAXY_REPOSITORY_URL`, `NEXUS_GALAXY_USERNAME`, `NEXUS_GALAXY_PASSWORD` | Protected candidate writer; separate read-only developer/customer and central-validation access. |
| Production Galaxy publication | `ANSIBLE_GALAXY_API_KEY` in the admitted publishing environment | Only the authenticated promotion path receives it, after validation and applicable approval. |
| Heavy/Application execution | Central validation service and role-scoped protected environments | No publishing credentials or unrelated family infrastructure access. |
| Durable release evidence | Protected evidence-archive identity | Append-only seven-year immutable retention, encryption, checksum verification and independently readable receipt. |

These are observed configuration names and required operational responsibilities,
not evidence that credentials exist or have been rotated. The private operating
record must name each actual accountable owner, exact App/installation IDs,
credential custodian and rotation/revocation process before onboarding. Do not
invent a person or publish secret values, endpoints or private evidence links.

Organization-wide installation/baseline eligibility does not grant every
repository privileged role-family access. Onboarding must discover the complete
current selected-repository App inventory, authenticate each new repository and
visibility, and separately admit its required role environments and secrets.
An unknown or incompletely paginated inventory blocks; a static pilot allowlist
does not silently onboard future Collections.

## Negative cases and immutable versions

Reject missing or mismatched Nexus bytes, stale source or policy identity,
invalid signatures, absent scans/SBOM/provenance, incomplete pagination,
unauthorized App scope, unsupported impact, expired evidence, missing approval,
mandatory failures/skips, failed cleanup and unknown publication outcomes.
Reject every attempt to promote a transition receipt or publish production
through a manual-start shortcut.

The same version with the same digest may finish idempotently only after
authoritative readback of the published bytes and associated evidence. The same
version with another digest fails. Never overwrite published bytes, move a tag
or delete evidence to make a retry look new. Corrections require a new semantic
version and retained revocation/supersession evidence.

## Cutover checklist for each Collection

- Record exact protected source, common source, policy and installed consumer revisions.
- Publish the complete candidate once to Nexus and verify its exact bytes on readback.
- Prove exact-version developer/customer installation with least-privilege access.
- Admit the actual repository/App inventory and required role-scoped environments.
- Execute affected Heavy and then Application Acceptance cells with explicit deadlines.
- Exercise signature/digest/source/policy mismatch, missing/expired evidence,
  failed/skipped/canceled cells, cleanup failure, API/pagination failure,
  unauthorized/manual publication and conflicting-version negative cases.
- Prove normal one-person approval and the separately admitted Security
  `humanActions=0` route without weakening either route's native controls.
- Promote without rebuilding; download Galaxy bytes and prove the Nexus/Galaxy
  digest equality plus clean installation/FQCN smoke.
- Verify same-version/same-digest idempotency and different-digest rejection.
- Sign and independently verify the final receipt and complete immutable
  seven-year archive; Actions artifact retention alone is insufficient.
- Run a new end-to-end operation on the final current head after the last
  material source/configuration change. Prior-head success is historical evidence.
- Read back live installed workflows, policies, App scope, native results,
  production bytes and evidence retention. Record gaps and excluded surfaces.
- Update the observed inventory only after these actual results. A documentation
  merge closes a documentation deliverable, never an unperformed runtime cutover.
