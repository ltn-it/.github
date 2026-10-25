# ModuLix validation lanes

This organization-wide guidance applies to ModuLix source repositories and central
validation. It does not change the `.github` repository's own
`repository_profile` classification, test profiles, or release behavior.

The public [Collection candidate/promotion contract](docs/collection-candidate-promotion.md)
defines Nexus as the candidate registry and Galaxy as production for every
current and future Collection. The [observed inventory](docs/collection-promotion-inventory.md)
separates installed transition paths from the target and records exact sources.
Internal governance and acceptance records retain their private system boundary.

## Ownership and triggers

- Source pull requests run Static/Build, Unit/Contract, and impact-selected Tiny checks without privileged infrastructure.
- `modulix-validation` owns Heavy and Application Acceptance scheduling, protected runners, secrets, cleanup, and evidence.
- Application Acceptance starts only after successful Heavy validation.
- Releases verify evidence for the exact immutable candidate instead of synchronously repeating Heavy and Application Acceptance.
- Missing, expired, revoked, or mismatched evidence fails closed and requires central manual validation.
- Pull-request authors identify affected profiles, but the validated central policy is authoritative and the declaration never authorizes privileged execution of untrusted code.

Required GitHub Actions checks provide technical gate evidence; they cannot
approve a pull-request review. REP-70 applies to protected deployment
environments and does not change pull-request review policy. Required human
approval counts may be zero; required conversation resolution remains a
separate branch/ruleset control.

Source repositories keep reusable role tests and environment-neutral scenarios.
They do not add source-owned Heavy or Application Acceptance schedules.

## Stable contexts and names

Stable source-repository contexts are:

- `develop`: `Collection / Fast`
- `main`: `Collection / Fast` and `Collection / Release Evidence`

Job names describe what actually happened. A skipped, delegated, compatibility,
or no-op adapter must not use a name that implies Heavy or Application
Acceptance executed. Those profile names belong to real central runs in
`modulix-validation`. Temporary migration aliases must be identifiable as
compatibility checks and removed after the stable aggregates report on both
protected branches.
A compatibility alias communicates migration state only; it is never release
evidence and must not imply that a protected profile executed.

## Evidence and exceptions

The default evidence freshness ceiling is 36 hours. Evidence binds the full
source SHA and immutable tree or artifact digest, tested component and image
identities, policy and matrix identities, workflow SHA, executed cells and
results, timestamps, cleanup result, run identity, and tamper-resistant
provenance. Any bound identity change invalidates reuse.

Exceptions require a control ID, reason, owner, approver, linked ADR,
compensating controls, start date, expiry date, and review date. Source-owned
Heavy schedules or synchronous PR Heavy/Application execution without a current
exception are not permitted.

## Implementation responsibilities

Each implementation layer must provide its own current-revision evidence.
Documentation does not claim completed cross-repository enforcement:

- The private canonical distribution source owns versioned policy schemas,
  renderers, templates and distribution contract tests.
- [`modulix-validation#134`](https://github.com/ltn-it/modulix-validation/issues/134)
  tracks central orchestration, evidence verification, cleanup and failure tests.
- [`ansible-collection-supplementary#554`](https://github.com/ltn-it/ansible-collection-supplementary/issues/554)
  tracks the pilot Fast Lane, impact selection and scheduling boundaries.
- Private administration owns branch-specific required contexts, environment
  admission, scoped App access and live drift detection.

The repository-local documentation deliverable is tracked in
[issue #55](https://github.com/ltn-it/.github/issues/55).
