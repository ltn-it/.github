# Common source release notes

This repository versions its reusable workflow source by immutable full Git
commit ID. These notes describe protected Main source revisions and the effect
of upgrading to them. A source publication does not independently select a new
verifier for a consumer, approve a release, or establish fleet adoption. Use the
existing protected management path for any independently admitted source change.

Maintainers update this human-readable record for source changes intended for
consumers. Entries describe behavior, compatibility and upgrade implications;
the raw commit log is not a substitute. Documentation candidates and unmerged
branches are not released source revisions.

## 25 October 2026 — organization identity and native evidence compatibility

Protected Main revision:
[`e4df45c87b6ea2d32124d13dc1cc9863f317dca5`](https://github.com/ltn-it/.github/commit/e4df45c87b6ea2d32124d13dc1cc9863f317dca5)

Immutable control runtime:
[`530b8fb175b7fccf238b03aab652bd5ee2ad2a41`](https://github.com/ltn-it/.github/commit/530b8fb175b7fccf238b03aab652bd5ee2ad2a41)

- Adopt the current organization identity in the common delivery source while
  retaining authenticated historical ingress and archive provenance. Historical
  compatibility does not authorize an arbitrary repository alias or rewrite an
  original proof.
- Share the final native workflow-generation revalidation through one reader.
  A consumer must still authenticate its own operation, approvals and applicable
  native evidence; a prior successful generation is not current acceptance.
- Preserve known historical qualified workflow paths without relaxing live
  source identity. Repository state must be explicitly known rather than
  inferred from absent, null or incorrectly typed fields.

Upgrade impact: delivery helpers must retain their exact immutable runtime
bindings. This Main publication does not itself migrate another repository's
selected verifier, deploy a publisher guard, establish OpenSSF Passing, or
accept a Collection candidate or production release. Existing review budgets,
quality gates, source admission and normal approvals remain applicable.

## 24 October 2026 — historical ingress after branch reuse

Source revision:
[`611464c2c84c7e67c909dde8a4bc51f192e7439b`](https://github.com/ltn-it/.github/commit/611464c2c84c7e67c909dde8a4bc51f192e7439b)

- Preserve genuine accepted ingress when GitHub reuses an automation branch for
  a later pull request and changes the old run's cached PR association. The
  original operation, source, successful jobs and proof remain independently
  authenticated; unrelated or ambiguous associations still block.
- Exclude an older native review delivery from a later PR's funding history
  only when strict native timestamps prove it predates that later PR. Equal,
  malformed or missing timestamps provide no exemption. Current pending or
  failed deliveries still prevent duplicate requests.
- Retain the independently admitted predecessor in the explicit source lineage
  so existing genuine proofs remain verifiable after a separately approved
  source change. Unknown sources remain rejected.

Upgrade impact: this revision corrects false blocking after branch reuse. It
does not refund a consumed review, retry a failed provider request, turn an old
failure into success or authorize a Main promotion. Existing policy selection,
current-revision checks and applicable native approval remain required.

## 23 October 2026 — paired closed-PR refresh history

Source revision:
[`5ea3415d2f385b93c930b6faf308534d4ad0d4e2`](https://github.com/ltn-it/.github/commit/5ea3415d2f385b93c930b6faf308534d4ad0d4e2)

- Recognize the exact historical topology where a genuine pre-merge successful
  ingress is followed by the paired delayed refresh failures caused solely by
  that PR already being merged and closed.
- Require the original successful binding and native closed-PR classifications,
  preserve both later failures, and reject missing, ambiguous, semantic,
  provider or current-head failure evidence.

Upgrade impact: this extends only the historical merged-PR reader. Open changes
gain no fallback, no additional review allocation and no automatic retry.

## 23 October 2026 — bounded read diagnostics and source compatibility

Source revision:
[`5111f81ba8aba4efe206186b59b659b8000ef1ec`](https://github.com/ltn-it/.github/commit/5111f81ba8aba4efe206186b59b659b8000ef1ec)

- Preserve safe GitHub API failure categories and recognize unambiguous native
  gateway status lines. Only payload-free GET requests with one clear transient
  502, 503 or 504 outcome may use at most three total attempts.
- Reject duplicate/conflicting statuses, authentication errors, malformed
  successful data and unknown outcomes. Mutations and model requests gain no
  retry. Provider bodies and credentials are not included in diagnostics.
- Retain the specifically admitted predecessor in the immutable source lineage.

Upgrade impact: consumers obtain bounded read-only resilience and clearer safe
diagnostics. A source upgrade neither selects itself nor restores an exhausted
review budget; normal protection and approval boundaries remain in place.

## Security reporting and historical context

No CVE fix is asserted by these entries. Report suspected vulnerabilities
through [SECURITY.md](SECURITY.md), without publishing undisclosed details in a
public issue. Earlier native operations and failed attempts remain historical
records; these notes never retroactively grant acceptance or declare an
unperformed rollout complete.
