# Lightning IT · GitHub organization and common workflows

This public repository contains the Lightning IT GitHub organization profile,
contribution templates, and common quality, review and delivery workflow source.
It is maintained in [`ltn-it/.github`](https://github.com/ltn-it/.github).

The Root reference has an active protected Main control. Other repositories
remain in their documented POC transition until their individual scope is
explicitly admitted. Copying a workflow or changing a configuration file does
not activate that scope or select its trusted verifier.

<!-- BEGIN LIT_QUALITY_BADGES -->

[![CI](https://github.com/ltn-it/.github/actions/workflows/repository-quality.yml/badge.svg?branch=develop)](https://github.com/ltn-it/.github/actions/workflows/repository-quality.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ltn-it/.github/badge)](https://scorecard.dev/viewer/?uri=github.com/ltn-it/.github)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15886/badge)](https://www.bestpractices.dev/projects/15886)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

<!-- END LIT_QUALITY_BADGES -->

## Repository contents

| Path | Purpose |
| --- | --- |
| [`profile/README.md`](profile/README.md) | Public GitHub organization profile |
| [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) | Bug, feature, change, task and security-readiness issue forms |
| [`.github/pull_request_template.md`](.github/pull_request_template.md) | Pull request description template |
| [`.github/workflows/`](.github/workflows/) | Common control, delivery, repository quality and Scorecard definitions |
| [`scripts/`](scripts/) | Workflow policy, review transport, evidence and deterministic validation helpers |
| [`tests/`](tests/) | Regression tests and sanitized fixtures for those helpers |
| [`.lit/`](.lit/) | Repository classification, workflow contracts and policy metadata |
| [`docs/`](docs/) | Operating guides, architecture decisions and historical migration records |

## Workflow entry points

| Workflow | Responsibility |
| --- | --- |
| [`repository-quality.yml`](.github/workflows/repository-quality.yml) | Run the pinned deterministic profile on PRs and protected pushes; signal Root promotion preparation after successful current Develop quality |
| [`change-control-required.yml`](.github/workflows/change-control-required.yml) | Apply the independently selected native control to the current revision, including applicable review, quality/security checks and normal promotion approval |
| [`delivery-operations.yml`](.github/workflows/delivery-operations.yml) | Refresh the original verifier after native review/metadata events and signal preparation for explicitly admitted consumers |
| [`review-events.yml`](.github/workflows/review-events.yml) | Emit an unprivileged, checkout-free review event for the protected receiver |
| [`openssf-scorecard.yml`](.github/workflows/openssf-scorecard.yml) | Assess repository security posture |

Privileged promotion preparation belongs to the protected Management path.
Preparation grants no approval or merge authority. Consumers retain their own
product tests, builds and publishing checks; private code, credentials and
results remain in the consumer's visibility boundary.

Use the [workflow contract](docs/workflow-target.md),
[entry-point catalog](docs/workflow-target-catalog.md) and
[operator guide](docs/protected-runtime-operations.md) for the full procedure.
Historical ADRs and qualification records describe their original revision;
current authority comes from the independently effective native settings.

## Branches and contribution flow

| Branch | Role |
| --- | --- |
| `develop` | Default integration branch for normal changes and managed synchronization |
| `main` | Protected stable branch; updated through a normal Develop promotion PR |
| `lit-review-operations` | Protected historical operation-data ref; retained for audit integrity |
| `recovery/ltn-it-identity-v1` | Explicitly protected namespace-migration recovery point |

Use a short-lived branch and a PR into `develop`. Include current Main ancestry
when Main is ahead, preserve both branches' intended content, and finish the
applicable current-revision checks and ingress review before integration. Delete
completed working and qualification branches after checking for unmerged work.
The protected data and recovery refs are not development branches.

The admitted Root Main route requires its prescribed native review evidence,
technical checks and genuine one-person normal release approval. One authorized
person can approve their own operation. Unadmitted scopes retain the documented
[POC process](docs/poc-workflows.md); it does not waive active native requirements.

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) before making
changes. Do not reactivate retired review, retry or promotion controllers.

## Local validation

From a clean, committed checkout with `origin/develop` available, run:

```bash
scripts/lit-ci-profile.sh repository-quality
```

The dispatcher uses the existing digest-pinned Devtools container through
Docker or Podman. It checks instruction binding, repository policy, the workflow
contract, unit tests, Actions syntax and Git diffs. Local validation never calls
an AI reviewer. See [TESTING.md](./TESTING.md) for prerequisites and interpretation.

<!-- BEGIN LIT_SHARED_RELEASE_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.

Repository classification: **Repository Profile**.
Required test profiles: `markdown, repository-profile`.
Publishing targets: `none`.

See [RELEASE.md](./RELEASE.md) for the branch flow and managed release model.
This repository publishes no product artifacts. Protected Main promotion and
its native control requirements still apply.

## Supported and Tested Platforms

| Platform / Product | Status | Validation |
| --- | --- | --- |
| ubuntu-latest | Supported | Repository quality |
| github-profile | Tested where applicable | Repository quality |

<!-- END LIT_SHARED_RELEASE_MODEL -->

## Evidence and rollout status

Ordinary Develop PRs retain native GitHub checks and review evidence without
creating duplicate durable release packages. Full Main release acceptance still
requires its complete audit package and verified seven-year immutable retention.
Native GitHub artifacts or storage qualification alone do not establish that
archive. The complete native archive producer and private rollout acceptance
remain separate acceptance items; the public reference does not establish fleet
production acceptance.

## Documentation and security

- [Protected runtime operations](docs/protected-runtime-operations.md)
- [Source-owned common quality](docs/source-owned-common-quality.md)
- [Root control reference checks](docs/root-control-reference-checks.md)
- [Root CodeQL merge protection](docs/root-codeql-merge-protection.md)
- [Validation lanes](./MODULIX-VALIDATION.md)
- [OpenSSF readiness](OPENSSF.md)
- [Security policy and private vulnerability reporting](./SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

Licensed under the [MIT License](./LICENSE).
