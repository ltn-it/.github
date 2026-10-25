# Observed Collection publication inventory

Reviewed 24 October 2026 in the user's timezone. The evidence below is a direct
read of immutable protected Main workflow source, together with the observed
Develop tips. It is static implementation evidence, not a claim that a workflow
ran successfully or that Nexus, credentials, environments or retention are live.

All six active Collections require the
[candidate-to-production target](collection-candidate-promotion.md). A future
Collection inherits the same contract through canonical onboarding guidance.

| Collection | Observed Main publisher source | Observed behavior and remaining gap |
| --- | --- | --- |
| Foundational | [bff0668](https://github.com/ltn-it/ansible-collection-foundational/blob/bff0668f6dde071b839d50f88f5a687fc37176f1/.github/workflows/collection-publish.yml) | Builds locally, publishes directly to Galaxy and dispatches transitional central validation afterward. Full Nexus-before-validation target unproven. |
| Supplementary | [7629452](https://github.com/ltn-it/ansible-collection-supplementary/blob/7629452aaed2ce00cbd3809114915337613deaed/.github/workflows/collection-publish.yml) | Contains a separate Security Nexus stage/central-evidence path and production readback; normal transition still exists. Source alone does not prove current-head Security or normal end-to-end acceptance. |
| OCP | [65894e7](https://github.com/ltn-it/ansible-collection-ocp/blob/65894e7f0c933d2f5b2b88914cf861bc0f36cc99/.github/workflows/collection-publish.yml) | Legacy direct build/Galaxy publisher; the Main publisher does not contain the later Develop transition dispatch. Nexus/central promotion is unproven. |
| RHEL | [087d8e1](https://github.com/ltn-it/ansible-collection-rhel/blob/087d8e1c5e628db0926ed38ba91767dfd2fe3ab6/.github/workflows/collection-publish.yml) | Legacy direct build/Galaxy publisher; the Main publisher does not contain the later Develop transition dispatch. Nexus/central promotion is unproven. |
| Ubuntu | [462fa70](https://github.com/ltn-it/ansible-collection-ubuntu/blob/462fa70d6f67b2436602e96a3100934f9dd2addb/.github/workflows/collection-publish.yml) | Builds locally, publishes directly to Galaxy and dispatches transitional central validation afterward. Full Nexus-before-validation target unproven. |
| Cloud | [34f8020](https://github.com/ltn-it/ansible-collection-cloud/blob/34f8020d4f6668be7ba47d7148007228e9ad1924/.github/workflows/collection-publish.yml) | Legacy direct build/Galaxy publisher; the Main publisher does not contain the later Develop transition dispatch. Nexus/central promotion is unproven. |

Observed Develop tips, which must not be substituted for production Main:

| Collection | Develop commit |
| --- | --- |
| Foundational | `1a8df3aece1da02ca31e6178444f1a8fe8b58a5c` |
| Supplementary | `6bc253b81a59e11a522a2ace94d4d8847e702caf` |
| OCP | `bf031dc052d906f222bde07f4cfb4130da5a00f7` |
| RHEL | `9042fc2fd9ebd7fbbb6d6b8ead0bc37b731e75ea` |
| Ubuntu | `71534b29debb29d9a637326578c49571cd5d1e88` |
| Cloud | `1309c301c8caa41cdc954bb3fc24c2f3c239680f` |

## Central transition and execution evidence

The [central Main transition source](https://github.com/ltn-it/modulix-validation/blob/c2a251041b121e59809b06e158b52dc6df81a0a3/.github/workflows/collection-release-transition.yml)
declares `transition-noop`, `validated=false` and `release_eligible=false`.
It prints a future command and runs no Heavy/Application validation or Galaxy
publication. It has no explicit job timeout and still recognizes the historical
organization namespace. Neither source presence nor a successful no-op is
cutover or production acceptance.

The same central Main revision's
[generic Collection cells](https://github.com/ltn-it/modulix-validation/blob/c2a251041b121e59809b06e158b52dc6df81a0a3/.github/workflows/collection-molecule-profile.yml)
and [runbook Heavy job](https://github.com/ltn-it/modulix-validation/blob/c2a251041b121e59809b06e158b52dc6df81a0a3/.github/workflows/ansible-runbook-heavy-profile.yml)
declare 180-minute execution timeouts. Those declarations do not prove that the
six candidate promotion paths call them, use the right digest or archive results.

## Documentation delivery and operating boundaries

The generated Collection `RELEASE.md` texts currently describe legacy publishing.
Their canonical generator requires correction and normal protected distribution
to every managed Collection. Supplementary's repository-owned `RELEASE.md` must
be updated with its separately owned candidate; generic synchronization must not
overwrite it. An unmerged local candidate is not installed documentation.

The open technical gaps remain distinct: Nexus availability and immutable
candidate intake, current-namespace admission, per-family impact routing,
complete repository/App onboarding, explicit deadlines and cleanup, exact-byte
Galaxy promotion/readback, actual approval-route acceptance and seven-year
immutable retention. The named cutover checklist defines their evidence; this
inventory does not mark them completed.
