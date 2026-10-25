# Collaboration content admission

## Current status

This is a prospective, locally testable implementation for issue #556. Source
presence does not activate a publisher, a monitoring service, or a protected
workflow source. The issue remains open until the integrations and actual
runtime acceptance below are observed.

The public common implementation lives in `scripts/collaboration_content.py`;
versioned policy lives in `.lit/collaboration-content-policy.json`. Its caller
must load those files from the independently accepted source, never from an
untrusted pull request. Positive and negative fixtures are executable through
`tests/test_collaboration_content.py` in the pinned Devtools environment.

## Managed publication boundary

The existing publishing transport calls `guarded_payload` with the final API
payload and a fresh complete trusted inventory. The function serializes once,
checks every submitted string including inline review bodies, and passes those
same immutable bytes to the existing transport only after admission. Unknown
publication fields fail closed. There is no mutation retry or new credential.
An admission receipt never authorizes an operation or replaces native review.

Supported content kinds are issues, pull requests, reviews, issue comments and
inline review comments. Every create or edit needs a fresh call. The guarded
function is not yet wired into the existing private publishers or distributed
legacy templates; it must not be described as enforced there.

The initial source inventory identifies these distinct publication families:

| Family | Required integration | Present limitation |
| --- | --- | --- |
| Protected promotion preparation | Final PR title/body before create | Private administration source owns the transport. |
| Managed asset distribution | Final PR and provenance-comment payloads | Private distribution source owns create and comment operations. |
| Existing Collection release and back-sync templates | Every final PR payload | Canonical template and installed consumer revisions must both be enumerated. |
| Legacy request/remediation templates | Every reservation and remediation comment | Retired runtime paths stay retired; source-template presence is not evidence of active deployment. |
| Native hosted reviewers | Review body and inline comments | The current reviewer-request API exposes no final text to our pre-publication validator. |
| Hosted dependency dashboard | Generated dashboard body and edits | The current hosted service publishes directly; local configuration is not a final-payload interception point. |
| Interactive AI/tool publishing | Final tool payload before submission | Repository code cannot intercept arbitrary independent connector calls. |

Native hosted publishing cannot be silently reclassified as validated. An
explicitly reviewed operating design must either provide an actual mediation
point or record those paths as unsupported and prevent their managed public
publication. Monitoring after publication is a different control and cannot
satisfy the pre-publication requirement for them. Existing required reviewers,
dependency checks and protected controls cannot be disabled by this change.

## Policy and exceptions

The bounded policy rejects tracker identifier forms, private tracker suffixes,
non-public network addresses, common credential forms, secret assignments and
email addresses. Unicode compatibility normalization, HTML entities and bounded
percent decoding occur before inspection. Hidden formatting characters and
malformed or excessive input fail closed. Code fences are inspected too.

GitHub source links must resolve to a public repository in the complete trusted
inventory. Unknown owners, unknown repositories and private/internal targets
are rejected. Historical organization aliases are not inferred from a redirect.
The inventory producer must authenticate any supported migration separately.

External public-source exceptions are exact HTTPS URLs in the versioned policy,
with a documented public-source verification in the reviewing PR. There is no
domain-wide bypass, query-string bypass or runtime skip flag. A false positive
requires a narrowly reviewed policy revision and regression fixture. Do not
paste the rejected value into a public review or exception request.

Private exact-value additions use normalized SHA-256 values, not raw protected
infrastructure. Their provenance and review stay private. Empty supplemental
data does not establish an inventory of every protected value.

This deterministic control does not recognize every natural-language personal
name, customer fact, novel secret format, or deliberately encoded disclosure.
It makes no universal data-loss-prevention claim. Human content review and the
private incident process remain necessary. A known real secret or regulated
data finding goes directly to that process; generic metadata findings alone
do not establish a credential compromise.

## Read-only observation

`scripts/collaboration_inventory.py` obtains a fully paginated organization
repository inventory, checks its public/non-public counts against authoritative
organization metadata and requires administrative inventory visibility. Missing
counts, unreadable visibility, duplicate IDs, missing terminal pages, API errors,
count drift and expired inventories fail closed. A partial list is never clean.
The current adapter is an operator inspection tool; it does not prove that a
least-privilege production monitoring identity has been provisioned.

The observer reads explicitly selected public repositories' open issue titles,
bodies and current issue comments. It rechecks issue metadata and open-item
enumeration for drift. Source text remains in memory. Private receipts contain
only the inventory, native object locators, safe categories, counts, hashes,
timestamps and deterministic dispositions. They never contain source bodies or
matched values. Receipts require a private output directory, mode 0600 and
exclusive creation. Public Actions artifacts are not a private reporting sink.

This observer has only a fixed GET implementation. It cannot delete a comment,
change visibility or rewrite history. An operating deployment additionally needs
an independently provisioned read-only identity, named owner `litroc`, a private
remediation sink, an agreed maximum detection interval and actual notification
delivery. None of those deployments is implied by a local observation receipt.

The declared initial content scope excludes closed issues, pull requests,
reviews, inline comments, edit histories, attachments, timeline events,
releases, repository files, wikis, external caches and unselected repositories.
An observation is a bounded time window, not an atomic organization snapshot.
Comment edits after their individual read can race the observer. No statement
that the entire organization is clean follows from an open-issue observation.

## Separate history procedure

The detector never deletes or edits a revision. Resolve each native content node
and exact revision ID in the private remediation record. Record its availability,
deletion timestamp, safe finding category and hash without copying its diff.
`history_disposition` rejects malformed or contradictory history metadata and
never infers deletion authority from the presence of a target.

Before a redaction, obtain explicit human authorization for that exact node and
revision, the intended effect and retained evidence. Re-read the target before
the separately operated native action. Afterward read back `deletedAt` and diff
availability. An unavailable observation is unknown, not proof of deletion.
Issue deletion requires its own explicit fallback authorization. History,
attachments and external caches retain their separate acceptance boundaries.

## Acceptance checklist

- Version and review policy, source and executable fixtures through normal PRs.
- Bind and validate each real publisher's final bytes before every effect.
- Observe actual complete inventory and each declared current content surface.
- Correct confirmed findings without publishing private source values; read back.
- Deploy and qualify the private monitoring/notification path with read-only rights.
- Resolve native hosted publisher mediation without weakening required controls.
- Observe the applicable current-revision checks and protected integration.
- Close #556 only after every issue acceptance criterion has its actual evidence.
