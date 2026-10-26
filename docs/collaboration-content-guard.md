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

Repository visibility is necessary but does not prove that an administration or
draft resource is public. The offline guard admits only the repository home,
public issue/PR/discussion routes, full commit IDs, blob/tree/compare/wiki paths,
security-policy page and public Actions run/job/attempt routes. Listing pages
for releases and tags are supported; individual release/tag links are not yet
admitted because an authenticated maintainer can also see drafts. Settings,
advisories and unknown routes fail closed. This check does not assert that an
individual referenced resource exists; extending support needs public-resource
evidence and regression fixtures, not a broad path bypass.

External public-source exceptions are exact HTTPS URLs in the versioned policy,
with a documented public-source verification in the reviewing PR. There is no
domain-wide bypass, query-string bypass or runtime skip flag. A false positive
requires a narrowly reviewed policy revision and regression fixture. Do not
paste the rejected value into a public review or exception request.

The exact public project URL `https://www.bestpractices.dev/projects/15886`
was verified through its public project JSON to identify `ltn-it/.github` after
actual enrollment. That exception admits neither another project nor query
parameters, and says nothing about whether the project has achieved Passing.
The initial saved questionnaire was still in progress at 99 percent.

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

By default the observer reads explicitly selected public repositories' open
issue titles, bodies and current issue comments. The explicit
`--include-open-pulls` option also reads open PR titles/bodies, current PR
conversation comments, submitted reviews (including dismissed reviews) and
inline review comments. Pending review drafts and their comments are excluded.
It rechecks parent metadata, comment/review snapshots, open-item enumeration
and repository visibility for observed drift. Source text remains in memory. Private receipts contain
only the inventory, native object locators, safe categories, counts, hashes,
timestamps and deterministic dispositions. They never contain source bodies or
matched values. Receipts require a private output directory, mode 0600 and
exclusive creation. Public Actions artifacts are not a private reporting sink.

This observer has only a fixed GET implementation. It cannot delete a comment,
change visibility or rewrite history. An operating deployment additionally needs
an independently provisioned read-only identity, named owner `litroc`, a private
remediation sink, an agreed maximum detection interval and actual notification
delivery. None of those deployments is implied by a local observation receipt.

The initial live receipt covered open issues only; the optional broader path
requires its own actual readback and runtime acceptance. Both scopes exclude
closed issues/PRs, edit histories, attachments, timeline events, releases,
repository files, wikis, external caches and unselected repositories. The broader
scope also explicitly excludes pending review drafts. An observation is a
bounded time window, not an atomic organization snapshot. Edits after each
final individual read can still race the observer. A clean selected-scope
observation never establishes that the entire organization is clean.

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


Admission applies NFKC again after every bounded HTML/percent decode, including
its fixed-point check. Known GitHub token prefixes include the underscore, dot
and base64url segments of stateless installation tokens. The same detector is
shared with private custody, which inspects both wire bytes and JSON-decoded
strings/keys before writing. No matching value is included in a rejection.

Markdown inline/image/reference destinations and HTML href/src destinations
must use a verified absolute HTTPS URL. Relative destinations are rejected
because this boundary has no trusted rendering/base-ref context to establish
their destination visibility. Safe in-page anchors remain allowed. Ordinary
file path text is unchanged; use a verified absolute public URL for a document
link instead of a relative destination. This change grants no publisher or
source admission and does not turn local tests into operating coverage.


All recognized HTML href/src, Markdown inline/image/reference and prose autolink
candidates now share one strict destination validator. HTML attributes retain
their complete parsed values from both original and normalized text, so entity
decoding cannot split one browser attribute into a safe URL and an ignored tail. Before URL splitting or policy comparison, the
validator rejects whitespace, controls, backslashes and non-ASCII URL spelling;
it never repairs a browser-normalized destination. Bare `www.` autolinks are
recognized and rejected: use an explicitly verified absolute HTTPS URL instead.
Exact external sources, repository visibility/route checks, same-page anchors,
ordinary file-path prose and the unchanged policy allowlist retain their scope.


### Markdown grammar and native repository references

Markdown destinations are extracted by the tested `markdown-it-py==4.2.0`
CommonMark parser, including multiline reference definitions and blockquote/list
containers. The parser's URI repair and scheme filter are disabled for inspection;
the existing strict destination/visibility policy alone decides admission. Raw
and normalized HTML values and prose autolinks retain their independent capture
boundaries. Code text is inspected under explicit nesting/work limits; reaching
a parsing bound produces an unknown rejection rather than a partial clean result.
There is no fallback to the former incomplete Markdown destination regexes.

GitHub-native `owner/repository#number` and `owner/repository@commit` references
enter the same public inventory and URL-route policy. Issue numbers must be
canonical, and commit references must contain the full forty hexadecimal digits;
short commits remain unsupported even where GitHub can render them. Unknown or
private repositories cannot gain visibility authority through shorthand spelling.
Ordinary file-path prose, safe same-page anchors and existing exact sources keep
their scope; no public-source exception was widened.

The qualified dependency and its `mdurl` dependency are present in the tested,
digest-pinned Devtools runtimes. The adopting caller must preserve its accepted
runtime binding and this parser version. Missing, unqualified or failing parsers
reject with the fixed safe category `content-parser-unavailable`; they never
silently skip inspection or install dependencies at runtime. Declaring this
requirement does not activate a credential controller or grant source admission.
