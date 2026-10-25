# Strict pre-publication publisher migration proposal

Status: prepared proposal for issue #556, not an admitted operating design.
The owner retained the strict requirement: managed public issue, PR, review and
comment text must be validated before publication. Post-publication detection
cannot replace that control. The new offline helper is only a building block;
this proposal neither activates it nor changes reviewer or credential authority.

## Required invariant

Each managed producer prepares a complete final payload without a credential
that can publish collaboration text directly. The accepted publisher owns the
narrow write capability, obtains the current trusted visibility inventory,
checks all final title/body/inline strings and submits exactly the admitted
bytes. Unknown endpoints, malformed payloads, unavailable inventory, rejected
content and uncertain writes block. The producer cannot select a weaker policy,
substitute a new payload or use another credential to bypass the publisher.

The publisher is not a general GitHub proxy. Admit exact create/edit endpoints,
repository and operation subjects under the existing protected-source model.
Do not grant deletion, visibility administration, history rewriting or review
approval authority to a content filter. An approval/review remains a separate
native trust decision; a valid content receipt never supplies that decision.

## Separately prepared changes

| Publication family | Proposed correction | Acceptance before any claim of enforcement |
| --- | --- | --- |
| Controlled PR/comment publishers | Call the shared validator at the last transport boundary, with the actual final JSON bytes. Keep current source, actor, scope, approval and at-most-once rules. | Actual allowed and rejected create/edit attempts for every installed route; no direct alternate transport. |
| Hosted native AI reviewer | Replace the unmediated publication capability with a provider route that returns its complete result to a protected preparation step before any GitHub review/comment write. | A separately approved review-source/proof contract, actual private result capture and complete mediation, with existing review authority independently migrated. |
| Hosted dependency service | Prepare an owner-controlled execution path whose worker cannot post PRs/issues/comments directly. Only its narrowly scoped publisher can issue those mutations after admission. | Real dependency discovery/branch/PR/dashboard flow, malicious generated metadata tests and denied direct-write attempts. |
| Interactive managed AI/tool actions | Submit final payloads through the admitted publishing transport; do not give the agent an independent public collaboration-write capability. | The actual tool/credential surface prevents alternate writes; a written instruction alone is insufficient. |
| Human content | Retain GitHub's human submission interface and detect changes through a bounded private read-only monitoring path. | Complete declared event coverage, actual owner notification and private remediation record, with known latency and explicit exclusions. |

### Native reviewer boundary

The currently used native review-request endpoint accepts reviewer identities,
not the future review body and inline comments. Adding a check before that
request cannot validate the later result. Inspecting the review after GitHub
publishes it also does not meet the strict requirement.

A new provider/proof route therefore needs an explicit governing decision and
independent source admission. The existing native verifier must not be fooled
with another App's review, fabricated service evidence or a renamed successful
check. Preserve all consumed requests and historical outcomes. This proposal
authorizes no new inference, funding, retry, environment approval, source
selection or removal of a required reviewer. Until the mediated replacement is
admitted, this path is unsupported by the strict guard and #556 remains open.

### Dependency automation boundary

The present hosted dashboard is generated and edited by its service. Repository
configuration and a post-edit observer are not final-payload interception.
An owner-controlled replacement must preserve dependency discovery, existing
required checks, protected branch updates and the operational dashboard.

Separate the worker's permitted source/branch operations from collaboration
publication rights. For example, a branch-writing identity must not also permit
direct issue/PR/comment writes; a separate publisher owns only the needed
collaboration mutations. The real integration must demonstrate this separation
against the actual service API and token permissions, including alternate Git,
REST and GraphQL routes. Do not assume that a configurable API endpoint alone
establishes an unbypassable guard.

The existing dashboard stays open during preparation. Switching service
ownership, disabling the hosted writer or provisioning new persistent access
requires its own exact, reviewed operating change. No such change is applied by
this proposal.

## Inventory, monitoring and private handling

Enumerate installed live publishers and their defining protected revisions;
canonical template presence is not an installed-path inventory. Include active
legacy consumers, hosted applications, scheduled jobs, dispatch paths, review
comments and metadata edits. Authenticate the complete repository inventory and
visibility independently of a contributor. A selected-repository token cannot
assert that it sees the complete organization.

Provision a read-only monitor identity and a private finding/notification sink
under the named existing remediation owner. Neither raw matched values nor
private repository identities may appear in public jobs or public remediation
comments. Keep inventory and content reads separate from that notification
effect. Failure to read a page, classify visibility, reach the sink or notify the
owner is a recorded failed control, never a clean result.

The initial live receipt covered only explicitly selected open issue
titles/bodies and current issue comments. The local optional broader path also
reads open PRs, conversation comments, submitted/dismissed reviews and inline
comments with repeated snapshot checks. Its presence does not establish actual
monitoring deployment, timely edit-event detection or owner notification.
Qualify each of those controls separately. Declare closed content, pending
review drafts, histories, attachments and caches individually. History metadata
observation never authorizes revision deletion.

## Delivery order and proof

1. Finish the independently owned organization-identity admission prerequisite.
   Do not combine or bypass that recovery with this publisher redesign.
2. Complete and review the deployed-path inventory and the proposed provider,
   worker, publisher, inventory and monitoring identities/permissions. Keep
   private operational evidence in the existing private record.
3. Version the policy and final-payload contract, test every supported content
   kind and its create/edit forms, and bind consumers to the accepted source.
4. Qualify each controlled publisher with an allowed public payload, a rejected
   private/secret-like payload, malformed nested comments, changed final bytes,
   incomplete inventory, API failure and an uncertain-effect case. Prove that
   alternate direct-write capabilities are denied by actual permissions.
5. Independently qualify the new native-review proof route and dependency
   service transition. Their preparations do not admit themselves and do not
   authorize buying an additional review of an already consumed input.
6. Qualify private monitoring/notification with actual human create/edit events
   and each declared content surface. Record timing, owner receipt and failures.
7. Perform direct live readback across the final declared public scope, remediate
   confirmed current-content findings safely, and observe the resulting exact
   revisions. Obtain separate exact authorization for any destructive history
   action; the detector never performs one.
8. Close #556 only after every actual acceptance criterion is met and the
   independently reviewed evidence is retained. A local passing suite, source
   merge or successful monitor run alone does not satisfy that boundary.
