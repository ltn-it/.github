# Final-byte publisher transport component

This is an offline component for issue #556, based on source revision
`57cb3eeaed4a9649bd5d3128eb9873b102ae7a34`. No caller, workflow, producer,
credential, provider, source admission or installed permission is changed.
It is not complete enforcement or acceptance of the issue.

## Operations

Every route is rooted at `https://api.github.com/repos/ltn-it/.github/` and
repository ID `1112629689`. No URL, HTTP method or headers come from a producer.

| Operation | Method | Relative endpoint | Final fields |
| --- | --- | --- | --- |
| issue.create | POST | issues | title, body |
| issue.edit | PATCH | issues/{number} | title and/or body |
| pull.create | POST | pulls | title, body, head, base, draft |
| pull.edit | PATCH | pulls/{number} | title and/or body |
| comment.create | POST | issues/{number}/comments | body; issue or PR parent |
| comment.edit | PATCH | issues/comments/{id} | body |
| inline.create | POST | pulls/{number}/comments | body, commit_id, path, line, side; optional start_line/start_side |
| inline.reply | POST | pulls/{number}/comments/{id}/replies | body |
| inline.edit | PATCH | pulls/comments/{id} | body |
| review.create | POST | pulls/{number}/reviews | body, commit_id, event=COMMENT; optional comments array |
| review.edit | PUT | pulls/{number}/reviews/{id} | body |

Nested review comments require body, path, line and side, with an optional
same-side start range. All strings, including paths and branches, are content
validated. Unknown fields, legacy positioning variants, file-only comments,
approvals, changes-requested reviews, pending drafts, state transitions,
review dismissal, deletion, Ready, merge and GraphQL are not admitted. Empty
strings can clear bodies. This deliberately bounded request schema is not an
allowlist of every optional GitHub API feature. Issue/PR numbers and child
object IDs are positive integers, never booleans or caller-composed routes.

The route shapes were checked against GitHub's documentation for
[reviews](https://docs.github.com/en/rest/pulls/reviews),
[inline comments and replies](https://docs.github.com/en/rest/pulls/comments),
and [conversation comments](https://docs.github.com/en/rest/issues/comments).

## Trusted inputs and integration example

`Authorization` fixes the operation ID, operation, parent kind, number/object
locator, canonical final payload hash, policy hash and complete inventory hash.
Its immutable `Facts` fixes repository name/ID/visibility, independently admitted
origin producer numeric ID/source commit, separate actual publisher actor ID,
exact head, native generation digest,
and (for edits) existing object owner, revision digest, original origin ID/source
and authenticated origin/object assignment receipt hash. The independent
issuer must bind **all** these values to the actual authorized operation and
budget. These dataclasses are not signed admission or an authentication protocol.
A producer must never issue its own authorization or facts.

The trusted attestor accepts only that operation descriptor, not content or a
publishing credential. It must authenticate the current repository, producer,
source, actual publisher actor, parent and child associations, edit ownership/revision,
original origin/object assignment evidence, head and
native generation. It must obtain complete visibility through the authoritative
inventory adapter; a partial selected installation is insufficient. It must
check branch resolution for PR creation and actual native run/attempt/job
bindings rather than trust a contributor's generation string.

Origin producers do not receive GitHub write credentials. The independent
admission map has `(origin_producer_id, publisher_actor_id)` keys and immutable
origin source values; a single broker actor can publish for several separately
admitted origins. The sender is independently fixed to its actual authenticated
GitHub actor, and a mismatched actor fails before reservation or transport.
For edits, `owner_id` must equal that publisher actor, while the independently
retrieved original origin ID/source must match the current origin and a real
private assignment-receipt hash is mandatory. Broker ownership alone never
permits one origin to edit another origin's content. Missing assignments and
origin/source migrations require separate authenticated admission; they are not
inferred from user text, the broker's object owner, or matching content. The
attestor must verify the receipt, not merely trust a supplied hash string.

The interface to integrate is:

```python
ledger = PrivateLedger(private_owned_directory)
publisher = Publisher(
    admitted_bindings=independently_accepted_origin_publisher_source_map,
    attest=authenticated_operation_reader,
    ledger=ledger,
    serialize=ledger.serialize,
    transport=BoundedTransport(credential_isolated_once_sender,
                               publisher_actor_id=authenticated_github_actor_id),
)
receipt = publisher.publish(authorization, canonical_final_utf8_bytes,
                            authoritative_inventory, accepted_policy)
```

The example's named dependencies are integration requirements, not installed
identities or authority invented by this component. The model/result adapter
must finish rendering first, canonicalize with `json_bytes`, then obtain the
independent authorization for that exact hash. There is no re-rendering step
after admission. The existing `collaboration_content.guarded_payload` validates
every string without receiving the transport or credential; its serialized
bytes must equal the submitted immutable bytes exactly. Policy and inventory
are hash-bound and rechecked after evidence reads. Inventory freshness and all
text are validated again before the last native generation/ownership read.
The transport repeats the byte-hash and endpoint checks at its send boundary.

## One effect, durable consumption, safe outcomes

`PrivateLedger` stores operation-ID/fingerprint hashes in an owned private
SQLite database with synchronous durable commits and a cross-process file lock.
Every target publisher instance must use the **same** database and lock.
The reservation is committed before transport; a later failed generation check,
transport failure, timeout, ambiguous response or crash consumes it permanently.
No retry, reset, release, delete or replacement operation-ID generation exists
here. The issuer must not allocate a new ID to retry an unknown operation.
A new legitimate edit is a new independently admitted operation, never a retry.

The credential-bearing sender is invoked once with method, fixed URL and those
same bytes. It must disable HTTP-library retries and redirects, enforce GitHub
TLS egress, use bounded responses and keep authentication and provider bodies
private. `TransportResult` contains only status and numeric object ID. A 200/201
response produces `response-observed`, **not** independently confirmed GitHub
acceptance. Any other/malformed response or exception produces
`unknown-readback-required`. No provider exception or rejected value is logged.

`reconcile` accepts only a trusted read-only observer. It can emit
`effect-reconstructed` only for one exact, complete operation-bound result.
The observer must use retained private request evidence and authenticated
GitHub reads, binding target, producer, subject and byte hash. Matching equal
text alone is not proof of which attempt wrote it. An absent, partial or
ambiguous result stays unknown. Reconstruction never invokes the sender and
never frees a reservation. Normal confirmed writes also require authoritative
readback during real integration.

`collaboration_https.HTTPSOnceSender` implements the concrete HTTPS part behind
`BoundedTransport`. It opens one standard verified TLS connection to the fixed
GitHub host, preserves the supplied request bytes, admits only the declared
Root method/path pairs, and follows neither redirects nor HTTP retries.
Requests are bounded at 256 KiB; responses at 1 MiB. Non-success, malformed or
duplicate response fields, invalid IDs and connection/read failures yield only
an unknown result. No raw exception, token or response body is returned. The
credential callback is private trusted broker code; it is never sent to the
validator or selected by a producer. No environment token lookup, proxy,
caller-selected CA or alternate URL is supported.
The header-safe bounded token syntax supports both legacy and stateless
installation tokens, including JWT dots and base64url characters; it does not
assume a 40-character or underscore-only token. GitHub documents the 2026
stateless-token rollout in its
[App token endpoint reference](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app).

This adapter is not a running credential boundary. Its offline tests replace
the connection at the socket boundary and exercise the actual sender through
`BoundedTransport`; they do not contact GitHub or prove installation identity,
permissions, broker process separation, network confinement or a live effect.
Deployment must still bind the real credential to the independently admitted
publisher actor and deny alternate credential access and outbound writes.

## Required boundaries outside this component

- Independently admitted issuer, signed/otherwise authenticated authorization,
  actual producer/source maps, native evidence and budget authority.
- Credential-free validator process and credential-isolated sender process with
  fixed egress and denied alternate REST, GraphQL, CLI and tool writes. Python
  private attributes/classes in one process do not create this boundary.
- Authoritative complete fresh inventory and a qualified private protected-value
  corpus. The existing public empty supplemental hash list is not that corpus.
- Real private request/receipt custody and a read-only exact-effect observer.
  Neither public artifacts nor raw responses are an acceptable private sink.
- Repository-wide serialization across all admitted publishers and technical
  denial of alternate writers. The supplied ledger coordinates only its users.
- GitHub provides no atomic compare-and-swap for these publication endpoints.
  External state can change after the final read and before the effect. This
  residual race is explicit; no atomic freshness guarantee is claimed.
- Every managed producer, including all hosted review families and Renovate,
  needs real integration and direct-write denial. New provider/proof/bootstrap
  decisions and existing consumed budgets remain separate from this component.
- Extension beyond this one public Root target, live canary acceptance, human
  monitoring/private notification, and issue #556's remaining acceptance items.

No provider call, scan, review, Ready transition, dispatch, push, merge or live
publication is part of offline qualification. The component has recorded
positive/negative transport tests, including every declared create/edit route,
nested findings, malformed fields, private titles/bodies/paths, foreign
identities, visibility/freshness failures, changed bytes, drift after reservation,
uncertain outcomes and durable restart behavior.
