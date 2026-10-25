# Private publication request custody and exact known-effect readback

This offline component extends the local publisher composition at
`c7e558c4750e5eb2e504130a0846e2b506de92ef`. It changes no existing ledger,
transport, issuer, provider adapter, workflow, rights or source binding. It does
not install a private sink, admit a publisher, prove a native budget, or complete
issue #556. Production private deployment and real independent evidence remain
separate acceptance requirements.

## Inputs and genuine authentication

The API accepts the existing immutable `Authorization`/`Facts` types and the
**actual canonical wire bytes** already bound to `payload_sha256`, not a newly
rendered copy. `NativeProof` binds:

- repository ID, origin producer ID and source commit, separate publisher actor;
- exact head and generation, actual native run ID, attempt and job ID;
- SHA-256 of the entire canonical authorization descriptor and SHA-256 of the
  actual private native evidence;
- an authenticated before-field hash map for edits; and
- the optional private model response hash, only when that response is supplied.

`verify_native(auth, proof)` is required independent trusted read-only issuer
integration. It must authenticate these facts against actual native evidence,
including the origin/object assignment and immutable source. A contributor
cannot supply it, assert `authenticated=true`, or turn a hash into evidence.
This module does not accept a token, OIDC JWT, authentication headers or client
secret. It never creates a new request budget or invokes a provider.

The optional private provider response must be bounded JSON model-result bytes
(up to 1 MiB), hash-bound in the native descriptor. It is not an HTTP response
with headers or an authentication envelope. Credential/header-shaped fields and
recognized authentication-value forms are rejected without echoing them. This
check is not a general secret detector; the provider boundary must ensure that
real authentication material never reaches this API. Final request bytes are
bounded to 256 KiB and must satisfy the existing publisher's strict schemas.
This is custody of previously admitted bytes, not a substitute content policy.

## Private write once and crash behavior

Use a pre-created, caller-owned directory with mode **0700**, outside repository
sources, public artifacts and public runner uploads. The leaf may not be a
symlink. All descendants are accessed relative to held directory descriptors;
operation names are exact SHA-256 IDs, not user paths. The deployment must deny
contributor and alternate-writer access to this directory and its owner account.
Filesystem modes do not isolate other processes running as that same owner.

```python
custody = PrivateEvidence(private_directory, independently_authenticated_verifier)
receipt = custody.write_once(authorization, actual_canonical_wire,
                             authentic_native_proof, optional_private_model_json)
```

The original run/job/source binding and payload bytes are frozen, authenticated
and stored together. The procedure is:

1. Create a new 0700 operation directory exclusively; fsync its parent. That
   operation ID is consumed even if any later write fails.
2. Create `request.json` using O_EXCL/O_NOFOLLOW and mode0600. Store the exact
   request bytes as base64, canonical authorization, native descriptor and
   optional private model bytes. Handle short filesystem writes, then fsync
   the file and operation directory.
3. Exclusively create mode0600 `complete.json` binding the operation and full
   request-file hash. Fsync the marker and directories before returning.

There is no overwrite, repair/resume, deletion, retention cleanup or retry API.
Any failure returns only a fixed safe error category. Never publish after an
ambiguous/failed custody write. Repeating the same operation fails rather than
allocating a fresh directory. A crash or failed sync leaves the ID consumed;
partial files and missing/corrupt completion markers cannot be read as complete.
A complete retained record may later be observed by reads, but such observation
never permits retransmission or a new publication. Custody is separate from
and does not reset the publisher's durable operation ledger.

The result exposes only operation/payload/custody hashes and a fixed disposition.
Raw provider output, final content, rejected values and filesystem error paths
are not diagnostics. No private request file may be uploaded as a public proof.

## Exact authenticated known-response readback

```python
result = custody.exact_readback(
    authorization, independently_confirmed_known_response,
    verify_response=actual_transport_receipt_verifier,
    reader=trusted_get_only_github_reader,
)
```

The default reader is the existing `collaboration_inventory.GitHubReadOnly`,
which uses only GitHub GETs. Tests replace its GET transport with recorded
objects; they do not call GitHub. All read paths are constructed from fixed Root
repository identity and authenticated positive numeric locators. There is no
search, state mutation, publication client or arbitrary caller-composed URL.

`KnownResponse` binds operation ID, payload hash, repository ID, separate origin
ID/source and publisher actor, generation, exact object ID, actual issue/PR
number (or authenticated parent number), and the original private response
provenance hash. `verify_response` must authenticate the **actual original
transport response**, not a caller assertion or content coincidence. For issue
and PR creation, the actual returned number is necessary: a numeric database
object ID is not a REST issue-number lookup. Missing provenance/number remains
unknown. The present sender's ID-only result is not extended or falsely labeled
sufficient here; its real private custody integration remains with the owner.

An unknown CREATE result, even if equal text can be found somewhere, stays
`unknown-readback-required`. No object search or guessed ID is attempted. The
component never retransmits, resets a consumed operation or mints a new ID.

For a genuine known response, readback checks:

- exact API object ID and parent URL/number in fixed Root;
- actual publishing actor, not the model worker's identity;
- actual PR head plus both Root repository identities;
- exact title/body, inline path/line/side/range/commit and reply association;
- for reviews, COMMENTED state and the complete exact inline-comment multiset,
  each actor/review/parent/head binding and terminal pagination;
- for edits, original authenticated origin/object custody and all unchanged
  field hashes, not merely the fields requested for replacement.

The object and parent/content are read twice. Drift, missing visibility,
unavailable API, incomplete pagination or a final failed native authentication
returns only `unknown-readback-required`. A successful result is
`exact-known-effect-read-back` with safe hashes and the confirmed object ID.
It confirms the bounded current known effect, not an atomic GitHub snapshot,
normal Main approval, review quality, source admission or release eligibility.
Later edits and races after the last GET remain possible.

## Before-field hash convention for edits

The independently authenticated origin/object record must supply these
pre-write hashes. Hash each value using `digest(json_bytes(value))`, then bind
`Facts.object_revision = digest(json_bytes(before_fields))`. This is a specific
contract the real edit issuer must adopt; a differently defined opaque digest
cannot be silently treated as equivalent.

| Operation | Required before-fields |
| --- | --- |
| issue.edit / pull.edit | title, body |
| comment.edit | body |
| inline.edit | body, path, line, side, start_line, start_side, commit_id, in_reply_to_id, pull_request_review_id |
| review.edit | body, comments |

Absent inline range/reply fields project to null. Review comments project to
body/path/line/side and optional start_line/start_side, sorted by canonical JSON
bytes. Their actual object/actor/review/parent/commit associations are checked
separately. `owner_id` must match publisher; original origin ID/source and
receipt must match the current origin. Missing or foreign assignment fails.
Create operations require an empty before-map and no edit-origin fields.

## Qualification and remaining integration work

Regression tests cover every existing create/edit/reply operation, real-reader
GET dispatch with offline fixtures, exact nested review content, read drift,
unknown CREATE, actor/origin/head/parent mismatches, preserved edit fields,
provider binding, prohibited auth inputs, exclusive writes, short writes, every
sync failure, partial files, restart, mode enforcement, corruption, symlinks and
hardlinks. The complete pinned repository profile is required on the final
component revision; passing local tests is not deployed private custody.

The overall integrator owns actual issuer/transport-response provenance, the
private production filesystem and credential isolation, native budget/source
admission, real provider capture, safe private receipt access, egress and all
managed-producer integration. No live GET, provider, credential, publication,
ref, Ready, review or merge effect is part of these local component tests.
