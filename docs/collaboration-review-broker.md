# Composed review broker pilot

`collaboration_review_broker.ReviewBroker` connects the implemented issuer,
private request custody, App credential preparation, final-byte publisher,
original-response custody and exact readback. It is a library with no daemon,
workflow activation, installed identity or live grant. The active R4 source
has no publisher registry, so the real registration reader rejects operation.
An ordinary protected development review remains governed by its existing
contract; this future operating protocol adds no general development freeze.

## Request and trusted construction

The request consists of a GitHub OIDC token, PR number, already frozen canonical
review bytes, source policy and complete fresh inventory. The producer uses the
existing bounded gateway's protected result and `collaboration_review_result`
before requesting the operation-bound audience. The broker authenticates that
job and its actual native capture; it does not call or impersonate a provider.

The broker's constructor fixes the real authenticated read-only GitHub client,
private state directory, admitted App/installation/actor, private key supplier,
trusted clock and GitHub OIDC key reader. A remote caller cannot supply those
objects, an attestor, sender, admission map or response verifier. Private state
must already have the actual broker's ownership and mode0700. No key/token is
read from the environment or written to the request/response journals.

## Actual implementation sequence

1. Verify the signed job identity, immutable active-source registration and
   policy, full inventory, actual Required run/attempt/job, native operation
   artifact, already-consumed provider budget and successful protected capture.
2. Check the canonical schema and every final string before any key access or
   credential mint. A rejected private body creates no custody or mint request.
3. Derive `NativeProof` from a fresh authenticated issuer read, rather than a
   producer descriptor. Persist its exact authorization and final wire through
   `PrivateEvidence.write_once`. The verifier re-derives the actual native
   frame, including Source/Origin/Publisher and run/attempt/job bindings.
4. Durably reserve and prepare the actual Root-only App credential. The App,
   organization installation, Bot actor, returned permissions and authenticated
   token repository list are verified. No implicit all-repositories token is
   requested. Credential network I/O finishes before publication attestation.
5. Interpret the admission map only from that independently authenticated
   source registration. The publisher validates final bytes again, checks the
   real issuer, commits its separate durable one-write claim, then repeats its
   policy/inventory and native-generation checks immediately before transport.
6. Create a private original-response intent directory before the one HTTPS
   request. A valid original 200/201 numeric object response is hash-bound to
   the complete authorization, written0600 with exclusive creation, and fsynced
   with a completion marker and its parent directories before further use.
7. Load a `KnownResponse` only from that original private HTTP record. Verify
   it against the private record, then read the real review, parent/head/actor
   and complete inline objects twice. The native proof is revalidated last.

The success disposition is `exact-known-effect-read-back`; it confirms one
operation's content and provenance, not a successful AI review, Source admission,
Main merge, release or completed issue. The runtime does not search public text
to infer an object ID. A timeout or missing/incomplete original response record
stays `unknown-readback-required` and is never resent. A failure before the
collaboration request is `blocked-before-publication`; credential preparation
may have consumed its own separate mint slot and must not be retried either.

The broker retains no raw OIDC token, App JWT, private key, installation token
or HTTP authentication headers in either journal. This pilot's private evidence
has `before_fields={}` and no optional model-response body; only `review.create`
is admitted. It does not invent old edit ownership or authenticate an unknown
historical response. Raw provider custody, future edit issuers and historical
read-only reconciliation require their actual separate integration.

## Concrete operating work still required

- Supply and protect a real private broker execution/custody environment,
  persistent storage and narrow key role; the Python library itself creates no
  OS/process/network boundary and no deployed retention guarantee.
- Admit the actual reviewed source, registry identities and actually observed
  OIDC job claims through the existing protected management path. The installed
  native source, old review contract and consumed requests remain authoritative.
- Connect the immutable producer's protected result to this request protocol.
  The current workflow has no broker call or corresponding OIDC permission.
  Do not expose raw model results through public logs/artifacts while adding it.
- Remove or isolate actual alternate write capabilities. A job's declared
  default read permission and a per-token scope response are not evidence that
  broad App keys, Actions credentials or interactive tools cannot bypass it.
- Integrate hosted Copilot, automatic Security with equivalent real coverage,
  Renovate and the remaining managed App/human routes. This one controlled-job
  pilot does not mediate them or change their current ON settings.
- Complete private protected-value and credential inventories, monitor/owner
  notifications, live canary positive/negative effects and the current clean
  declared-scope content readback before closing #556.

The tests execute the full RSA OIDC/native-artifact/budget → private custody →
RSA App JWT/narrow-token → last native guard → exact HTTPS bytes → original
response journal → two-read/final-native-proof chain with recorded socket edges.
They verify no second effect after timeout, disk failure or content drift; a new
native generation after token preparation blocks publication. Token/key bytes
are absent from the actual test journals. These are local integration results,
with no live mint, provider request, GitHub publication or operating admission.
