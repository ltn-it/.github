# Preparing the publisher's actual App credential

`collaboration_app_credential.AppTokenPreparer` implements the credential stage
for the narrow Root `review.create` pilot. Its key supplier and independently
admitted App/installation/actor identity are private broker construction inputs.
There is no CLI, environment key lookup, installed credential, App creation or
permission change. Tests generate an offline RSA key; no live token was minted.

## Ordering and identity

1. Authenticate the frozen authorization through `NativeReviewIssuer.attest`.
2. Under the same repository-wide private lock, durably claim a separate
   credential-preparation operation derived from the stable publication ID.
3. Sign a short-lived App JWT with the private key supplied by the real broker's
   key role. Authenticate `/app`, the exact installation and its organization,
   and the numeric Bot actor resolved from that actual App's slug. Missing
   suspension state is unknown, rather than evidence of an active installation.
4. Revalidate the exact native authorization after those reads and before mint.
5. Make exactly one installation-token request, explicitly restricting
   `repository_ids` to Root ID 1112629689 and permissions to
   `pull_requests:write`. There is no default/all-repositories request.
6. Reject returned extra permissions, expired or overlong validity, or a token
   whose authenticated installation-repository list contains any other target.
7. Pass the memory-only prepared getter to `HTTPSOnceSender`. Run the ordinary
   publisher checks, durable publication claim and last native attestation
   **after** all credential-stage network calls and before publication.

Token narrowing and the one-hour lifetime are described in
[GitHub's App token reference](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app).
Returned permissions may include implicit metadata read; no other extra grant
is accepted. Both legacy and stateless JWT-shaped installation tokens are
supported without allowing whitespace, CRLF or unbounded header values.

The key supplier, HTTP implementation, expected identity, native attestor and
ledger cannot be supplied by a remote producer. The actual HTTP implementation
uses fixed GitHub TLS and bounded JSON responses, with neither redirects nor
HTTP retries. It has no arbitrary URL, GraphQL, deletion or broad-mint route.
Safe receipts contain identity, operation, scope and expiry metadata, never
the private key, App JWT, installation token, raw headers or response bodies.

## Failure and remaining boundaries

A failed preflight, ambiguous mint response, scope mismatch or crash consumes
the credential-preparation slot. The code neither refreshes a token nor resets
the slot; a different payload or JWT cannot create another publication ID.
An expired prepared getter fails locally without network I/O. The publication
ledger independently consumes the eventual write. Generation drift after token
preparation still blocks the final publication. No token preparation can replace
the actual source, native review, budget or release requirements.

This prepares a narrowly scoped **token**, not endpoint-specific GitHub App
permissions. `pull_requests:write` can authorize operations broader than this
publisher's routes. The private broker/key process and OS/network boundary must
therefore prevent alternate token/key access and raw REST, CLI, GraphQL or tool
writes. An App's other installations and legacy key holders are not constrained
by this module. Neither a token response nor an Actions default-permission
setting proves that all direct writers have been removed.

The nine-App/25-public-repository metadata inventory, including Root's four
collaboration-write App grants, remains a separate bounded observation. Complete
PAT/OAuth/tool and per-run credential coverage, real broker deployment and key
custody, native source admission, private request/effect custody, readback and
all hosted/Renovate/interactive producer integrations remain required. Existing
App metadata does not authorize repurposing its key or changing its permissions.

The combined offline tests execute actual RSA App-JWT signing, GitHub JSON/TLS
request code, installation/actor/scope checks and both durable ledgers. The
native OIDC/artifact/budget reader runs before preparation and again after it;
the last native generation read immediately precedes the fixed HTTPS effect.
A new generation during credential preparation, foreign actor, extra token
permission, foreign repository, missing suspension state, timeout or expiry
fails closed. The socket boundary is replaced in these tests; this is not a
live credential, least-privilege deployment or #556 completion claim.
