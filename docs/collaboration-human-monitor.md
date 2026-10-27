# Bounded human-content monitoring and declared current-scope readback

This inactive component reuses `collaboration_inventory.py`; it does not install
an observer, credentials, private notifications, a scheduler or a new source.
The existing open-only observer remains its default. Its explicit `state="all"`
mode additionally reads current closed issue/PR content and comments. Human
edits to a closed item are therefore not silently excluded from that mode.

`collaboration_monitor.monitor_current` obtains a complete authoritative
visibility inventory, selects all public active repositories or an explicit
limited list, performs two complete current-surface observations and compares
their object signatures. It then obtains another complete authoritative inventory
and requires unchanged repository visibility and identity. Each content scan
retains the existing per-object and pagination drift checks. All origins are
covered; no author label is used to silently skip content as automation.

The trusted GET-only reader is bounded to at most 5,000 requests and 600 seconds,
including a time check after each request. A request cannot be declared timely
merely because it started before the limit. The actual read client also needs a
finite per-request timeout. A short page requires its terminal empty page.
Malformed metadata, API/visibility/pagination failures, bounds or detected drift
return a fixed `monitor-incomplete` with `current_surface_clean: null`; partial
findings and exception text are not returned as a clean observation. Protected
source text remains in memory; receipts contain categories, hashes, counts,
opaque object/repository IDs and validated timestamps, not matched values.

A successful `declared-current-scope-clean` concerns only the named current
surface during that read window. Pending private review drafts, edit history,
attachments, releases, timeline, repository files, caches and other declared
exclusions are not silently covered. Post-read edits and a cross-object
non-atomic window remain explicit. `notification_delivery_proven` stays false:
a clean readback is not proof that a private owner message was delivered.

The separately prepared private Management entry consumes this result, retains
its bounded private record, reads the actual existing remediation recipient and
prepares a separate exact notification intent. Its Main workflow must use a
read-only GitHub job and separate narrowly scoped Jira read/notification
credentials. No public issue/comment, GitHub mutation, visibility change or
history deletion is provided. Its actual protected integration, complete reader
custody, named private owner, private classification, queue/delivery evidence,
invocation cadence and failure escalation remain operational acceptance items.

A workflow-dispatch candidate is a qualification entry, not a continuously
bounded monitor. Record the real invoking mechanism, maximum invocation gap and
actual measured create/edit detection times before claiming bounded monitoring
in operation. Do not create an unrequested timer or a new service to fill that
fact by assertion. Unknown notification outcomes require original native
intent/result inspection, never automatic resend or new-run reset.
