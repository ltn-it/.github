# Fixed Root ancestry 986: code and admission plan

Status: local code qualification only. No source admission, rule mutation,
Main PR, native approval, inference, retry, or production acceptance is granted
by this document or its captured fixtures.

## Actual defect

Root Main `c353913fc261e193b60876219820e9714b0122b9` was normally accepted by
Release App PR 985 from Develop `000ed477a7af21e0accec549531966f095523bc2`,
with native Required Workflow `40885286707/1`, Source
`015233f4dfe0f95a6df0ea8a9e4ef8150dadc19f`, all four native jobs successful,
and a genuine normal Main approval. Its original `control-proof-1` artifact
`12903126597` binds integration tree
`0e3abaf9c461bdbe01bd3be383058038d0f711b1`.

Human PR 986 merged that exact Main into Develop as
`1d19405fefd66e5f1b007bddcd1920e3a1287866`, parents
`[000ed477a7af21e0accec549531966f095523bc2, c353913fc261e193b60876219820e9714b0122b9]`.
Its tree is byte-identical to the already accepted Main tree. Its sole native
Required run `40895680515/1` failed after the PR was merged, with only
`pull-not-reviewable` in both failed gates. It has an original operation
artifact but no completion proof and no earlier successful attempt.

The actual Root Main preparer `41020724785/1` therefore correctly stops at
`ingress-protected-run-not-successful`. Ordinary first-parent traversal still
visits 986 before genuinely accepted code ingress 987. An extra NoOp PR, a
rerun, a new review of 987, or renaming the failure cannot repair that record.

## New narrowly typed reader

`workflow_root_ancestry.py` admits only Root repository ID `1112629689`, PR 986,
the exact two-parent merge above, and current Main equal to the fixed accepted
Main. It authenticates the actual protected branch and Git refs, the original
985 PR/commit/run/jobs/proof/normal approval, exact proof digest, the actual
986 operation and failed generation, both post-merge closed-subject errors,
and final unchanged native reads. Another repository, tree, parent, approval,
artifact, source, generation, or semantic failure still denies admission.

The resulting `protected-main-ancestry-baseline/v1` is a new disposition of
already accepted Main bytes. Its history explicitly retains run 986 as
`failure`, its budget as `unchanged`, and both funding and source-admission
grants as false. It does not manufacture a successful check or an old proof.
The Main ingress loop uses it only for this one merge. Every genuine code
ingress, including 987 and this repair's eventual PR, still uses the complete
ordinary current native reader. A cumulative Main promotion still requires a
real reviewed code change, all product/security checks, and the normal native
Main approval.

Fixtures are field projections of the original public GitHub API/artifacts,
with original capture digests. They are inert test data. Production must fetch
the genuine native records; a fixture cannot replace an unavailable artifact.
The tests reproduce the unchanged reader's actual 986 failure, verify this
strict baseline, and verify that actual 987 still passes its ordinary native
reader. Negative cases cover identity/ref/tree/parent/approval/proof changes,
semantic or pre-merge errors, and a later generation during the final reads.

## Existing 015 cannot consume this proof

There is a real bootstrap cycle. The installed 015 Main reader has no consumer
for this new disposition. Its historical attempt path requires a real earlier
successful attempt, which 986 never had. The typed Devtools first-Main context
is restricted to Devtools. The old initial Root admission is tied to its
historical source and must not be revived. Namespace recovery is unrelated
and remains retired. Selecting another already published source without this
reader would retain the same first-parent failure.

Simply merging this code into Develop does not activate it. The normal
`validate_source` rule requires an admitted source on protected Main, while
Main is precisely what the current reader blocks. A new, separately reviewed,
Root-only migration is consequently required.

## Smallest proposed migration, still requiring separate code qualification

1. Normally qualify this real repair unit under current Source 015 into
   protected Develop. Let `S` be the resulting immutable Develop merge/source
   commit. Authenticate its actual PR, code checks and current native review;
   bind its tree to the reviewed head. Review 987 remains completed with four
   consumed reviews. This unit has its own genuine scope and review allocation.

2. Publish a dedicated bounded admission consumer normally through Management
   Develop/Main. It must not execute candidate Source code or reuse a retired
   controller. Reuse the existing serialized native management administration
   boundary and credentials. Two explicit operation choices can use existing
   source/develop/plan/qualification-run inputs; no new workflow input, generic
   issuer, repository target, model privilege, or credential namespace is needed.
   The consumer independently authenticates the fixed 985/986 facts, current
   `S`, every real code ingress under 015, exact unchanged Root protections,
   and saved plan bindings before each effect.

3. Under a concrete saved preparation plan, update only the defining source of
   existing Evaluate rule `25138461` to `S`, preserving its entire scope and
   all other fields. Keep Active Main rule `25154946` on 015 unchanged. The
   trusted Management consumer may then prepare exactly one ordinary Release
   App Develop-to-Main PR at `S`, initially Draft, using the existing App restricted to Root,
   contents read and PR write. Its preflight uses the separately reviewed
   trusted admission reader; the unchanged 015 preparer cannot create it.
   One attempt per effect, fresh before-state checks and readback are mandatory.

4. The Evaluate workflow at `S` must first actually reject that Draft before any
   effect. One genuine Ready transition then qualifies the same immutable
   request; an unchanged-request replay must create no model allocation.
   It must actually authenticate the complete current
   Main integration: fixed baseline 986, every ordinary code ingress, actual
   integration tree, product/security checks and one genuine existing normal
   Main approval. Promotion must make zero model requests. An Evaluate pass
   alone grants no active source selection or merge authority. A failed 015
   result remains failed in history.

5. Only a second concrete saved native activation plan may replace the source
   SHA in existing **Active** Main rule `25154946`, from 015 to `S`. Authenticate
   the actual successful `S` Evaluate run/attempt, immutable source/job origin,
   exact Main PR/base/head, original approved plan, genuine normal approval,
   full unchanged protections, and all native evidence before the single PUT.
   Enforcement must remain active, repository scope must remain only
   `1112629689`/Main, and bypasses must remain empty throughout. No rule is
   deleted or disabled; no other repository or collection source changes.
   This is an explicit narrowly qualified exception to pre-merge Main source
   placement, not a generic permission to activate any Develop candidate.

6. Read back effective protection and finish the ordinary protected Main merge.
   The immutable source `S` is then an ancestor of protected Main, restoring
   the ordinary source-placement invariant. Complete the normal App ancestry
   backsync and final no-content-change observation. Once Main moves, the fixed
   986 baseline cannot apply to another Main base. Unknown effects stop and are
   observed; no automatic retries, funding resets or invented acceptance.

The Management consumer and its immutable source/operation hashes do not yet
exist in this unit. Steps 2–6 are proposed interfaces, not implemented or
authorized effects. They require independent architecture/code review and the
actual saved bounded plans before any operational decision. If original
native evidence becomes unavailable or the fixed boundary changes, stop and
re-plan; never replace it with the fixture.
