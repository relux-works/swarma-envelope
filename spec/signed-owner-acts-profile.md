# Signed owner acts: consumer profile proposal

Status: **contract proposal with a bounded portable implementation subset;
no native or consumer activation**. Requirement words describe the profile and
its consumer obligations, not a claim about a deployed consumer. The
[platform contract](swarm-envelope-2.md), especially §§2, 4–7, remains normative
for existing records. Publishing this consumer mapping of `operator-act/1`
changes no signed body, domain, preimage, algorithm, record type, Go API or
refusal vocabulary.

At the original proposal baseline, the verifier recognized only Keymaker
`revoke` and illustrative `grant.issue`; owner-DM targets could fail its schema
before operation lookup. The current schema recognizes `owner-dm`, while
`VerifyOperator` still refuses these operations. The separate `VerifyOwnerAct`
route verifies prospective owner-acts/1 candidates with protected facts and a
genuine root-currency `/2` receipt: eligible unbind can return a candidate plan;
bind and mirror-enable remain closed widening. The current
[portable APIs](../verifier/README.md) and [owneracts package](../owneracts/README.md)
also provide bounded argument/body parsing and byte mapping, immutable signing
preparation, verified raw/DER assembly, public-point conversion and local frame
parsing/encoding. None performs a native key operation, reserves an action or
permits a consumer effect. Full native lifecycle, current-state acquisition,
consumer integration and the qualification gates below remain open. This is not
a claim that the full core or the future acceptance matrix is implemented.

## 1. Profile ownership, selection and assurance

Swarma Envelope owns the immutable static profile **`owner-acts/1`**: its operation
table, schemas, target kinds, classification and byte mapping. A future reviewed
implementation must select it from protected consumer configuration and a reviewed
source pin. The sender's operation or argument `profile` value cannot select a
policy module. The Signer independently pins the same profile. A semantic change
needs a new profile version and reviewed pin transition; unsupported, absent or
conflicting protected configuration fails closed. Dynamic registration, caller
callbacks, operation aliases, mutable classification and automatic fallback are
excluded. Consumer policy may further restrict operations or require additional
checks; it cannot weaken a profile floor or reclassify widening as narrowing.

The operator root and root-attested P-256 device retain their existing distinct
roles. Attestation establishes the signing profile, not action/target authority.
An MXID, successful signature, `confirmed`, room membership, account login or
caller `current=true` is not a source of authorization. Complete protected root
role separation remains mandatory before the existing signed-evidence intake.
No device attestation becomes carrier-account attestation.

The selected provider-contract targets are iOS Secure Enclave and macOS Secure
Enclave, with separate implementation and qualification reviews. iOS remains the
first A3 qualification target and its implementation is later work. macOS is not
qualified for A3. A separately enrolled second Secure Enclave device key is the
backup device, not a root-recovery authority. No software or 1Password signing
fallback is admitted. Raw P-256 low-S, the exact existing preimage and all
wrapper/algorithm refusals remain unchanged. This document qualifies no provider,
key custody, display, biometric path, IPC, deployment or enrollment mechanism.

Shadow is the only pre-activation stage. It may record refusal or candidate-plan
observations under protected audit/disclosure policy, but MUST produce no effect,
reservation, binding change, pending activation, approval token or later reusable
authority. There is no transitional A0 hardening mode. A later stage-2 owner-DM
narrowing consumer may verify the full path under the same UID as the agent;
its claim protects an honest consumer against carrier forgery only. A compromised
agent can bypass it. Containment requires a separately protected consumer owning
all effects, credentials, policy, journals and entry points; it is not supplied
by this profile. Native activation and any widening remain closed.

## 2. Operation registry and effect scope

| Proposed exact operation | Exact typed target | Effect and class | Admission status |
| --- | --- | --- | --- |
| `owner-dm.bind` | `{kind:"owner-dm",id:identity}` | Create one pending, non-mirroring DM binding for this installation identity, inviting exactly the pinned recipient. Enables a new owner decision channel: **widening**, critical. | Portable mapping/verification only; otherwise-valid widening remains `act_a3_inactive`; critical coordinator and consumer gates also closed. |
| `owner-dm.unbind` | `{kind:"owner-dm",id:identity}` | Remove only the matching local active/pending binding; cancel its pending activation and future deliveries. No new room, recipient, replacement binding or delivery. **Narrowing**. | Pure candidate verification is implemented; full-path stage-2 consumer admission and effects remain later work. |
| `owner-dm.mirror-enable` | `{kind:"owner-dm",id:identity}` | Enable bounded mirroring to the exact current joined owner DM and its fixed audience. Adds a disclosure path: **widening**, critical. | Portable mapping/verification only, same closed widening/critical gates as bind. |
| `launch.approve` | Candidate `{kind:"launch",id:request_id}` | Approve exactly one immutable launch request, never a standing grant or arbitrary session input. **Widening**, critical. | **Reserved/inactive**; exact launch-handler and target contract missing (§10). |
| `host.change` | Candidate `{kind:"host-assignment",id:assignment_id}` | Candidate meaning: move one execution assignment from an exact previous host to an exact next host. Enables execution elsewhere: **widening**, critical, even if the previous placement is removed. | **Reserved/inactive**; exact assignment/host-change handler and target contract missing (§10). |

`owner-dm` is the profile's typed target-kind registration, now recognized by
the envelope schema; it is not an alias for registration or account.
Launch/host target kinds are proposals only; they
are not registered for admission by this draft. The proposed spelling of host
change does not claim that every consumer uses placement changes: the effect
owner must confirm that meaning or replace the proposal before registration.
Unknown operations, including reserved spellings not registered by an accepted
profile, MUST refuse `act_operation_unknown` once the earlier envelope gates
have passed. Earlier malformed target/schema failures keep precedence. There is
no wildcard, generic command, caller-chosen handler or default operation.
Keymaker's numeric registration target, `revoke`, `grant.issue`, their exact
argument bindings and existing refusals remain unchanged. Unbind MUST NOT be
aliased to `revoke`, and a target MUST NOT be relabelled to pass an existing API.
`VerifyEnvelope` is never act authority; no second parser/verifier is introduced.

Unbind removes local future authority/disclosure only. It cannot promise removal
of plaintext already disclosed, delete remote history, release consumed IDs,
withdraw device authority, change roots, stop unrelated sessions or repair an
unknown remote outcome. Any added effect needs its own reviewed classification.
Mirror disable and emergency cancellation are narrowing only if they solely
remove future local access; they are not new signed operation registrations here.

Mirror enable is a separate operation and does not follow from bind/unbind.
Its inclusion here defines that boundary; it does not authorize a mirror
implementation or activation. Bind always leaves
mirroring disabled. Join, an existing binding, a terminal mode change or an
unsigned owner message cannot enable it. Expanding recipients or re-enabling a
mirror after disable needs a new eligible signed widening act, not an old act.
This candidate grants no standing mirror consent: its retained authorization
cannot outlive the enabling act's original expiry. Every later disclosure still
needs fresh current authority/currency and the exact enrolled audience; an old
receipt, prior membership observation or stored enabled bit is insufficient.
A durable mirror-consent model beyond that window would need its own reviewed
contract/version, not an implicit extension of this act.

## 3. Protected installation, identity and authority state

Provision each consumer installation out of band with one unpredictable 128-bit
installation identifier, encoded as 32 lowercase hexadecimal digits; its exact
`aud` is `owner-acts:` followed by those digits. This namespace is proposed for
this profile, not a change to the general audience grammar. An identifier is
unique across installations, never reallocated or copied into a clone/restore
that can serve concurrently. A clone needs new provisioning and an independent
journal. The Signer's protected enrollment maps this exact audience to a human
recognizable installation; requester-supplied labels are not trusted mappings.

An owner-DM identity is a protected lowercase ASCII name matching
`[a-z0-9][a-z0-9-]{0,62}`. Names identify slots only within the installation.
`identity_generation` starts at 1, increases before a deleted name is reused,
and never resets on restore. `binding_revision` starts at 0 and advances once
for every committed binding-state transition. Both are safe JSON integers;
values before an increment are at most 9007199254740990. Overflow fences and
requires explicit reprovisioning; it cannot wrap. Retain tombstones/floors outside
the relevant restore domain. Generation and revision are different from the
semantic `epoch`, from authority-policy revision and from a carrier event ID.

The protected epoch is `epoch:` followed by 32 independently random lowercase
hexadecimal digits. Enrollment chooses it, not the request. A pin/ownership or
explicit continuity transition changes it, invalidates old pending candidates,
and preserves installation, replay, withdrawal and currency floors. Repinning
is not proof of old-identity recovery. Device loss, root loss, compromise and
planned transitions retain the platform's separate out-of-band requirements;
no DM, login, backup device or act obtains root-recovery powers.

The host operator is the **sole writer** of current-rights policy, applying owner
decisions out of band through protected provisioning. Neither an act nor the
agent/carrier writes that policy. For each installation it binds owner, exact
device key, exact profile/operation/typed target and identity generation. No
patterns or implied rights. It includes a monotonic `authority_revision`, full
configured root-role catalog, mode/critical-effect restrictions and the pinned
full recipient identifier. Revisions start at 1 and obey the same integer,
atomic replacement and external restore-floor rules. The provisioning owner
must publish its storage, update coordination and recovery contract (§10).

`SignerFacts.current` is derived from that protected source for the exact current
owner/device/operation/target, never supplied as an unaudited carrier boolean.
Unavailable/malformed/below-floor authority refuses `key_binding_unavailable`;
well-formed policy without that exact right refuses `key_binding_invalid`.
Withdrawing a local right does not revoke the device's root-signed attestation;
current signed revocation is independently mandatory. A policy replacement
binds all new admissions whose final serialized comparison follows its commit.
It does not recall executed effects or establish global completion.

## 4. Closed arguments and bounded intake

The future adapter supplies the exact envelope bytes, a separate canonical
arguments byte string `A`, and immutable protected facts to the shared profile.
Describing these consumer inputs adds no envelope member, Go API, Matrix key
or IPC grammar. Transport/provisioning owners must publish extraction,
full event budget and argument carriage before integration; the existing
`works.relux.swarm.envelope` carrier key and unchanged envelope bytes remain.
The carrier cannot choose the profile or become protected expected state.

Use the existing bounded CCJ-1 parser/canonicalizer, not another JSON parser.
Reject duplicate/unknown/missing members, nulls where a value is required, wrong
types, unsupported versions and normalization. `A` MUST be a canonical CCJ-1
object, at most **2048 bytes**, depth at most **4**, no arrays in these schemas.
The complete received signed act remains at most **8192 bytes**, depth at most16,
with the existing limits and signature shape. Actual delivered UTF-8 text is at
most **4096 bytes**. Charge all inputs before allocation/parsing; smaller
carrier/consumer ceilings still apply. These are independent profile caps, not
an invented full carrier budget or permission to truncate. No untrusted URL
retrieval, implicit pointer, compressed payload or silently dropped field.

Every schema below includes exactly these common argument members:

| Member | Constraint |
| --- | --- |
| `profile` | Exact literal `owner-acts/1`, equal to protected selected profile. |
| `source_room` | Actual canonical source room identifier, opaque printable ASCII 0x21–0x7e, 1–255 bytes, not an alias. |
| `source_recipient` | Full actual recipient identity of this delivery, same byte bounds; not a display name. |
| `text_sha256` | Exactly 64 lowercase hex digits; SHA-256 of the actual delivered text bytes, without prefix. |
| `authority_revision` | Exact protected current-rights revision, integer 1–9007199254740990. |

For each operation the **only** additional arguments are:

| Operation | Additional closed members and required values |
| --- | --- |
| `owner-dm.bind` | `identity_generation` (positive safe revision), `binding_revision` (nonnegative safe revision), `owner_recipient` (full protected pinned recipient, same 1–255 byte bounds), `mirror` (literal false). Current identity must be unbound; no pending/unknown effect. |
| `owner-dm.unbind` | `identity_generation`, `binding_revision`, `bound_room` (1–255 byte opaque canonical room ID), `owner_recipient`. These identify exactly the known active/pending local binding to remove; no wildcard/unbound substitution. |
| `owner-dm.mirror-enable` | `identity_generation`, `binding_revision`, `bound_room`, `owner_recipient`, `mirror` (literal true), `audience_revision` (positive safe revision), `audience_digest` (`sha256:` plus64 lowercase hex). Exact joined binding, mirror currently disabled, no unresolved effect; audience fixed to that protected owner DM as defined below. |
| Reserved `launch.approve` proposal | `request_digest` (`sha256:` plus64 lowercase hex), `request_revision`, `service_generation`, `policy_revision` (positive safe revisions). `request_id` in target is32 lowercase hex digits. These bind an immutable request; they do **not** yet define its complete launch semantics. |
| Reserved `host.change` proposal | `assignment_generation`, `assignment_revision`, `policy_revision` (positive safe revisions), `previous_host`, `next_host` (distinct protected identifiers matching the identity-name grammar), `request_digest`, `previous_assignment_digest`, `next_assignment_digest` (same digest grammar). `assignment_id` follows the identity-name grammar. These are candidate placement arguments, not an accepted effect contract. |

For mirror enable, the only intended reading principals are the exact
`owner_recipient` and the consumer's protected carrier account, which MUST equal
`source_recipient`. Compute `audience_digest` as SHA-256(CCJ-1 of the closed
object `{room:bound_room,owner:owner_recipient,service:source_recipient}`), with
the `sha256:` prefix. All constituents are displayed in full. `audience_revision`
names the protected accepted room-policy/roster revision. The adapter must
independently establish that exact audience and required private/invite-only
room policy, with no other invited or joined principal; uncertainty refuses.
Bind likewise requests one private invite-only room, no public alias/directory
entry or public-readable history, inviting only the pinned owner alongside the
protected consumer account. These are requested properties, not proof of
truthful or atomically stable carrier state; exact creation fields and their
qualified observation remain carrier-owner gates.

All state values must equal independently obtained protected values or the exact
bounded change selected by the protected consumer handler. An opaque digest is
not a substitute for validating/displaying the full launch or assignment request.
The two reserved argument sets cannot support admission until their owners close
that missing request schema, exact target identity and display contract. A
hash-only request with undisplayable security-relevant content MUST refuse.
No proposed argument is added to the closed `operator-act/1` body.

## 5. Deterministic text, digest and signing display

To avoid a self-referential text digest, let `A0` be exactly `A` with only
`text_sha256` removed. Build the closed object `D` with members:

```text
{profile, class, operation, target, owner, epoch, aud, action_id, nonce,
 iat, exp, confirmed, key, arguments:A0}
```

`profile` and `class` come from the protected static table; `key` is the single
approver key ID; other scalars/target come from the exact proposed body. Define
`Render = UTF8("owner-acts/1\n") || CCJ-1(D)`, with no trailing newline.
`A.text_sha256 = lowercase_hex(SHA-256(Render))` and
`body.arguments_digest = "sha256:" || lowercase_hex(SHA-256(CCJ-1(A)))`.
Neither `arguments_digest`, envelope `id` nor signatures is a member of `D`.
Thus no rendering input depends on its own hash. This is not the signature
preimage: the existing raw domain-tagged operator-act preimage and content ID
are computed by `record` over the complete unchanged body.

Both Signer and consumer independently validate the exact schema/profile,
recompute this mapping and require equality. The consumer also hashes the
**actual delivered** raw text and compares its bytes with `Render`; comparing a
reconstruction alone is insufficient. Transport extraction uses the exact UTF-8
bytes of the carrier's plain body, with no normalization, Markdown/HTML rendering,
newline tolerance, display-name substitution or edit indirection. Edited/replaced
or moved events refuse; a signed original is not permission to use its edited
presentation. Missing text, invalid UTF-8 or over-budget text refuses.

The Signer validates from its own immutable buffer. It independently recomputes
CCJ-1/digests, shows operation and trusted class, typed target, owner, epoch,
resolved audience **and exact aud**, action ID, nonce, all argument names/values,
full device key ID, confirmation assertion and time bounds. It displays the
computed text digest and arguments digest too, without using them as substitutes
for content. Byte-exact opaque identifiers remain visible, escaped if necessary
so no control or bidirectional ambiguity is hidden. Anything security-relevant
that cannot be shown fully refuses; no truncation, ambiguous elision or unsigned
requester label replacing a value. Free text, if shown, is separately marked as
unverified. Display, presence decision and raw-preimage signing use the same
buffer; any mutation aborts. One decision covers one signature, never a batch,
reused authentication context or later queued request. These are provider
obligations awaiting a separate contract/qualification, not a platform assertion.

## 6. DeliveryContext and exact binding comparisons

The pure `VerifyOwnerAct` profile comparison uses the existing common
envelope/time and operator pipeline plus the closed argument checks, not
`VerifyEnvelope` alone. Consumer integration must resolve immutable protected
inputs outside the effect lock; the pure call acquires no current state. Compare:

| Signed value | Independent protected/current input |
| --- | --- |
| `body.aud`, owner, epoch | Exact installation enrollment, owner and semantic epoch; no sender override. |
| Operation, class, typed target | Registered static handler, protected operation policy and exact local identity. No caller-selected class or relabelling. |
| `A.authority_revision` | Current per-installation protected rights-policy revision and exact device right. |
| Generation/revision and bound room | Current identity generation, binding revision, binding state and exact known room. |
| `A.source_room`, `A.source_recipient` | Actual carrier room and full recipient from authenticated DeliveryContext. |
| `A.owner_recipient` | Protected enrolled full recipient, and exact current binding recipient for unbind/mirror. |
| Mirror audience revision/digest | Independently established exact room policy/roster, protected consumer carrier account and the two fully displayed principals; no broader audience or stale observation. |
| `A.text_sha256`, Render | Actual delivered raw UTF-8 text bytes; never a caller's digest assertion. |
| `arguments_digest` | Digest of complete schema-checked canonical A and independently validated expected effect inputs. |
| Device/current evidence | Full root-attested owner binding, independent current-rights policy, and current operator revocation. |

The installation audience, command source room, actual delivery recipient, invited
owner recipient, resulting newly created DM and mirror audience are distinct
facts even when some strings happen to coincide. Creating a room cannot sign its
future room ID in advance: bind authorizes one bounded creation/invitation, and
the resulting actual room ID is retained as that operation's outcome. It does
not authorize posting plaintext to arbitrary rooms or accepting a caller's
chosen result ID. A qualified carrier adapter must establish actual identifiers;
MXID equality alone does not provide that qualification or current authority.

Preserve E1–E8, O1–O5 and all T/R/K/currency subpipeline ordering. New schema,
profile/argument/context equalities belong to the reviewed profile's O1 binding
stage; definite mismatches use `act_binding_mismatch`, unavailable required
binding source uses existing `key_binding_unavailable`. Do not reuse message-only
E7a/E7b as an unreviewed operator API or move signature failures behind these
comparisons. `audience_mismatch`, raw signature/schema/time errors, current-rights,
revocation, replay and widening refusals retain their existing precise codes and
first-failure order. Coarse application error mapping belongs to its owner;
Keymaker's `OperatorRecordCode` is unchanged and is not a new carrier wire map.

## 7. Currency, candidate plan and serialized effects

Import the **complete** [platform §§2.6–2.9, 4.3, 6–7](swarm-envelope-2.md)
contract, not just a signature/current flag. Operator-domain stage-2 admission
requires protected RegistryCurrencyVersion=2 with no fallback, latest selection
from the complete-prefix index, required coverage for every used root, cumulative
original signed snapshots and complete retained history. Fresh authenticated
witness reads occur for each admission outside final locks; exact head/state and
qualified read age/deadline are compared inside. Changed state, failed reads or
asynchronous re-entry requires new evidence, not cached last-good fallback.
Preserve all capacity-first, /2 version/pin floors, old-instance fences and
one crash-atomic state/evidence/history/watermark/re-anchor commitment before
receipt use; retain original Evidence and remint after restart. A receipt has
its original exclusive expiry and is never an effect permit.

Revocation guarantees start at the **observed authenticated witnessed prefix**.
Once it contains newer cumulative root content, a new /2 admission cannot select
its predecessor. No signing/submission-to-publication deadline or immediate
global revocation is asserted. Earlier receipts keep fixed expiry; publication,
local withdrawal and completion are different. Completion still needs the defined
durable acknowledgements/barriers or proven expiry of all prior authority.

The proposed adapter sequence is:

1. **Recovery selection, not new admission.** Resolve the protected installation
   and authenticated caller/disclosure context, and look up the retained journal
   using bounded untrusted identifiers without accepting their assertions. If an
   action is consumed, exact retained envelope bytes, canonical arguments and
   binding/operation identity must match. Different bytes/context refuse
   `act_replay` (earlier byte-integrity conflicts keep their existing precedence).
   Identical retained results may be returned only under **current disclosure
   authority** for that result and destination. This is not `VerifyOperator`
   acceptance of a used action, not a new time window, and never an effect retry.
   An expired act may recover a previously stored outcome only through this
   separate disclosure-authorized recovery path; it cannot be readmitted.
   Unavailable disclosure policy/journal/history yields no disclosure or effect.
2. **Candidate outside locks.** Resolve protected policy, current authority,
   attestation/revocation, fresh witness, qualified time/watermark, journals and
   exact DeliveryContext; invoke the full pure profile validator. An accept is
   an immutable candidate persistence/effect description, not an effect permit.
   It owns no I/O, global clock, fetching, secret, reservation or mutation.
3. **Fresh local final comparison.** Under the identity serialization, compare
   installation/epoch, generation, binding and authority revisions, profile/pin,
   mode/policy revision, witness/index/evidence versions, qualified time and
   watermark, revocation, event-ID/act journals and actual intended effect.
   Re-run the pure pipeline with current immutable facts and unused action ID.
   All local reads must be bounded; changes require release/re-resolution outside
   the lock. No provider/network acquisition occurs under these locks.
4. **Critical effects stay fenced.** Bind, mirror enable, launch approval and
   host reassignment require `OnlineAuthority.Check(exact_request)` with the
   authority owner immediately before the effect at its serialized boundary.
   Only `current` permits progress. A protected consumer can strengthen unbind
   to critical as well. The coordinator, ordering against external changes,
   bounded freshness and exclusivity of this online check are **unresolved**;
   no cached result, receipt, check done merely before waiting for a lock, or
   network call hidden inside a lock satisfies it. These operations cannot
   activate until that contract is reviewed/qualified, independently of A3.
5. **One recoverable pre-effect commit.** Atomically reserve `(aud,action_id)`
   installation-wide across owners/keys/epochs/operations; retain full received
   act bytes, canonical arguments, exact request/binding digests, policy/evidence
   identities, source event ID, durable time watermark and pending-effect intent.
   Record the exact intended successor revision and exclusive effect deadline.
   Failed/partial commit gives no effect. Concurrent duplicates can reserve at
   most once. An event ID remains an additional single-use carrier fence, never
   a substitute for the act journal. No consumed ID is released, including abort.
6. **Effect point and outcome.** Recheck the relevant expiry/time/revocation and
   binding conditions at the actual effect point, including after asynchronous
   work. Record exact resulting room/state and original outcome durably. Intent
   is not completion. Local binding-state transitions atomically advance the
   binding revision with the corresponding intent/outcome state. No watermark
   or revision rollback is permitted after cancellation.
7. **Unknown outcome fence.** A failed reply/crash after possible remote room
   creation leaves `unknown`, never absent or safe-to-retry. Fence the identity
   and every dependent mutation/delivery. Reconciliation must use the original
   intent and qualified authoritative carrier observations to establish the one
   actual outcome; do not allocate a fresh act or blindly repeat creation.
   Lack of unique provable correlation retains the fence. A new act cannot erase
   it. No at-most-once remote API, authoritative correlation/reconciliation or
   exactly-once guarantee is assumed; until its owner publishes that procedure,
   remote bind/mirror effects remain inactive. Authenticated metadata-only status
   must not disclose a retained result to an unauthorized current reader.

A widening request with missing confirmation/presence or used action ID retains
its earlier O3/O4 refusal; an otherwise-valid widening still returns
`act_a3_inactive` at O5 with zero plan. No self-assertion opens it. A narrowing
candidate still needs current rights, revocation, trustworthy time and journals;
missing evidence is not an empty set. Preserve every existing refusal and plan
zeroing property. Storage failures remain `state_unavailable`, conflicts remain
`act_replay`; the recovery statuses described above are local journal concepts,
not new wire refusal codes.

## 8. Pending join, mutation entry points and residual disclosure

After an admitted bind, the known resulting room is pending and mirroring is
disabled. A later carrier join is liveness under the original operation, never
presence/A3 evidence. Pending activation must refer to that reserved action and
its exact successor revision, not try to readmit its consumed ID. Its deadline is
no later than the original act expiry and any stricter qualified authority,
receipt or protected pending deadline; observing a join cannot extend it.
Activation requires fresh full current facts/final comparisons, exact recipient
and room state, unchanged authority/profile/policy and identity generation, and
the recorded expected binding revision. It uses the shared current-evidence
checks under the original journaled continuation; it cannot call a fresh O4
admission and suppress `act_replay` to make the consumed act pass. That bounded
continuation interface is part of the consumer implementation review, not an
API supplied here. It advances revision atomically. Expiry,
withdrawal, revocation or a competing transition cancels and retains the record;
a late join cannot activate. A terminal cancellation may stop future local
behavior but cannot undo an already observed remote effect or remove its fence.

Every entry point shares the same per-identity serializer and durable revision
transaction: signed bind/unbind/mirror commands, carrier event handlers, pending
join activation/cancellation/expiry, terminal ensure/set/unset, mode/mirror
changes, identity delete/recreate, restore/recovery, re-pin/epoch/owner change and
protected policy updates. Provisioning updates must coordinate their revision
commit with that boundary, or force candidates to fail/re-resolve. Root/policy
changes remain host-operator provisioning actions, never DM operations. Even
same-value committed replacements advance the relevant revision. Background
senders must compare that revision immediately before future delivery; queued
old work cannot revive a removed binding. Mirroring also rechecks current
rights/revocation/currency, fixed act expiry and the exact audience/policy
immediately before each disclosure; changed or unavailable room state stops
local delivery and invalidates the mirror revision. This still supplies no
atomic audience isolation against a carrier race or prior disclosure. Generation
changes preserve tombstones and invalidate all old acts/pending work.

Terminal/UI/maintenance entry points are not unsigned widening alternatives.
They invoke the same signed admission for any new bind/mirror effect; separately
authenticated local narrowing can only cancel/remove access under its own
published policy and must advance revisions. It cannot weaken Keymaker's signed
persistent revoke. The existence of a host-operator provisioning channel does
not give an agent that channel's rights. An inventory and concrete lock/storage
coordination for **all** entry points is an activation prerequisite; no omitted
terminal path is covered by a signature on a different path.

Signatures provide no confidentiality, truthful membership assertion, atomic
audience isolation or remote exactly-once delivery. Mirror plaintext and prior
recipient access remain disclosed after local unbind. A valid typed act does not
make other text from that sender an owner decision, approve a session, supply a
missing grant/caller provenance/session fence or override a consumer policy.

## 9. Proposed acceptance matrix — future full-path claims, UNRUN here

These historical proposal labels name **future full-path** test claims and
paired fixtures for the shared profile and consumer owners. They are not the
current test inventory or execution results of this documentation unit. Later
portable-library tests may cover narrower properties; their existence does not
establish these complete consumer/native/effect claims. “Candidate” below needs
the applicable reviewed implementation and protected fixture evidence; it is
never a live effect claim.
For inactive operations the valid control is a well-formed, bound proposal that
still produces no permit, paired with the nearby eligible narrowing control.

| Future test name / specific claim | Nearby valid control | Invalid/control variant and required observable result |
| --- | --- | --- |
| `TestOwnerActsUnbindExactLocalRemoval` | Current bound DM, full authorized device, current /2/time/journals: unbind candidate removes only its local binding. | Ask for replacement room, alternate recipient, unknown argument or remote-history deletion: reject, zero plan/no writes or disclosure. |
| `TestOwnerActsBindWideningClosed` | Structurally valid bind, exact unbound target and all facts reaches `act_a3_inactive`; nearby valid unbind candidate. | Class override, bind disguised as unbind or mirror=true on bind: reject; neither candidate nor room creation. |
| `TestOwnerActsMirrorEnableSeparateClosed` | Exact joined DM, disabled mirror, mirror=true: widening still inactive; valid unbind beside it. | Bind/join/TTY alone enables mirror, larger audience or a previous enable act reused after disable: no enable or delivery. |
| `TestOwnerActsReservedLaunchNoPlan` | Exact proposed launch request shape is documented but inactive; valid registered unbind beside it. | Reserved launch or alias to grant.issue/VerifyEnvelope used as approval: existing ordered rejection, no launch permit/session/grant. |
| `TestOwnerActsReservedHostChangeNoPlan` | Exact proposed placement shape is inactive; valid unbind beside it. | Treat remove-old/add-new as narrowing, change host outside exact request or caller-selected handler: reject, no placement effect. |
| `TestOwnerActsUnknownOperationNoFallback` | Registered unbind candidate. | Unknown spelling/profile/version, reserved spelling, relabelled target, missing static policy: fail closed with earlier structural code or O1 `act_operation_unknown`/binding refusal as applicable; no fallback. |
| `TestOwnerActsExactOwnerAudienceEpoch` | Same owner/aud/epoch as protected state. | Change each independently, replay to a cloned installation: exact audience/binding refusal, no effect/disclosure. |
| `TestOwnerActsClosedTypedArguments` | Exact canonical schema, integer revisions, literal booleans. | Unknown/missing/null/duplicate fields, noncanonical A, string/float revisions, patterns, wrong kind or over-cap input: intended ordered parse/binding refusal; no truncated parse or plan. |
| `TestOwnerActsGenerationRevisionFence` | Matching current generation/revision. | Delete/reuse name, terminal transition or same-value replacement after signing, restored lower floor or overflow: reject/fence; no old binding revival. |
| `TestOwnerActsCurrentRightsIndependent` | Attested unrevoked device with exact protected operation/target right. | Withdraw right, substitute current=true/MXID/confirmed or omit known role pin: key binding refusal; attestation cannot restore authority. |
| `TestOwnerActsPolicyChangeAtFinalBoundary` | Unchanged authority/profile/mode/pin revisions through final comparison. | Rights/policy/pin changes while waiting or after asynchronous work: release/re-resolve or refuse before effect; no stale candidate reuse. |
| `TestOwnerActsDeliveryRoomRecipientText` | Exact source room, full delivery/owner recipients and actual Render bytes. | Move event, wrong recipient, edited/replaced text, one-byte text/newline change, absent/invalid UTF-8: O1 binding failure after earlier gates; no disclosure/effect. |
| `TestOwnerActsRenderDigestNoCycle` | Independent canonical A0/D/Render/A/body-digest mapping agrees at Signer and consumer. | Wrong digest, Unicode normalization, hidden/truncated field or mutation after display: no signature/acceptance; envelope-only success is insufficient. |
| `TestOwnerActsRawSignatureAndEnvelopeOrder` | Existing raw low-S P-256 act and valid root-attested device. | DER/high-S/FIDO/WebAuthn/SSHSIG/Ed25519 device, duplicate signature, changed raw preimage, malformed/oversized envelope: exact existing schema/crypto refusal before later bindings; zero plan. |
| `TestOwnerActsReplayRecoveryNotAdmission` | Fresh unused action candidate; separately identical retained outcome under current disclosure right. | Pure identical act replay: `act_replay`; changed retained bytes/context: conflict; current disclosure withdrawn: no result; expired consumed act never creates a fresh effect. |
| `TestOwnerActsConcurrentReserveAndCommitFailure` | One successful durable reservation/intent before effect. | Concurrent duplicates, journal unavailable or failed watermark/state transaction: at most one reservation, no losing/partial effect, no released consumed ID. |
| `TestOwnerActsPendingJoinCurrentBoundary` | On a future qualified bind fixture, exact timely join with matching original successor revision and fresh facts activates once. | Late/wrong-room/wrong-recipient join, intervening unbind, authority withdrawal/revocation/expiry: cancel/fence, no activation/mirror; consumed act not readmitted. |
| `TestOwnerActsUnknownRemoteOutcomeFence` | Recovered original uniquely established outcome, disclosed only under current permission. | Crash after possible creation, lost reply, missing history, ambiguous room correlation or fresh replacement act: identity fenced, no blind retry or unrelated result disclosure. |
| `TestOwnerActsTimeWindowAtEffect` | Exact valid 120-second lifetime and current time/watermark before expiry. | Lifetime121 seconds: `envelope_malformed`; future iat: `not_yet_valid`; expiry at max(now,watermark), provider-disqualified time, failed watermark continuity or expiry while waiting/after asynchronous work: the applicable existing time/watermark/expiry refusal, no effect or extended deadline. |
| `TestOwnerActsTimeJournalCurrencyUnavailable` | Qualified current time/watermark, continuous ID/replay stores and full /2 evidence. | Any time/watermark/journal/authority/snapshot/witness unavailable, stale read or failed receipt remint: exact existing unavailable/expiry code, zero plan/effect; no last-good fallback. |
| `TestOwnerActsCurrencyLatestCoverageRestore` | Complete-prefix newest cumulative snapshot, every used root covered, valid original evidence and external floors. | Registry selects older root content, missing coverage/originals, restored old binary/pin/version/index/journals or receipt beyond exclusive expiry: existing /2 refusal/fence; no mode downgrade. |
| `TestOwnerActsCriticalOnlineBoundaryClosed` | Noncritical eligible unbind candidate; critical proposal remains inactive. | Cached online check, check before lock wait, network under final locks, changed head or authority unavailable: no critical effect; offline candidate is insufficient. |
| `TestOwnerActsShadowNeverAuthority` | Shadow records bounded protected observation only. | Shadow accept/refusal converted to pending binding/permit/reservation, reused at stage2, or A0/T fallback: zero such changes; any observed effect fails test. |
| `TestOwnerActsEveryEntryPointRevisions` | All inventoried mutation paths commit successor revision with their state. | Terminal/mode/pin/pending/restore/background path skips serializer or floor, old queued send survives unbind: invariant fails, no handoff. |
| `TestOwnerActsExistingProfilesPreserved` | Existing Keymaker revoke and existing grant.issue closed-widening controls retain their exact results. | Registration integer changed to string, unbind aliased to revoke, target relabel or unknown op accepted: existing named refusals and original tests preserved. |

For time fixtures, scalar `now < W` alone does not fail the core window:
starts use `min(now,W)` and expiry uses `max(now,W)`. For qualified abstract
facts `iat=9, now=10, W=11, exp=12`, both inequalities pass. A negative must
identify provider disqualification, unavailable/rolled-back watermark continuity
or an actually failed start/expiry bound, paired with an eligible positive.
These are paper fixture constraints, not executed temporal qualification.

**Future instrument plant, UNRUN:** in an isolated reviewed implementation
fixture, replace only the full shared verifier result with unconditional accept
and a nonzero candidate plan. Keep consumer effects fake and isolated, not live
carrier/network state. Run `TestOwnerActsRawSignatureAndEnvelopeOrder` with its
named bad-signature case and `TestOwnerActsCurrentRightsIndependent` with its
withdrawn-right case. Each must fail its assertion of the exact refusal/zero
plan; unrelated setup errors or skipped/not-applied plants prove nothing. Pair
with the valid unbind test, so reject-all cannot pass. Record actual commands,
exit codes and any surviving plant's precise bound. If adapter binding checks
mask the shared-verifier plant, exercise the pure profile path directly; a
plant with no named intended failing test is a survivor, not a kill. This plant
proves only harness sensitivity, not complete parser/crypto/consumer coverage.

## 10. Review and activation gates still open

The original static v1 proposal received content review before the later
bounded portable helpers. Publication review, implementation review and
consumer/native qualification remain distinct. This documentation continuation
changes no implementation pin and reports no new conformance result.

- **Shared verifier owner:** review static profile/target registration, O1
  integration and context availability mapping, preservation of every existing
  refusal and paired vectors. The current pure APIs are only the portable
  subset; an adopting consumer must select the exact reviewed implementation
  pin and qualify its remaining integration before even shadow uses these
  operations. Existing `VerifyOperator` cannot be
  bypassed, and no second parser or crypto implementation may be substituted.
- **Owner-DM consumer/carrier owner:** publish canonical arguments carriage and
  exact received-byte extraction, actual event byte budget, authenticated
  DeliveryContext resolution, every terminal/background entry point, pending
  deadline policy and authoritative remote-effect correlation/reconciliation.
  No unknown-outcome retry or implied at-most-once remote API. Bind/mirror stay
  inactive while any such boundary is missing, independently of A3.
- **Host provisioning owner:** assign and review protected storage, full role
  catalog, audience/epoch uniqueness, per-device exact rights, sole writer,
  mode/critical policy, atomic authority/binding coordination, external floors,
  restore fencing and explicit continuity/re-enrollment procedures. The writer
  principle is decided; the concrete provisioning implementation is not.
- **Launch consumer owner:** confirm `launch.approve` and launch request target;
  define its complete immutable request (principal, service/session generation,
  caller provenance, credentials/grants, limits, target, policy and expiry), exact
  bounded schema/display, one-launch consumption, every mutation and result
  recovery/disclosure/fan-out rule. Existing caller/grant/standing-consent/session
  fences remain independently required. The selected authority is
  `operator-act/1`, not `activation/1`; this decision is not an implemented launch
  handler or permission to reinterpret an inactive activation proposal.
- **Host-change consumer owner:** confirm whether the intended effect is one
  execution assignment move, then define its exact target generation and
  before/after schema, draining/cancellation/credentials/session/grant checks,
  concurrency, fan-out, outcome/recovery and display contract. If it is another
  effect, replace the provisional meaning and classify it from that effect
  before registration. The reserved generic operation cannot edit arbitrary
  configuration, roots or current-rights policy.
- **Effect/coordinator, time, currency and provider owners:** review/qualify
  critical online serialization; the full /2 publisher/witness/custodian/
  consumer and time/state/restore boundaries; common provider/enrollment/IPC/
  display contract and each device separately. Trust-node work is not pulled
  forward by the same-UID stage2 choice. None of these deployment or qualification
  gates is met by this proposal. A3 remains closed; there is no native activation.

The full-path matrix and future instrument plant remain UNRUN in this
publication unit. Existing portable results cover only their named, pinned
library properties, not a live effect boundary or this entire matrix. Independent review,
lead disposition, implementation review, exact pin adoption and consumer-owned
activation are separate decisions.
