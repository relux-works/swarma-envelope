# Pure verifier

`github.com/relux-works/swarma-envelope/verifier` implements the ordered platform v0
pipelines. `record` contains the independent byte, domain, crypto and signer
admission layer; this package adds protected evidence and authorization. This
split keeps provider/state policy out of generic signature verification and
avoids a dependency cycle. Neither package imports either conformance tool.

Construct immutable `Evidence` with `Present(value)`, fill `Context`, then call
`New(context)`. The zero `Evidence` explicitly means unavailable. Available
empty dictionaries/arrays must be explicitly constructed. Null remains null;
it never means an empty journal. `Present` copies maps, arrays and byte slices,
rejects unsupported Go interfaces/callbacks and bounds depth and total size.
Do not ignore its error. Input dictionaries use `map[string]any`, arrays `[]any`,
integers `int64`, strings and booleans. They are protected in-process values,
not a newly registered network or native request grammar. Values with a wrong
supported type are refused at their consuming pipeline row. No provider method
is called by the verifier. There is no ambient clock or implicit fetch.

| Context evidence | Value when available |
| --- | --- |
| Audience | Exact consuming installation string |
| RequiredRoles, AdmittedKeys | Arrays of role/key-id strings |
| GrantRoot, OperatorRoot, OperatorOwner | Purpose-scoped key-id / owner string |
| ServiceRoot | `{key,purpose}` with integer purpose 5 |
| AgentRevocationRoot | `{key,purpose,attestation_root}` with purpose registry-revocation |
| Attestations | Content-id to raw signed attestation bytes |
| AgentAttestationIDs | Key-id to current attestation content-id (grant subjects only) |
| DeviceAttestations | Device key-id to raw signed attestation bytes |
| CurrentGenerations | Key-id to `{active,uid,generation,registration_number,master_epoch,owner,path}` |
| SignedSnapshots | Issuer key-id to `{availability,max_age,rollback_safe,snapshot}`; snapshot is raw signed bytes, max_age int64 seconds |
| Time, Now | `{trusted,fresh,authority_until}` and exact sampled timestamp; trusted/fresh include the provider's hold/continuity decision |
| WatermarkAvailable, Watermark | True and exact durable timestamp; available means the caller has established continuity |
| IDJournalAvailable, IDJournal | True and content-id to exact accepted raw wire bytes |
| ReplayAvailable, UsedActions | True and an explicit array of consumed action-id strings in this installation's journal namespace |
| SignerFacts | `{current,presence,presence_current}` provider facts; presence gates widening only |
| Assurance | Protected request-bound `{level,presence}`; asserted A3 is unavailable in v0 |
| Delivery | `{room,to,text}` with exact carrier identifiers and raw delivered UTF-8 bytes |
| ActBinding | `{operation,target,owner,epoch,arguments}` for the protected concrete request |

Methods:

- `VerifyMessage`: receiver checks, current author evidence by signed reference,
  every approver, delivery identifiers/text, time and id journal.
- `Authorize`: leaf-first grant chain and one protected request evidence value
  `{key,action,target}`, including attenuation, revocation and assurance.
- `VerifyOperator`: complete act pipeline; widening remains inactive.
- `VerifyEnvelope`: E1–E8 for a selected platform type. This lower-level method
  does not replace chain authorization or the operator pipeline.
- `VerifyAttestation` and `CheckRevocation`: signed evidence independently of
  envelope admission. Agent lookups require an exact key and nonempty content
  reference; device lookups require the exact key and, if supplied, exact content
  reference. The standalone helper never defers identity equality to a caller.
  Snapshot roots must match a protected registry, operator or grant issuer;
  registry purpose and exact service-root scope are mandatory, and purpose-5
  roots cannot issue snapshots. Missing policy/evidence yields unavailable;
  invalid policy or evidence is an error, never a fourth successful revocation
  state. Only `not_revoked` permits progress.
- `OperatorRecordCode`: separate coarse Keymaker refusal mapping; keep the
  original fine reason in local audit. An empty/missing verifier code maps to
  unavailable. Supply `state_unavailable` for a failed/unavailable Commit.

Operator envelopes additionally recognize exactly the two-member target
`{"kind":"owner-dm","id":NAME}`, where NAME matches
`[a-z0-9][a-z0-9-]{0,62}`: 1–63 ASCII bytes, beginning with a lowercase letter
or digit. Message and grant targets do not recognize this kind. Existing JSON
intake permits whitespace, member order and valid escape variations as in
wire specification §2.2; the decoded name must satisfy this grammar.
`VerifyEnvelope` can return an envelope candidate for this target, while
`VerifyOperator` still refuses `owner-dm.bind`, `owner-dm.unbind` and
`owner-dm.mirror-enable` as `act_operation_unknown`. Reserved `launch.approve`
and `host.change` remain closed. `revoke` still requires a registration target,
and `grant.issue` an account target.

`Result` returns the exact code and an empty `Plan` on refusal. Acceptance
returns ordered ids, candidate watermark and, for an act, its single-use id.
No method reserves, writes, commits, dispatches, performs effects or qualifies
provider deployment. A fresh verifier/context is needed after facts change.
The caller must atomically Commit before effect, recheck current authority at
its serialized effect boundary, and perform the authority-owner online check
for consumer-selected critical effects. The v0 library defines no network,
registry service, recovery, emergency-stop or witness implementation.
Pure journal/checkpoint format verification is supported below.

The caller owns the exact received-byte slice and must not mutate it during
verification. Returned plans are independent of the verifier's immutable facts.
One verifier value can be used concurrently; this promises no serialization
of external effects or storage.

## Owner-act candidate verification

`New(context).VerifyOwnerAct(envelope, arguments, deliveredText, protected)`
selects the immutable owner-acts/1 operation table. It shares E1–E8 and the
operator O2–O5 continuation with the existing APIs. It does not change
`VerifyOperator` or make `VerifyEnvelope` an authority check. Operations are
exactly owner-dm.bind (widening), owner-dm.unbind (narrowing) and
owner-dm.mirror-enable (widening), with target kind owner-dm. Unknown and reserved
operations refuse after earlier envelope gates. No caller supplies a class,
handler, callback, dynamic registry or fallback profile.

The three byte inputs are independent: operator envelope at most8192/depth16,
canonical arguments at most2048/depth4, actual raw UTF-8 text at most4096.
Lengths are inspected before decoding; argument/text refusals stay at O1 after
the common envelope gates. Nil text means unavailable; non-nil empty text or
unequal bytes refuse binding. Envelope JSON transport whitespace/order/valid
escapes remain permitted. Arguments must be exactly canonical. Raw delivered
text must equal the mapper's complete Render, including its single LF; no
normalization, trim, Markdown, alias resolution or digest proxy occurs.

`OwnerActContext` uses `Present` snapshots with the following closed in-process
object shapes. These are an API between a qualified source adapter and the pure
verifier, **not** a new wire/local policy-document format. All integers are
int64. Omitted, null, wrongly typed or otherwise malformed required sources
are unavailable at their consuming row. Definite signed binding inequalities
use act_binding_mismatch. Other existing earlier and later refusals retain
their slots. The mapper fixes the text, argument digest, body, ID and original
domain-separated preimage from signed metadata and independent protected A0.

| Snapshot | Required members and meaning |
| --- | --- |
| Selection | `aud,owner,epoch,device,owner_recipient,consumer_recipient,profile_pin,candidate_enabled,critical,presence_required`. Exact enrollment, full recipients, immutable reviewed source content ID and protected booleans. Audience is owner-acts:32lowerhex; epoch is epoch:32lowerhex. |
| Binding | `identity,generation,revision,state,bound_room,owner_recipient,mirror,unknown_effect`. Exact local slot and current state. Bind requires unbound, empty bound_room, mirrorfalse, no unknown effect. Unbind requires a known active/pending/joined binding and exact recipient/room. Mirror requires joined and mirrorfalse. |
| Delivery | `room,recipient,edited,replaced,moved`. Authenticated actual source identifiers and all three mutation flags false. Recipient must equal Selection.consumer_recipient. |
| Authority | Provenance tuple below plus `device,profile,operation,target,generation,admitted`. Protected adapter's exact lookup query and boolean result, not a bare current-device assertion. Available denied lookup is key_binding_invalid. A foreign query or unavailable/malformed provenance is key_binding_unavailable. |
| ActiveHead, RestoreFloor | Each is the exact complete provenance tuple, independently authenticated outside the restore domain being detected. Both must equal the selected Authority tuple; an integer minimum alone is insufficient. |
| Lineage | `aud,owner,epoch,policies`, with policies an oldest-first array of closed `{revision,policy_id,previous}` rows from explicitly provisioned revision1/null predecessor through the exact selected head. Revisions are consecutive, IDs unique and links exact. This bounds the API to histories fitting Present's existing1MiB snapshot cap. |
| Instance | `aud,owner,epoch,instance_fence,profile_pin`, bound to the selected serving instance and source pin. |
| RootCatalog | `id,roles`. Roles is a complete closed object with `service_root,agent_revocation_root,operator_root,root,commit_signing_key,enrollment_publisher,service_authority,service_attestations`, using the corresponding Context values, explicit null only for unconfigured roles. A known configured role omitted or substituted is key_binding_invalid; unavailable complete catalog is key_binding_unavailable. Existing distinct-role checks still run. |
| ProfileCatalog | `id,profiles`. Profiles maps every provisioned published profile identifier to its immutable source content ID. The owner-acts/1 entry must equal Selection.profile_pin. The adapter must establish completeness and authenticate these IDs; received values cannot publish a catalog. |
| RoomAudience | Mirror only: `room,owner,service,revision,digest,private,invite_only,principals`. Principals is the complete union of invited/joined reading principals, exactly the distinct enrolled owner and protected consumer. Service equals actual delivery recipient. Digest is SHA-256(CCJ of `{room,owner,service}`), with sha256: prefix. Revision/digest and current room/roster observations must match the received arguments. |

The provenance tuple is
`aud,owner,epoch,revision,policy_id,previous,root_catalog_id,profile_catalog_id,instance_fence`.
Policy/catalog/source IDs are complete content IDs. Instance fence is an exact
nonempty string of at most255 bytes. Authority revision and generation are
1..9007199254740990, binding revision0..9007199254740990. Owner permits exact
nonempty UTF-8 up to255 bytes; opaque carrier identifiers use the mapper's
1..255 printable ASCII grammar. Distinct facts remain distinct when strings
coincide. Bind fixes a private invite-only creation/invitation to the protected
owner, with no public alias/directory/readable history; it cannot select the
future result room. This candidate API performs no creation or observation.

Every profile call forces genuine original process-local `/2` receipt
consumption at the existing T/R slot, regardless of RequireFreshnessReceipt.
Version0/1 cannot fall back; missing receipts, rebuilt original Evidence,
missing coverage, mismatched pins or expired receipts refuse through the
existing shared gates. Keep original SignedSnapshots and SnapshotJournal
Evidence. Current exact rights never replace signed device attestation,
owner equality, current operator revocation, trusted time, ID or replay journals.
SignerFacts.presence/presence_current remain independent for widening; the
legacy SignerFacts.current boolean alone neither grants nor withdraws a profile
right. Optional protected presence restrictions strengthen unbind. Disabled
candidate mode or critical unbind closes at O5 after earlier gates. Widening
always requires confirmation/current presence and remains act_a3_inactive.

Snapshots describe explicit pure-function premises only. Caller assertions of
source pins, catalog identities, lineage or floor equality do not establish
qualified provisioning, source authenticity, restore exclusion or live custody.
Source adapters must supply them independently and report unavailable if those
premises are not qualified. No catalog resolver, raw policy parser, storage,
update service, currentness cache or network lookup is supplied. Immutable
Prepare/review/Finalize signing, native provider qualification, serialized
current/effect comparisons, critical online coordination, recovery and
disclosure remain separate. Acceptance is a prospective standard Plan, never
an effect permit, reserved action or proof of exactly-once execution.

## Validation

From the repository root with Go 1.26+ selected in `CURATOR_GO`:

```sh
CURATOR_GO="$CURATOR_GO" GOMAXPROCS=2 "$CURATOR_GO" test ./... -p 1 -count=1
CURATOR_GO="$CURATOR_GO" GOMAXPROCS=2 "$CURATOR_GO" test ./verifier -run '^TestConformance$' -count=1 -v
GOMAXPROCS=2 "$CURATOR_GO" test -race ./verifier -run '^TestConcurrentVerifier$' -count=1
GOMAXPROCS=2 "$CURATOR_GO" test ./record -run '^$' -fuzz '^FuzzParse$' -fuzztime=5s -parallel=2
```

On a resource-managed host, wrap each full test, conformance, race and fuzz
command in the host's required serialized resource runner, sequentially. The
conformance test generates its corpus with the existing generator in a Go test
temporary directory. `CURATOR_GO` selects that child toolchain explicitly;
otherwise it uses the runtime toolchain or Go on PATH. `WAGGLE_VECTORS` may
select an already materialized corpus. The committed sweep digest, entire
manifest, all 1688 sweep byte hashes, all 1217 named bytes and exact 2905
code/plan verdicts are checked. Generated sweeps are never committed. Fixture
base64 transport and legacy field names are adapted only in the test.

A tampered expected named verdict in a temporary selected corpus makes
`TestConformance` fail its named-byte gate. To establish the semantic gate's
sensitivity as well, temporarily plant a wrong library verdict and run the
same full test; the named witness must fail with a derived/expected mismatch.
Restore the exact source before any further validation. Keep plants and logs
in ignored `.tmp/`. Parser fuzzing is bounded smoke evidence, not a proof of
all inputs, live integration or cryptographic security.

Each package's `api.txt` and `TestAPISurface` inventory exported declarations,
fields and methods. This name inventory is not a compatibility proof or review
approval. Consumers pin a reviewed main commit and raise it through review.

Registry formats add these protected context facts. They are immutable
in-process values, not a witness wire format or self-asserted received claims:

| Context evidence | Value when available |
| --- | --- |
| ServiceAuthority | `{key,purpose,owner}`; key exactly GrantRoot, purpose `grant-service`, independently bounded owner |
| ServiceAttestations | Exact service key id to raw grant-root-signed attestation bytes; presence selects expected service role, never an unsigned class field |
| RegistryOwner | Exact protected nonempty UTF-8 owner, at most255bytes |
| JournalWitness | Already verified head projection exactly `{registry_id,owner,registry_seq,registry_head,checkpoint_id,previous_checkpoint_id}`; registry_seq is positive int64, predecessor null only externally authorized genesis. No timestamp or witness wire parsing; absence refuses |
| CommitSigningKey, EnrollmentPublisher | Separate key-id strings; every present role is compared under D30; commit key has no protocol-record profile |

`VerifyServiceAttestation(key)` returns only an exact verified identity, including
owner, current time and grant-owner revocation. Its zero identity and definite
error on refusal confer no partial authority. `Authorize` still requires a
covering parent grant, all narrowing and every-link time/revocation checks.
Agent keys remain forbidden as grant issuers. Service keys sign only grants.

`VerifyJournal(entries, checkpoint, conflict)` checks an oldest-first suffix,
registry-author checkpoint, exact current registry snapshot and external witness
facts; conflict is nil or one additional fully authenticated current checkpoint.
Every advancing suffix starts with the authenticated prior-head entry, within
its64entry bound. `IDJournal[witness.checkpoint_id]` must provide the exact
prior checkpoint bytes; `IDJournalAvailable` must be true. The API authenticates
prior id/root/scope/owner/seq/head without age and compares checkpoint times
separately from entry times. Exact non-advancing witnessed retransmission needs
no prior bytes. It returns exact J1–J6 (including J5a) codes and an empty plan on
every refusal. The accepted
plan names only the checkpoint id and watermark. Persist those exact verified
checkpoint bytes and watermark atomically before using the view; witness updates
follow the external witness owner's contract. This API authenticates references
and ordering, never referenced-record admission, action authority, enrollment
publication or repository commits. Genesis authorization and witness authentication/storage
remain activation requirements. Snapshot paging is a format direction only;
over-capacity single snapshots refuse without truncation.

Focused checks, with generated artifacts/logs in ignored `.tmp/`:

```sh
GOMAXPROCS=2 "$CURATOR_GO" test ./verifier -run '^Test(Registry|ServiceAttestationAPI|JournalBounds)' -count=1
GOMAXPROCS=2 "$CURATOR_GO" test ./record -run '^TestRegistryDomains$' -count=1
```

## Signed snapshot freshness

`VerifyFreshness(chain, checkpoint, ids, keys)` is the separate D38 B registry
revocation entry point. The bounded chain is oldest-first raw signed freshness
bytes; checkpoint is exact raw signed checkpoint bytes. `SignedSnapshots`
provides the current registry snapshot and maximum age. The full F1–F9 pipeline
checks every proof signature/link, the current tip, exact three-way snapshot
binding, checkpoint signature, protected witness currency and query matches.
Only accept with a candidate plan permits further caller processing; revoked
and every refusal have zero plans. No method performs an effect or persistence.

Two additional protected Context values are required:

| Evidence | Exact available value |
| --- | --- |
| FreshnessAnchor | `{registry_id,owner,publication_seq,freshness_id,issued_at,snapshot,registry_seq,checkpoint_id}` from the caller's last accepted durable publication. All sequences int64; registry_seq positive. Explicit authorized publication genesis uses publication_seq0 and null freshness_id/issued_at, still pins an authenticated positive registry checkpoint and snapshot. Absence never bootstraps. |
| WitnessReadAt | Exact protected §2.1 time of the fresh authenticated head read; >=current tip.issued_at, <=min(now,W), no older than the configured snapshot max_age<=60s. It is not a self-asserted field copied from received bytes. |

`JournalWitness` retains its exact six-field verified projection. The current
checkpoint may be old, but must match this freshly authenticated head exactly.
The snapshot must equal both checkpoint.snapshot and tip.snapshot; its own age
may exceed max_age in this full API and its receipt consumers below; the
current signed tip supplies the age clock. Signature, completeness, cumulative retention, future-entry rules,
rollback continuity and strict increasing snapshot issuance are unchanged.

The proof has at most64 records and one checkpoint,8192bytes each,depth16,
532480bytes total. Old intermediate publications only prove complete global sequence and
same-head predecessor continuity (prev null on head change); they do not confer historical authority. The tip alone supplies
current freshness. Gap/rollback/fork refuses without advancing anchor state.
Returned ids name all supplied proof records, checkpoint and snapshot. Persist
the exact bytes, final anchor and watermark atomically before use. Refresh the
witness head at the caller's admission/effect boundary. An over-bound proof refuses on this default path.

For explicit long-outage recovery, call
`VerifyFreshnessReanchor(tip, checkpoint, ids, keys)` with one raw signed tip.
No normal refusal automatically falls back. Consumers may explicitly invoke
this sibling in their automatic recovery flow; it retains F1–F7, current
witness/tip currency and F9 revocation matching, replacing only publication
continuity with F8R. The anchor must name a real positive publication; current
registry_seq must not fall below it. Equal sequence requires identical
checkpoint id (which cryptographically commits the same head) and snapshot;
advance requires a different checkpoint. Tip publication_seq and issued_at
must both strictly advance, otherwise `freshness_rollback`.

On accept, `Plan.Reanchor` points to `FreshnessReanchorPlan`, serialized as
`reanchor` with `reanchored:true`, integer `skipped_publications` and
`old_freshness_id`, `new_freshness_id`, `old_checkpoint_id`, `new_checkpoint_id`.
The count is exactly tip publication_seq minus anchor publication_seq minus1,
including zero for explicit adjacent recovery. Normal plans omit this member;
all refusals return a zero plan. Persist new anchor, watermark and audit of
both endpoint heads via these ids atomically. This API does not verify skipped
publication consistency; the registry must retain complete untruncated history,
and witness/off-node heads and the audit record must permit later cross-check.
Snapshots stay cumulative and bound to checkpoint.snapshot, so recovery cannot
hide revocation, extend authority or cancel revocation. An unavailable witness
refuses every admission requiring current freshness. Live recovery integration
and durable audit/storage remain unqualified by the pure library.

Receipt composition is specified in §2.10 of the envelope spec. Successful
VerifyFreshness/VerifyFreshnessReanchor return `Result.FreshnessReceipt`, an
opaque immutable pointer omitted from Result JSON. No constructor or accepted
JSON decoding exists; direct receipt marshal/unmarshal and Present(receipt)
refuse. Zero, reflection-allocated and concretely copied receipts are invalid.
Only the original pointer can be shared concurrently. Audit returns detached
FreshnessAudit metadata; its bool means authentic origin, not current validity.

After atomically persisting the producer's admitted anchor, watermark and
re-anchor audit, attach the pointer as Context.FreshnessReceipt with the admitted
anchor, current witness/read/clock facts, and the same SignedSnapshots Evidence.
Consumers MUST keep one immutable SignedSnapshots Evidence for the receipt's
lifetime. Rebuilding it, even byte-identically, invalidates the receipt. Rebuild
on any snapshot or cumulative/rollback-safe premise change, including changes
later returning to the same ids/booleans. Run F again after snapshot changes,
premise changes, re-anchor or restart. `complete=true` does not prove cumulativity.

Receipt behavior is explicit for every verification entry point:

| Class | Entry points | Rule |
| --- | --- | --- |
| May waive bound registry-root own-age | VerifyAttestation (agent), VerifyMessage, Authorize, CheckRevocation, VerifyEnvelope where applicable | Validate R1–R3; waiver applies only to the bound registry snapshot actually used |
| Validate-only | VerifyAttestation(device=true), VerifyOperator, VerifyServiceAttestation | Validate R1–R3; operator-root and grant-root own-age stay mandatory |
| Outside receipt mode | VerifyJournal, VerifyFreshness, VerifyFreshnessReanchor | Ignore receipt-consumption fields and run their independent full contract |

For consumers and validate-only calls, RequireFreshnessReceipt refuses absence.
Nil plus false retains legacy own-age behavior. Any supplied receipt must
validate, even if own-age passes; there is no fallback. CheckRevocation's
explicit root must match. Service receipt validation runs after its first
trusted-time gate and before service validity continuation; it never renews
grant-root age. D42(a) is implemented only by the explicit /2 profile described below.

Outside-mode calls ignore FreshnessReceipt, RequireFreshnessReceipt and
FreshnessMarginSeconds even when supplied or invalid. VerifyJournal keeps
journal/checkpoint continuity and snapshot own-age checks; it cannot replace
those with a receipt. The full F producers require no earlier receipt and
cannot use one to skip proof verification; they independently mint a new one
only on full success. New stores Context without admission. Context-free
Present/Evidence.IsAvailable, OperatorRecordCode and receipt Audit/JSON methods
are not verification consumers: existing evidence/serialization rejection and
origin-only audit semantics remain.

R runs after existing trusted-time checks: presence/provenance/margin; exact
root/owner/snapshot/Evidence/witness/admitted-anchor/read bindings; then expiry.
The four codes are freshness_receipt_unavailable, freshness_receipt_invalid,
freshness_receipt_binding_mismatch and freshness_receipt_expired, preserved
through K1/G7/O2. CheckRevocation returns Unavailable plus the exact error;
VerifyAttestation and VerifyServiceAttestation return zero identity plus the
exact error. Result refusals
have zero Plan and nil receipt. Full signed snapshot and effective-entry checks
still run; a future-effective entry can become revoked before receipt expiry.

Expiry is fixed at mint: E=min(tip.issued_at+max_age, issuing WitnessReadAt+max_age).
Use requires max(now,W)<E-FreshnessMarginSeconds. Margin is0..60, default0;
newer reads never extend E. Read must be non-future and no earlier than at mint.
An F accept on its inherited inclusive age boundary can yield an already
unusable receipt. Receipt evidence grants neither Commit nor effects.

Real-F corpus fixtures carry signed mint inputs and consumer use contexts,
never serialized receipts. Focused tests (run under the host's heavy-work lock
when required) use ignored `.tmp/` for artifacts:

```sh
GOMAXPROCS=2 "$CURATOR_GO" test ./verifier -run '^TestFreshness' -count=1
GOMAXPROCS=2 "$CURATOR_GO" test -race ./verifier -run '^TestFreshnessReceipt' -count=1
```

The legacy TestFreshnessCompositionBoundary still covers optional-absence
own-age refusal and a current-snapshot control. Live consumer adapters,
cumulative publication, witness authentication and durable audit/effect
serialization remain external. D42 records the adopted offline-root currency policy; live integration remains external.

### Root currency profile 2

Set `Context.RegistryCurrencyVersion=2` explicitly;0/1 retains the exact legacy
behavior. Current /1 records refuse under pin2, with qualified retained /1
predecessor bytes allowed only as upgrade history. Protect the pin floor against
restore/old processes externally. No new method signature or network/storage API.

`Context.SnapshotJournal` is `Present(map[string]any{"anchor":...,"entries":[]any{rawEntryBytes,...}})`.
Anchor is the complete-prefix, owner-qualified object described in spec section2.7:
version2, registry_id,owner,registry_seq,registry_head,checkpoint_id,latest.
Rows are sorted per configured role with root_role,root_key_id,snapshot_id,
record_seq. Null/zero means proven absence, including all historical configured
roles. Explicit qualified genesis uses seq0/null head/null checkpoint; returned
state is positive and encodes strings for those endpoints. `IDJournal` resolves
every scanned add/revocation original and every non-null anchor original.
VerifyJournal uses its argument entries; F uses SnapshotJournal.entries.
Re-anchor never skips the complete journal prefix. Ordinary journal verification
retains checkpoint age; stale intermediate checkpoints cannot backfill a gap.

Checkpoint/2 and freshness/2 bind the same whole sorted list of1..3
`SnapshotBinding{RootRole,RootKeyID,SnapshotID}` values. Registry-owner mandatory;
grant/operator optional. All configured roles retain index rows even when omitted
from coverage. Derive latest monotonically using original cumulative snapshots;
re-adding current id keeps first record_seq, regressing re-add refuses.
Plan.SnapshotJournal is a detached version2 `*SnapshotJournalState` with
`[]SnapshotJournalEntry`; each entry's `*string SnapshotID` is independently copied.
Exact Evidence/state encoding, capacity accounting and Plan.IDs inventory are in
spec2.7; the whole-call charge cap is2MiB including64KiB metadata reserve, while
per-Evidence1MiB, per-record8192, journal64 and publication64 still apply.
All input size bounds, including the full D45 charge, precede current candidate
version preflight and closed-body parsing at J1/F1. Raw lengths plus retained
Evidence costs and the reserve determine the entire charge; no combined raw
slice or body parse is needed and no residual charge is deferred.
Canonical storage/staging ceilings16MiB/32MiB do not override smaller native limits.

A /2 receipt binds original SignedSnapshots AND SnapshotJournal Evidence identities,
complete set, derived index, version/pins and existing admitted/witness facts.
Keep both original Evidence objects after atomically persisting the derived index;
rebuilding either invalidates the receipt. Never serialize receipt authority.
A=min(included root max_age), never an omitted root. Fixed exclusive expiry,
non-extension by later reads and all effective revocation checks remain.
Each entry point waives only its reached covered root's own-age (spec2.10 table).
For a valid optional receipt missing a reached root, own-age runs in that same
invocation. Required missing coverage refuses even with fresh own-age. Invalid
supplied receipts never retry without the receipt. /1 classification is unchanged.

Audit adds registry_currency_version2 and a detached snapshots list; legacy
SnapshotID still means registry-owner. /2 re-anchor plans add detached old/new
sets and currency versions. New fields are omitted on /1, retaining its eight
original audit fields and plan bytes. A plan is a candidate transaction, not a
commit acknowledgment. Persist version/pins/index/endpoints/history/watermarks/
re-anchor audit crash-atomically before use and read the authenticated witness
for each admission outside the final serialized window. These consumer duties,
root-side intake checks, complete-history provisioning and activation are external.
No issuance-age withdrawal bound is claimed for external-root /2 currency.

## Unsigned owner-act signing preparation

`PrepareOwnerAct(body, arguments, OwnerActPreparationContext)` returns an
immutable unsigned `*OwnerActSigningPlan`. It accepts the full **original
canonical** body and separately received canonical complete A. It reuses
`owneracts.ParseBody`, `Parse`, `Map` and the existing record helpers, comparing
both original byte strings to the complete derived mapping. It never accepts a
caller digest/preimage/review as a substitute, produces a signature/envelope,
or calls consumer verification with synthetic authority facts.

Construct the four independent context values with `Present` and check errors:

| Evidence | Exact available in-process value |
| --- | --- |
| Enrollment | `{device,owner,installation,aud,epoch,issuer,root_catalog_id,profile_catalog_id,profile,profile_pin}`; all strings. `device` is the enrolled full P256 key, `owner` the exact nonempty owner (<=255 UTF8 bytes), `installation` the local trusted nonempty label (<=255 UTF8 bytes), `aud` and `epoch` exactly match the body. `issuer` equals the selected operator-root role. `profile` is exactly `owner-acts/1`. The two catalog IDs and profile pin are full lowercase content IDs. |
| InstalledProfile | `{profile,pin}` from independently authenticated installation/build metadata; exact supported version and enrolled/profile-catalog pin. |
| RootCatalog | The existing complete `{id,roles}` model. Roles contains exactly `service_root,agent_revocation_root,operator_root,root,commit_signing_key,enrollment_publisher,service_authority,service_attestations`, with the same nested values as the consumer catalog. Null optional roles explicitly mean unconfigured; an omitted member or unavailable catalog refuses. `operator_root` is required here. |
| ProfileCatalog | The existing complete `{id,profiles}` model, with all name-to-pin entries present. Names are nonempty <=255 UTF8 bytes; each pin is a full content ID. The selected `owner-acts/1` entry must equal both independently installed and enrolled pins; other valid entries are retained. |

These are protected snapshots, **not received request fields or a new policy
wire grammar**. The integration must authenticate the enrollment, eligibility,
installation/build pin and full catalog provenance before supplying them, and
must refuse unavailable/expired/conflicting source information. Received IDs are
lookup hints only. `Present` supplies immutable ownership and availability,
not proof of protected storage, installation provenance, currentness or rights.
There is no current/presence flag, callback, inferred expected field or automatic
pin/version fallback. Syntax and equality do not qualify an adapter. The
implementation uses the static `owner-acts/1` mapper/review code. The externally
authenticated compiled implementation pin is not defined by hashing a source
file containing its own hash; this API does not attest a native package pin.

Catalog key syntax and role separation are checked, including enrolled-device
separation from root/protocol/service keys. Service attestation bytes are
bounded and retained opaque; preparation does not verify those signatures or
make them current. Consumer rights, attestations/revocation, genuine `/2`,
time, presence, replay, critical coordination and effects remain independent.
No protected enrollment or policy store is written.

`plan.Snapshot()` returns `(OwnerActSigningData, true)` with fresh independent
copies of all byte slices and the original immutable selection snapshots.
Ordinary returned values are mutable, carry no capability and may be discarded.
Editing a snapshot cannot change a plan or another call. Nil and public zero
plans return zero data and false. A copy of a valid plan shares immutable state.
Inputs must remain stable during the call; unsafe concurrent mutation, native
handles, durable storage and GC zeroization are outside this API.

`Render` is unchanged profile delivered text. `Review` is the separate pinned
**`owner-act-review/1`** projection, with literal fixtures in
`testdata/prepare-{bind,unbind,mirror-enable}.review`. Its exact fixed headings
and order show profile/pin/class, independent installation/key/owner/audience/
epoch/issuer/catalog IDs, complete canonical body, complete canonical A,
computed digests/content ID, then the full profile text. Complete JSON retains
all member names, types, target/generation, metadata and values; hashes replace
none of them. All scalar section values, including complete JSON and act text,
are quoted and reversible. Visible ASCII U+0021..U+007E passes literally except
quote and backslash, encoded as `\"` and `\\`. Space, every control, DEL and nonASCII
Unicode scalar is spelled **`\u{HHHHHH}`**, exactly six uppercase hexadecimal
digits (`SPACE = \u{000020}`, `LF = \u{00000A}`, `é = \u{0000E9}`, `😀 = \u{01F600}`). A literal
backslash is doubled: literal input `\u{000000}` displays as `"\\u{000000}"`,
while NUL displays as `"\u{000000}"`. Invalid UTF8
refuses. Nothing normalizes NFC/NFD, whitespace, line endings or locale order.
Layout separators are LF; all data controls are visible escapes. Hashing and
the raw preimage always use original validated bytes, never review escapes.
Native integration must display these exact bytes as **plain literal text**,
with no Markdown/HTML/terminal interpretation, links, truncation or elision, and
pin the same renderer/version/fixtures. Go fixtures qualify no native view.

Bounds precede parsing/copying: provider body/A outer 8192, stricter complete
A 2048, existing body field limits, and existing `Present` 1 MiB per snapshot.
Display labels are bounded 255 bytes; full catalogs remain bounded snapshots
and are not expanded into display. Render 4096, raw preimage 12288, full escaped
review 65536 (all headings/labels/expansion included), and exact predicted final
one-approver canonical envelope 8192 are enforced before signing. Prediction
counts closed syntax and the 86-character canonical raw64 signature encoding;
it neither constructs a signature nor verifies/returns an envelope.

The strict body maximum is 2043 bytes; preimage is body+143 <=2186 and final
one-approver envelope body+305 <=2348. For widening, Render=body+A-70; narrowing
uses -69 with its shorter operation/body. The attainable overall Render maximum
is 4021 at body 2043/A 2048. Tests witness these maxima and the A 2049 refusal;
4096/12288/8192 are unreachable for eligible inputs under these tighter schemas.
For the review cap, a conservative upper bound is below 28000: complete body/A/
Render contribute at most 6638/4098/10753 bytes when overcounting nonASCII owner
expansion, selected owner/label at most 5104, and all other fixed headings/values
under 1400. Canonical JSON controls are already ASCII escapes and expand at most
2x; only owner (<=255 raw bytes) can contribute nonASCII in body/Render. This is
a conservative bound, not a claim of an attainable review maximum. The exact
65536 check remains in code. No eligible 65536-byte view is fabricated.

Both `confirmed=false` and `true` are preserved as proposed assertions. Neither
means a human confirmed or presence occurred. A later native provider must use
one stable complete review, explicit fresh confirmation, unchanged plan/
enrollment/pin/key/time and a single authorized signing attempt, accepting true
only on that explicit path and never editing the body after review. Signature
verification/finalization, native once/cancel/expiry lifecycle, storage and
consumer authority/effects are **not implemented by preparation**.

Failures return nil and `*OwnerActPreparationError` with a fixed local code:
`preparation_too_large`, `preparation_invalid`,
`preparation_selection_invalid` or `preparation_mismatch`. No received values,
partial view, native result or signature are returned. These codes are not
consumer E/O verdicts and existing verifier refusal ordering is unchanged.

Focused commands (Go build cache; test output/logs in caller-owned `.temp/`):

```sh
GOMAXPROCS=2 "$CURATOR_GO" test ./verifier -run '^Test(Prepare|APISurface)' -count=1 -v
GOMAXPROCS=2 "$CURATOR_GO" build ./verifier ./owneracts ./record
GOMAXPROCS=2 "$CURATOR_GO" vet ./verifier ./owneracts ./record
"${CURATOR_GO%/go}/gofmt" -l verifier/owner_act_prepare*.go
```
