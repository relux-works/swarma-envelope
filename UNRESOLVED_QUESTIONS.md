# Open decisions and adopted defaults

These defaults make the proposed v0 contract reviewable. They are not consumer
activation decisions. The normative details are in
[the platform slice](spec/swarm-envelope-2.md).

| Decision | Adopted default | Remaining decision / activation evidence |
| --- | --- | --- |
| D1 — relation to v5.2, settled | The accepted platform encoding is CCJ-1 plus domain tag; Keymaker is the first agent-message signer. SSHSIG/A1 remains a separate repository/offline proposal with explicit channel selection. | Encoding choice is settled; qualify the exact message provider/intake separately. No fallback or automatic A1 translation. |
| D2 — assurance, superseded by R2/R6 | Attested agent author gives A1 provenance only. A2 needs a person and concrete authorization; no A3 provider is qualified in v0. Carrier E2EE is another A1 mechanism, out of scope. | Owner decision, 2026-10-24: qualify a signer app and platform provider against a written threat model, plus hardware/provider attestation where provided. First target: one phone iOS Secure Enclave P-256 key. Widening remains closed until qualification; signatures/flags alone cannot establish A3. |
| D3 — grant encoding | CCJ-1 closed record; keys only; time-window-only caveats/v1; no counters, roles or rule language. Biscuit deferred. | A later reviewed version may extend the language; do not reinterpret this one. |
| D4 — root and revocation | Protected owner root pin; root-signed shared snapshot, complete and rollback-safe; configured maximum age required, at most 60 seconds. Current mode has no deployed owner registry; D32 defines its future boundary. | Approve the freshness ceiling; qualify external rollback witnesses and restore fencing. |
| D5 — terminal fallback | Unsigned authentication creates no operator-act/1. Consumers may separately authorize unsigned narrowing. Persistent Keymaker revoke has no such path; widening always needs a signed act and confirmation. | Publish any separate narrowing fallback in its consumer, without weakening this format. |
| D6 — ownership | waggle owns format and future pure verifier; consumers import a reviewed pinned main commit. | Publish the library API in the next slice, then review consumer pin/integration changes. |
| D7 — action registry | Closed `credential.lease`, `agent.spawn`, `message.deliver`; no dynamic namespace registration. Targets are typed correlated tuples; only trailing `/*` in grant ids. | Approve vocabulary/versioning and any additional action profiles. Message delivery grants never authorize arbitrary execution. |
| D8 — generation subjects | No roles or `agent:` subjects in the general v0 slice. | Publish a versioned broker/dispatcher generation-to-key adapter before replacing generation-bound bindings. Do not discard generation checks. |
| D9 — signature construction | One fixed message tag `swarma-msg/2`; general grant and act tags outside that namespace. Id hashes tag + LF + CCJ-1(body); signing input is tag + LF + CCJ-1({body,key,role,version}). Type is inside body. | Review exact signed-record schema and new tag literals. No old draft tag aliases or prefix acceptance; broker signatures must be re-created. |
| D10 — state and retry | Pure verification returns a persistence plan. Caller atomically reserves act id and advances durable watermark before effect; identical act reuse refuses. Outer consumer request retry may return an already committed outcome. | Qualify crash/concurrency integration and rollback-resistant journal retention. Offline fixtures do not prove durability. |
| D11 — Keymaker Q7 | Exact opaque object mapping and refusal translation in §4.2; positive safe integer registration numbers remain integers; semantic epoch maps to native master_epoch. | Format proposal alone closes no runtime gate: library, device signer, clock/revocation and durable journal integration remain required. |
| D12 — broker transition | R1 remains unchanged in broker v0. Later adapter re-signs, maps ids/revocations, replaces bindings, accepts both roots only for a bounded interval. | Publish exact migration/binding version, transition bounds, generation adapter and reconciliation evidence. |
| D13 — time | Use shared time-policy provider and stricter-only protected policy, with max(now,W) for expiry and min(now,W) for starts. No new clock source. | Pinned time-policy proposal must land and consumers must qualify continuity, watermark durability and provider activation. |
| D14 — carrier | Completed bytes carried unchanged; no transport-specific authority. | Transport owner must publish actual Matrix event budget and authenticated bounded pointer form if needed. No pointer wire schema is invented here. |
| D15 — size and retention | 65,536 bytes/envelope, 8,192/operator record, depth 16, chain 4; message signing preimage <=24,576 bytes and signed-record depth <=12. Consumed ids survive admissible replay/restore horizons. | Consumers must publish/qualify retention horizons and the complete native request budget. Time expiry alone cannot erase recovery evidence. |
| D16 — key types and roles | Settled: agent keys Ed25519, operator device keys P-256 low-S. Agent author only; delegate has no v0 profile. Optional message approvers use P-256 device keys attested by the pinned operator root, never agent keys. | Review optional message-approver policy; it does not replace an operator act or automatically establish A3. |
| D17 — exact tag registry | Twelve pairwise distinct published literal tags (including the D34 registry formats and decided D38 freshness); generic witness placeholder assigns no tag. Exact first-LF comparison, ASCII 0x20–0x7e, length 1–96; prefix uniqueness is not required. | Signing service publishes its witness tag by a later reviewed registry change. No other tag is admitted to the message signer. |
| D18 — message signer budget | Provider checks length, exact message tag and canonical CCJ-1 remainder (including codec bounds), with the permitted caller-identity narrowing in D22, then signs original bytes. Base64url + <=4096 bytes metadata leaves a total frame <=36,868 bytes with header. | Native owner must publish the actual request grammar and enforce metadata/depth budgets; no field names or Keymaker implementation are invented here. |
| D19 — superseded by R3 | S0 now defines and verifies root-signed CCJ-1 attestation/1 and shared revocation/1. No caller attestation-valid flag or direct device pin. Missing/null remains unavailable; wrong types remain invalid. Root provenance wins in every grant position. | Issuer publication/custody, protected active-generation evidence, snapshot continuity and consumer integration remain external activation gates. |

| D20 — target/schema qualification | E2 rejects operator-only targets in grants/messages. G1 validates the complete request type/member schema; G8 validates concrete identifiers. Consumer handler schemas and authority gates remain mandatory after envelope-only acceptance. | A later adapter must explicitly map unsupported broker names such as `claude_code`, reject collisions and reissue grants; no implicit normalization. |
| D21 — operator currency | Current root-attested device authority and revocation are mandatory for every act; presence-enrollment currency is a separate widening-only gate. | Qualify both evidence sources independently; narrowing without presence enrollment claims no A3. |

| D22 — signer identity narrowing | A provider MAY compare exactly key and body.author to its resolved caller key id, and body.author_attestation to its resolved current attestation id; multi-agent providers MUST. Missing/wrongly typed paths refuse, with no aliases/fallbacks. No other body interpretation; receiver checks remain mandatory. | Keymaker owns caller resolution and attestation validation. Owner decision, 2026-10-24: receiver binding first; any additional signer-side generation check is a separate later change. No fourth path or further body interpretation is claimed. Stable 24,576-byte/depth-12 bounds remain shared; no native request fields are invented here. |

No deployed owner registry, phone enrollment protocol, production verifier, migration
executable, Matrix pointer grammar or consumer activation is delivered by this slice.
All vector inputs are synthetic public test data.

## Curator decisions, 2026-10-23

These rulings are DECIDED and supersede conflicting defaults above.

| Ruling | Decision | Remaining activation boundary |
| --- | --- | --- |
| R1 — DECIDED, 2026-10-23 | Required signed room/to (opaque printable ASCII, 1–255 bytes), required lowercase body_sha256 of exact delivered UTF-8 text, empty text defined. iat/exp <=120 s. Exact Matrix content key works.relux.swarm.envelope; signature list retained. | Transport owns event budget, exact carrier-id resolution and authenticated pointer form. |
| R2 — DECIDED, 2026-10-23 | Attested agent author provides A1 origin; peer content remains data, grants no session approval or critical authority. E2EE is another A1 mechanism outside scope. | Consumers still enforce concrete authority. |
| R3 — DECIDED, 2026-10-23 | Root-signed attestation/1 and revocation/1 with exact new domains; purpose-5 service root, swarma-msg Ed25519 author, UID/generation/registration/master epoch/owner/path, agent lifetime <=86400 s. Operator devices attested by pinned operator root; signed revocation snapshots <=60 s, key/id entries effective from stated time. Typed missing/invalid and position-independent provenance retained. | Live issuer/publication, current generation, rollback continuity and root rotation remain separate. Matrix-master/OMEMO attestations deferred. |
| R4 — DECIDED, 2026-10-23 | Operator devices P-256 low-S only; roots Ed25519 or P-256 low-S. | Ed25519 FIDO devices deferred to a separately reviewed profile. |
| R5 — DECIDED, 2026-10-23 | Required grant min_assurance {level:A1/A2/A3,presence:boolean}; child equal/tighter only. Separate established-request comparison and refusal step. | Protected request-bound assurance provider, no self-assertion; A3 constraints remain dormant in v0. |
| R6 — DECIDED, 2026-10-23 | No qualified A3 signer provider in v0. Otherwise-valid widening always returns act_a3_inactive. Narrowing and Keymaker persistent revoke stay supported. | Owner decision, 2026-10-24: qualified signer app and platform provider with a written threat model, plus hardware/provider attestation where provided. First profile to qualify: one phone iOS Secure Enclave P-256 key. Qualification and reviewed activation remain required. |
| R7 — DECIDED, 2026-10-23 | Historical signature verification is outside v0. Current effective revocation cannot be bypassed with an old claimed iat. | Current-time/effect serialization remains mandatory. |

## Content review decisions, 2026-10-24

These decisions are DECIDED and supersede conflicting earlier defaults.

| Decision | Status and adopted contract | Remaining boundary |
| --- | --- | --- |
| D3 | DECIDED: closed CCJ-1 grant encoding, keys only, time-window-only caveats/v1. | Extension needs a later version. |
| D4 | DECIDED: protected root pins, complete cumulative signed snapshots, rollback continuity, configured maximum age at most 60 seconds. | Qualify publication, external continuity and restore fencing. |
| D5 | DECIDED: unsigned authentication creates no act; persistent revoke requires its signed narrowing act. | Consumer-specific separate narrowing fallbacks cannot weaken this format. |
| D7 | DECIDED: closed credential.lease, agent.spawn, message.deliver vocabulary and typed correlated targets. | Additional profiles require versioned review. |
| D8 | DECIDED: no role or agent: grant subjects; keys only. | Generation-to-key consumer adapter remains required. |
| D23 | DECIDED: message/1 requires signed author_attestation; content-id lookup, full author and EVERY approver evidence verification, then exact author/id equality at the end of K1 before E8. | Binding prevents substitution; it does not prove creation time beyond the message window. |
| D24 | DECIDED: agent keys cannot issue grant/1 in v0; subjects/leaves remain admissible. | Agent-issued grants require the same signed attestation binding in a later version; no new signing-service language is enabled. |
| D25 | DECIDED: D22 narrowing extracts exactly key, body.author, body.author_attestation; compares to protected caller key and current attestation id. Existing signer_identity_unavailable/malformed/mismatch codes are extended. | Signing service owns resolution and full attestation validation, with no aliases or absence equality. Owner decision, 2026-10-24: no further signer-side generation check is included; that is a separate later change after receiver binding. |
| D26 | DECIDED: operator devices produce raw P-256 low-S signatures over the exact preimage. WebAuthn/FIDO assertions refuse. | A separate WebAuthn proof profile is a future slice, with its own tag/record. |
| D27 | DECIDED: snapshot-only revocation bound is first-containing issued_at + configured max_age for an effective entry, never before from; future entries use max(issued_at+age,from). Nothing is covered before signed publication. Cumulative retention, unique increasing issuance and continuity are mandatory. | D29 defines completion; concrete durable barriers, acknowledgements and online effect integration remain activation gates. |
| D28 | DECIDED: purpose-5 root signs only agent attestation/1; a separate registry-owner root signs agent revocation/1, with protected registry-revocation purpose and exact attestation-root scope. Operator-device snapshots keep the operator-root rule. | Signing-service binding revoke is authoritative; snapshots distribute it. Root custody/publication and continuity still require qualification. |
| D29 | DECIDED — owner decision, 2026-10-24: revocation completes only after a defined set of durable barriers and acknowledgements, or proven expiry of all previously admitted authority. Before completion only bounded propagation lag is permitted (snapshot bound S+A, or max(S+A,from)); after completion no admission window for the revoked right remains. Critical effects selected by consumer policy require an online authority-owner check immediately before the effect; unavailable refuses. | S0 defines the requirement and abstract OnlineAuthority.Check interface only. Concrete barrier/acknowledgement set, expiry proof, protocol and network mechanism remain activation gates; no completion latency or live guarantee is qualified offline. |
| D30 | DECIDED: purpose-5 service, registry-owner revocation, operator and grant-owner root roles use pairwise distinct keys. The operator root attesting devices and signing its snapshots is one role. D33/D37 extend the explicit role table with grant-service subjects, offline publisher and repository commit signer; no cross-role overlap is allowed; reject before signed evidence intake at K1/O2 (key_binding_invalid), or G7 (revocation_invalid). | Protected root provisioning and rotation must preserve distinct roles; no existing consumer exception is required by this slice. |
| D31 | DECIDED — owner decision, 2026-10-24: separately held, pre-attested recovery means can only replace or revoke the operator root. Next form: two of three custodians. | S0 defines no recovery record/tag; v0 refuses root replacement/recovery authority claims. A future reviewed type/tag and policy must support a threshold form; neither the up-to-eight-signature envelope nor root policy may assume a single recovery signer. Custody, attestation and recovery activation remain separate qualification. |
| D32 | DECIDED — owner decision, 2026-10-24: owner registry and rollback witness share a separately administered trust node outside the agent platform's administrative domain; no platform administrative access or agent root access. Registry exclusively stores, orders and publishes keys, attestations, grants, revocations and identity journals without re-signing content. Its D30 key signs only revocation/1, identity-journal checkpoints and freshness/1; original content roots stay distinct. Registrar enrollment/1 retains its offline publisher Ed25519 key; registry stores/serves but does not sign it online without a separate registrar decision. Admissible currency remains within60seconds, subject to stricter policy: legacy own-snapshot issuance, or full decided D38 B signed freshness plus fresh authenticated head read for an unchanged base. | Until deployment, pinned roots and caller-supplied snapshots remain unchanged; unavailable required evidence refuses. Registry-key compromise alone cannot mint grants or attestations, but may withhold/delay visibility subject to the snapshot bound and continuity rules, with no pre-publication guarantee. Future emergency stop must work without registry availability/fresh snapshots; restart needs separate current authority. The D34/D35 registry-format defaults define the CCJ-1 types/tags, hash chain and registry-signed checkpoint/witness-fact interface; witness wire/server format and deployment remain external. Git is storage/transport, never chain authority. Registry and witness on one node are one failure domain: separate processes, accounts and streams, no registry-writer append access to witness streams, trusted witness checkpoint outside the node, and node loss fails consumers closed. Deployment, continuity, emergency-stop and journal qualification remain external. |


## Registry-format defaults for content review

These extend the explicit S3 profiles; they do not activate a registry, witness
or consumer. Existing D24/D28/D30/D32 restrictions remain except the new
expressly described grant-service and checkpoint languages.

| Decision | Proposed default | Remaining owner decision / qualification |
| --- | --- | --- |
| D33 — grant-service identity | Ed25519 service class, purpose grant-service, author/grant.sign only, owner binding and <=86400 s attestation. Existing grant root attests it only with explicit protected grant-service purpose/owner. Existing grant-owner snapshots revoke service keys/attestations and delegation links. No agent issuers; complete parent authority and narrowing still mandatory. | Approve same-root protected-purpose use instead of a fifth attestation root and this minimal algorithm/lifetime profile. Live custody/issuance/delegation remain unqualified. |
| D34 — journal records and tags | Unsigned version/body/id journal-entry/1; signed registry-author checkpoint/1; exact swarma-registry journal-entry/1 and swarma-registry checkpoint/1 tags. Field registry is the owner-registry key id; original draft field names otherwise retained. Bounded64entry anchored suffix, 8192bytes/record, depth16. No journal signature and no online enrollment re-signing. | Approve tags, bounds and suffix API; referenced signed records still need their own verification. |
| D35 — witness and fork interface | Caller supplies exactly the already verified head projection `{registry_id,owner,registry_seq,registry_head,checkpoint_id,previous_checkpoint_id}`. Positive safe seq; scoped root/owner; content-id references; null predecessor only for externally authorized genesis. No witness wire parser or seq0 bootstrap. Missing is journal_unavailable, malformed journal_witness_invalid; equal seq/different head OR checkpoint id is journal_fork; lower seq journal_rollback. Both at fields use exact §2.1 time, copied verbatim externally. | Witness authentication, predecessor ancestry, genesis authorization, fresh head reads, external storage and update protocol remain externally qualified; the six-field fact supplies no timestamp. |
| D36 — snapshot capacity | Choose future paging under one complete signed head; implement only the direction plus fail-closed current count/byte bounds in this slice. Never truncate cumulative history or silently repartition. Existing single-snapshot domains remain unchanged. | Review page/head format, completeness, cumulative retention, issued_at/freshness/rollback bindings before any paging implementation; Merkle proofs and narrower-domain migration deferred. |
| D37 — commit signer separation | Separate protected commit-signing role, distinct from all protocol roles and enrollment publisher; publisher also distinct from registry. No record admission by commit signatures. Compare present roles before evidence; unused new roles need not be configured for inherited intake. | Approve stricter all-record-role separation, provision distinct keys and qualify repository custody; git layout remains informative. |

### D38 — DECIDED B: separate signed freshness

Owner decision, 2026-10-24: B is the selected protocol (§2.9), with a separate
registry-owner-signed freshness/1, not revocation/2 and not an optional
revocation/1 member. Its closed body is
`{type,registry,owner,publication_seq,prev,issued_at,snapshot,registry_seq,checkpoint_id}`.
The exact new tag is `swarma-registry freshness/1`. Unchanged snapshot bytes
retain their id; only the complete current signed freshness + exact checkpoint
binding + fresh authenticated witness-head read can extend their age. A changed
snapshot needs a new journal entry/checkpoint and matching freshness; old
freshness cannot renew it. Missing/stale evidence refuses; same publication seq
with different binding/id is fork. Cumulative entries, completeness and
publication-sequence continuity remain mandatory. See F1–F9 for exact codes.

| Option | Disposition and cost |
| --- | --- |
| B — DECIDED | Separate freshness record per unchanged reissue. At20s:4320 signed freshness positions/day, without unchanged-set journal/checkpoint/witness intent/commit growth. Globally increasing publication_seq, same-head predecessor (null only first after head) and strictly increasing issued_at, exact snapshot/current checkpoint references, protected max_age and fresh authenticated witness read are mandatory. Changed revocation state still advances the identity journal/checkpoint. Publication availability/completeness and effect serialization need live qualification. |
| A — rejected alternative | Each unchanged reissue would create its own journal entry/checkpoint and witness intent/commit:>=4320 journal/checkpoint positions and8640 witness positions/day at20s (1440/day at60s). Retained only as comparison, not current publication policy. Generic inherited journal fixtures remain valid record-format controls. |

### D39 — required journal anchor and prior checkpoint (decided by default; review)

The six-field witness fact has neither prior entry nor prior checkpoint time.
Earlier optional-anchor suffixes could not order the first new entry against
its predecessor, and prior checkpoint time was not checked. The default now
requires the authenticated prior-head entry for EVERY advancing suffix,
counting it within64 places, plus exact signed prior checkpoint bytes from
the protected id journal under witness.checkpoint_id. Verify prior id/root/
scope/owner and seq/head against the witness, without current-age admission;
then compare candidate.at>=prior.at. These two distinct prior records prove
the two time relations. No timestamp member is added to the witness fact.

| Consumer requiring global entry-time order | Required input/check before acceptance |
| --- | --- |
| Registry intake | Supply the exact authenticated prior-head entry and id-journal prior checkpoint; compare first new entry.at to anchor.at and candidate checkpoint.at to prior checkpoint.at. |
| Witness bridge | Supply both authenticated prior records in its registry proof before intent/resolution; the six-field projection alone is insufficient. |
| Any consumer comparing journal entry times | Obtain both exact authenticated prior records before advancing; missing evidence refuses, never substitutes an unverified timestamp or extra projection member. |

J5a refuses missing prior bytes as journal_unavailable, invalid/mismatched bytes
as checkpoint_invalid, and backward checkpoint time as journal_rollback. J6
adds journal_anchor_required before per-entry validation. Non-advancing exact
witnessed checkpoint retransmission requires no prior bytes. Checkpoint.at is
still exact §2.1 time copied verbatim externally. No live witness wire or
consumer implementation is added. The spec owner reviews this narrowed default.

Twelve inherited fixture inputs change to supply the required evidence; all
inherited verdicts stay unchanged: N-JRN-entry-id,seq-gap,time-backward,
time-after-checkpoint,entry-owner,entry-registry,chain-prev,final-head and
P-JRN-genesis,entries64,suffix,reissue (each suffix is its full prefixed id).
The suffix/reissue positives now include their required entry anchor; the
suffix still omits genesis and demonstrates bounded continuation; its accepted
plan names the resulting new checkpoint id. No other inherited plan changes.
Replaying the unmodified twelve historical inputs now returns
journal_unavailable because they omit the newly required prior checkpoint:
the four old positives previously accepted; the eight old negatives previously
reached their specific entry/chain refusal. This intended contract narrowing is
separate from preserving the repaired canonical fixtures' expected codes.
Adding prior checkpoint bytes alone still leaves the old anchor-less suffix
and reissue forms refused at journal_anchor_required.

### D40 — freshness verification interface defaults for review

Use one new `VerifyFreshness(chain,checkpoint,ids,keys)` entry point returning
exact code/zero-refusal plan, rather than weakening legacy `CheckRevocation`
age checks. New protected Context values are FreshnessAnchor (exact eight-field
last-accepted publication projection) and WitnessReadAt (fresh authenticated
read timestamp). Existing JournalWitness stays the exact verified six-field
head fact. Explicit scoped publication-genesis provisioning may use anchor
publication_seq0/null id/null time but still pins the positive authenticated
registry checkpoint and snapshot; absence never initializes state.

Proofs are oldest-first, <=64 signed records plus one checkpoint,8192bytes each,
depth16,532480bytes total. Every historical proof signature/link/time/reference
transition is checked; only the tip supplies current freshness. References do
not re-admit historical checkpoint/snapshot bodies. Caller must establish the
current head's verified ancestry and cumulative snapshot publication; unavailable
history refuses on this default path; explicit D41 recovery is separate. Positive retransmission is byte-identical.
A successful plan names proof ids followed by checkpoint/snapshot and watermark;
caller atomically commits exact bytes and final anchor before effect admission.
These bounds, explicit genesis provisioning and exact projected-state/read-time
interface need content review; live storage/read/consumer integration is not
implemented or qualified by offline format tests.

### D41 — explicit freshness re-anchor recovery

Use sibling `VerifyFreshnessReanchor(tip,checkpoint,ids,keys)` with a single tip.
Normal `VerifyFreshness` stays the default and never falls back on failure.
Consumers may automatically request this sibling after an outage exceeds the
bounded chain, or explicitly choose it; the distinct call makes the continuity
waiver reviewable and auditable without silently changing inherited verdicts.
All current tip/checkpoint/snapshot/signature/witness gates remain mandatory.
Require a positive retained publication, nondecreasing registry_seq (equal
requires identical checkpoint-bound head and snapshot), then strictly greater
publication_seq and issued_at; rollback/fork refuses. Genesis stays normal.
The optional plan `reanchor` contains explicit true `reanchored`, exact integer
`skipped_publications=T.publication_seq-A.publication_seq-1` including zero,
and old/new freshness and checkpoint ids. Persist the new anchor, watermark
and skip audit atomically. Checkpoint ids bind both endpoint heads. Registry
history retention, off-node/witness cross-check and consumer audit compensate
for lost skipped-segment freshness-fork detection (§7); no revocation or
authority relaxation. Witness outages fail closed. No live integration is
implemented or qualified by these offline fixtures.

Open consumer integration decision: the current API cannot compose old-base
freshness acceptance into `VerifyAttestation` or the other entry points that
independently require own-snapshot age. `TestFreshnessCompositionBoundary`
retains the refusal and a genuinely current signed-snapshot positive control.
An owner decision must select and review an explicit composition API/policy;
no consumer may fake a younger Context or implement a second verifier. The
pure recovery and publication fixtures do not resolve or qualify that
integration. See §7 for the current boundary and cumulative-publication premise.
