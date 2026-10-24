# Pure verifier

`github.com/relux-works/waggle/verifier` implements the ordered platform v0
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
manifest, all 1688 sweep byte hashes, all 944 named bytes and exact 2632
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
may exceed max_age only in this full API, whose current signed tip supplies the
age clock. Signature, completeness, cumulative retention, future-entry rules,
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

Legacy `CheckRevocation`, message/grant/act and `VerifyJournal` methods keep
own-snapshot/checkpoint-age rules. This API does not produce a weaker Context
for them or convert its candidate plan into their effect authority. Consumers
must explicitly adopt this full registry-revocation contract; existing platform
consumer integration remains separate. Non-registry revocation domains keep
their current profiles. Run focused tests with artifacts in ignored `.tmp/`:

```sh
GOMAXPROCS=2 "$CURATOR_GO" test ./verifier -run '^TestFreshness' -count=1
GOMAXPROCS=2 "$CURATOR_GO" test ./record -run '^TestFreshnessDomain$' -count=1
```

Current API composition has a specific limit: a successful freshness plan is
not a revocation receipt accepted by `VerifyAttestation`, `VerifyMessage`,
`Authorize`, `VerifyOperator`, `CheckRevocation` or `VerifyJournal`. Each keeps
its own snapshot-age checks, so the natural sequence "freshness verifies an old
snapshot, then VerifyAttestation consumes that result" is unsupported.
`TestFreshnessCompositionBoundary` exercises the old-base refusal alongside a
genuinely current signed-snapshot control. An owner decision is needed for an
explicit composition API/policy before consumers can use option B for those
old-base checks. Do not fake a younger Context or implement a second verifier.
Re-anchor comparisons and `complete=true` do not establish snapshot cumulativity;
qualified rollback-safe cumulative-publication evidence remains required.
