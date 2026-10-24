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
registry, recovery, emergency-stop or identity-journal implementation.

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
manifest, all 1688 sweep byte hashes, all 669 named bytes and exact 2357
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
