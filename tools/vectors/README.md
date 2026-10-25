# Deterministic vector generator

Go 1.26.0 or newer; run from the repository root with the selected Go binary
in `CURATOR_GO`. The pinned registrar CCJ package constructs valid signed
records. These are public synthetic keys and offline fixtures only.

```sh
# Check tracked named cases, public keys and the complete sweep manifest.
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -check
# Materialize the complete corpus for any independent checker.
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all -check
python3 -B tools/vectorcheck/check.py --vectors .tmp/vectors-all
# Narrow source validation.
GOMAXPROCS=2 "$CURATOR_GO" vet ./tools/vectors
```

Run commands sequentially through the host's required resource runner where
applicable. Logs and generated copies belong in ignored `.tmp/`. The default
write command (`go run ./tools/vectors`) writes 1157 named cases, the public keys
and sweep manifest/digest under `vectors/`; it does not materialize T/B/Z/U JSON.
`-sweeps` adds those 1688 cases (2845 total: 2663 negative, 182 positive).
The inventory check also rejects unexpected JSON under both managed trees,
including accidentally materialized sweeps when `-sweeps` is absent. Generation
does not remove obsolete files; remove only reviewed stale paths explicitly.

## Sweep manifest

`swarm-envelope-2/sweeps.tsv` is UTF-8, sorted by case id in ascending ASCII
order, with exactly one LF-terminated line per T/B/Z/U case and no header:

```text
id<TAB>expected_code<TAB>lowercase_SHA256_of_canonical_vector_bytes<LF>
```

`swarm-envelope-2/sweeps.sha256` contains the lowercase SHA-256 of the **entire**
TSV bytes, two spaces, `sweeps.tsv`, then LF. The manifest binds all ids and
expected codes, plus each case's complete claim, input, fixture, pairing and
expected plan via its byte digest. All inherited case ids/claims/verdicts are
preserved. Each generated JSON is consumable using the existing vector schema.

Canonical **vector-container bytes** mean the established generator fixture
encoding: Go `encoding/json.MarshalIndent(vector, "", "  ")` plus one LF.
Top-level fields are ordered `id,claim,positive_control,mode,input,fixture,expected`
(as declared in `Vector`); map keys are sorted by the JSON encoder, with its
standard string/HTML escaping and two-space indentation. Hash the emitted file
bytes directly. This is fixture serialization, distinct from protocol CCJ-1:
negative fixture inputs deliberately include floats, lone-surrogate tokens and
other invalid protocol values. Protocol bytes remain in their base64url fields;
canonicalizing those inputs would destroy the negative witnesses.

Even without `-sweeps`, `-check` reconstructs **all** cases in memory, computes
all sweep hashes and the manifest digest, then compares named bytes and both
manifest files with disk. It cannot be fooled by editing a manifest and updating
its digest: regenerated expected bytes are authoritative. With `-sweeps`, it
also compares every materialized sweep file byte for byte. Checks never write.

## Tamper controls

Work in a generated scratch copy. Change one byte in a T/B/Z/U case (for example,
inside its claim). `-sweeps -out DIR -check` must exit 1 and name that JSON byte
mismatch. Restore the one scratch file, change one TSV line, then repeat: it
must exit 1 and name the manifest mismatch. Restore it and repeat with a changed
manifest digest if desired. A green original copy is the positive control.

For independent crypto sensitivity, flip one signature byte in PE1 while
retaining expected accept. The inventory check must fail on PE1; the Python
checker must derive `envelope_signature_invalid` for PE1 and exit 1. Keep all
plants outside tracked files. These controls prove detection of these bounded
defects, not exhaustive resistance to every generator/checker defect.

## Refusal-order matrix

`order.go` constructs the U family after materializing the accepted source
fixtures. It alters actual signed evidence and re-signs changed bodies with the
synthetic issuing root. Each column is a representative independent bound/type
failure; each row is a compatible earlier failure. Expected codes are specified
by the pipeline in spec/swarm-envelope-2.md, never sampled from the checker.
Earlier-only and bound-only controls accompany each Cartesian group; the four
accepted source controls are PE1, PE5, PO1 and PG1.

The 1688 generated cases comprise T628 + B462 + Z147 + U451. U is stored in the
same byte-checked manifest, materialized by the existing `-sweeps` command, and
consumable by independent implementations. Three semantic regressions
N-O1-unknown-owner/epoch/target are committed separately. They preserve the exact
signed O16 input while invalidating the protected binding. O16 remains the
unknown-operation/valid-binding control; H-act-binding-owner/epoch/target remain
the known-operation/invalid-binding controls; PO1 accepts.

| Group / ordered row | Bound columns | Earlier conditions | Cartesian cases | Extra within-row cases | Operand controls | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| E7 | 3 | 3 | 9 | 0 | 6 | 15 |
| E7a | 6 | 2 | 12 | 6 | 8 | 26 |
| T1 | 4 | 4 | 16 | 0 | 8 | 24 |
| K1-header | 4 | 4 | 16 | 0 | 8 | 24 |
| K1-subject | 2 | 6 | 12 | 0 | 8 | 20 |
| K1-principal | 12 | 6 | 72 | 0 | 18 | 90 |
| K1-owner | 2 | 5 | 10 | 0 | 7 | 17 |
| O1 | 6 | 4 | 24 | 0 | 10 | 34 |
| O2 | 2 | 8 | 16 | 0 | 10 | 26 |
| G2 | 18 | 3 | 54 | 0 | 21 | 75 |
| G8 | 2 | 3 | 6 | 0 | 5 | 11 |
| K1-snapshot | 3 | 3 | 9 | 0 | 6 | 15 |
| O2-snapshot | 3 | 3 | 9 | 0 | 6 | 15 |
| G7 | 3 | 2 | 6 | 0 | 5 | 11 |
| K1-reference (controls reused) | 4 | 5 | 20 | 0 | 0 | 20 |
| K1-approver/reference (named controls reused) | 4 | 7 | 28 | 0 | 0 | 28 |

The original 14 groups use 70 bound columns and 56 earlier-failure controls to produce
271 Cartesian cases, six additional within-E7a cases and 126 operand controls:
403 original U cases. The added U-reference-* group crosses five earlier failures
with four valid-but-mismatched references (20 compounds). U-approver-* crosses
four such references with seven independent approver failures (28 compounds),
including missing/revoked evidence for the second distinct approver: 451 U cases
total. Its R-approver-only-* and R-reference-only-* operands and
PR-distinct-message/PR-two-approvers accepted controls are named fixtures.
Of 325 compound cases, 304 distinguish the earlier failure by a
different refusal code; 21 collide on the same required code and therefore
establish refusal behavior only, not observable internal order. The latter are
three T1 provider/authority combinations and 18 K1/O2 signature-vs-bound cases.

The columns cover protected audience (empty/overlong/nonprintable), each delivery
identifier (same three failures), malformed now/authority/watermark and expired
provider authority, protected/header root keys and content ids, subject key/byte
encoding, each signed/protected principal member, signed/protected device owners,
each protected act binding field/container, and concrete request identifiers.
All existing inclusive-bound positive fixtures remain in the full corpus.

Between-row witnesses include E3/E5/E6 before E7, E6/E7 before E7a, E7/E7a/E7b
before T1, E6/E7/T2 before K1, G1 before grant-link K1 admission, E8 before O1,
O1 before O2, G6 before G7, and G1/G3/G7 before G8. Nested evidence checks pair
missing outer headers with malformed header keys/ids, required body fields with
malformed subject/principal fields, strict root signatures with later fields,
and attestation admission with snapshot-header bounds. O2 also pairs missing
current authority with bad device owners. Within T1 provider trust precedes
watermark shape; within E7a the complete bounded room/recipient context precedes
either exact comparison; within O1 the operation profile precedes all six binding
columns. Operand mutations use separate fields, retaining both failures.

A malformed protected grant root cannot first fail at G7: earlier root/issuer
admission already rejects it. Its independent key bound is exercised at the
shared K1 header helper, while G7 varies the snapshot issuer, signature key and
content id under a valid protected root. Immutable time inputs similarly fail at
T1 before later snapshot checks. The matrix does not invent unreachable late
states or qualify live adapters, effects, storage, or provider continuity.

## Content-addressed author and revocation profiles

`content_review.go` adds W/PW semantic controls and I-attestation-* signer
controls. message/1 signs exactly one required author_attestation content id.
Fixture `attestations` maps the requested content id to the returned signed
bytes; the verifier independently checks that those bytes have that exact id,
subject and current protected binding. A wrong lookup response is untrusted.
`agent_attestation_ids` is the protected current-id selection for grant agent
subjects; message intake never falls back to it. Device evidence remains keyed
by device key id. `caller_attestation_id` is the signing service's independently
resolved current id for the third identity comparison. These are offline
interface fixtures, not new native signing request fields.

The purpose-5 root signs agent attestations only. Public synthetic test-7 is
the separately pinned registry revocation root; its protected configuration
includes purpose registry-revocation and exact attestation_root scope.
Operator snapshots keep their existing operator root. Generic grant controls
now delegate through a P-256 device; explicit agent-issuer witnesses refuse
the profile after evidence validation. PM10/PM11 now refuse rather than accept.
The B issuer evidence family retains an explicit agent issuer to isolate its
earlier evidence failures before that profile refusal. No inherited ID is lost.

W-webauthn-signature contains a real low-S P-256 signature over
authenticatorData || SHA-256(clientDataJSON), with a base64url content-id
challenge. Its construction bytes are included for independent recomputation;
PO1 is the same-key raw-preimage positive control. W-assertion-wrapper tests
the closed signature-entry schema. Snapshot-bound controls cover age at the
deadline and both sides of future from. Live publication, cumulative issuance
and rollback witness continuity remain separate issuer/adapter obligations.

`root_approver.go` checks all six pairs of the four distinct root roles across
message, act and grant intake (R-overlap-*), with PR-distinct-* controls.
Correctly signed purpose-5 device attestations and snapshots exercise the
service/operator overlap. Root-only grant controls reach policy admission first
at G7, whose invalid-policy code is revocation_invalid. M01–M06 retain their
missing-provenance refusal with an unused distinct fallback root. No inherited
verdict changes. Final message reference equality follows ALL approver evidence
and precedes E8; grant subject derivation retains its earlier position.

## Protected context availability

`context.go` adds Y-context-* missing/null/malformed neighbors for every
previously unhandled protected-context access: grant root, role policy, known
keys, id journal availability/state, grant request, replay availability/state,
signer-fact containers and widening presence, and configured domain probes.
Existing named controls are reused. Q06 has valid presence evidence but reaches
the closed O5 gate; PO1 remains its accepted narrowing neighbor. Eight order
compounds keep the context checks at their required rows. Mutations occur after
signed evidence construction, so construction cannot refill an absent input.
Availability-only interfaces refuse unusable state with their existing
unavailable code; missing/null is never a permissive empty set or default pin.

`N-E6-*` adds five named grant-link witnesses: two issuer/invalid-subject
compounds (Ed25519 and P-256), one disallowed-profile/invalid-subject compound,
and two subject-only operands. Each record is correctly signed after the subject
change. Existing PN02-grant and PG1 remain the accepted neighbors; no inherited
fixture or sweep expectation changes. These rows follow E6/G2 directly.

Registry-format construction lives in `registry.go`, independently of the
library and Python checker. `N-SVC-*`/`P-SVC-chain` cover service identity and
root→service→agent delegation, parent absence/depth, agent-profile substitution,
message refusal, parent expiry/revocation, widening and exact owner/purpose/key
binding. `N-JRN-*`/`P-JRN-*` cover unsigned entries, actual registry signatures,
current snapshot reference, exact six-field projection scope and externally verified genesis, fork, rollback, sequence,
prev, timestamp and final-head binding. `N-CAP-*`/`P-CAP-*` distinguish count and
full received-byte capacity;64unique short key entries can fit while64longer
record-id entries need not. `N-ORD-*` extends the U order matrix with named
service/J1–J6 compounds without changing inherited U sweep bytes. `N-REG-*`
adds38directed cross-domain pairs involving the two new tags,2own-domain math
controls and exact message-signer refusals:110directed pairs among11tags.
Witness tuples are protected interface facts only; no witness protocol, registry
service, consumer integration or paged snapshot implementation is simulated.

The freshness mode independently checks decided D38 B. `N-FR-*` and
`P-FR-*` cover registry-only signatures, exact snapshot/checkpoint/witness
bindings, missing/stale/future evidence, publication rollback/fork/gap/time,
complete history, count bounds, effective revocation and old-snapshot acceptance
only with current freshness. `N-ORD-FR-*` fixes F1–F9 precedence. Twenty-two new
directed domain mismatches complete132pairs among12tags; the message signer
refuses the new exact literal. Historical proof records are continuity evidence,
not historical admission; live publication completeness still requires issuer
and consumer integration. Inherited reissue journal fixtures remain generic
format controls for valid signed references, not the rejected option A policy.

Advancing journal proofs require the authenticated prior-head entry within the
64entry bound and exact prior checkpoint bytes in the protected id journal.
J5a verifies prior checkpoint id/root/scope/owner/seq/head without age and
compares checkpoint times; J6 requires the anchor before checking entry links.
Non-advancing exact witnessed checkpoint retransmission needs no prior bytes.
N-JRN-prior-* and N-JRN-anchor-* pin the refusals with accepted neighbors.

The explicit `freshness-reanchor` fixture mode selects the separate single-tip
recovery API. `P-FR-RA-*` supplies exact audit plans (same/higher head, zero skip
and safe-integer maximum); `N-FR-RA-*` preserves rollback, fork, current evidence,
cumulative snapshot and revocation refusals, paired with accepted controls.
`N-ORD-FR-RA-*` pins F6/F8 currency/F8R/F9 precedence. Normal freshness mode
still requires a complete bounded chain and emits no re-anchor member.

`P-JRN-publish-reissue` is the shared publication transaction: anchor E1,
E2 naming a real agent attestation, E3 naming a strictly later reissue of the
unchanged cumulative snapshot, checkpoint C3, exact prior C1 bytes and its
six-field witness projection. `N-JRN-publish-reissue-*` changes one input
aspect: old checkpoint snapshot (J3 `checkpoint_snapshot_invalid`), omitted
record/reissue entry (J6 `journal_chain_broken`), missing prior bytes (J5a
`journal_unavailable`), wrong prior bytes (J5a `checkpoint_invalid`), or
candidate time before prior time (J5a `journal_rollback`). Record references
remain publication evidence, not admission of the referenced authority.

`receipt` mode (`N-RC-*` / `P-RC-*`) carries `input.mint={mode,input}` with
real signed freshness/checkpoint proofs, the mint facts in `fixture`, and
`input.consume={mode,input}`. `input.use` patches current protected facts after
the admitted tip becomes the anchor. `attach`, `require`, `margin` and
`renew_evidence` select consumer policy and snapshot Evidence reuse/rebuild.
These are fixture adapter instructions, never a serialized receipt or a public
request grammar. Each runner verifies the entire F proof before creating its
private receipt; a failed mint returns that F refusal without a consumer call.
The generator computes expected plans from the consumer inputs independently
of the verifier. Byte-identical Evidence rebuild, fixed exclusive expiry,
future-effective revocation, re-anchor read requirements and other domain ages
have accepted neighbors. Direct Go tests cover pointer provenance and JSON.

Receipt consumer mode `service` invokes VerifyServiceAttestation directly with
the service key, compares an empty plan and exact zero refused identity, and
retains the grant-root snapshot own-age bound. It uses actual signed F mint
inputs and the existing immutable Evidence premise like other receipt modes.

Root-currency CU cases use the same commands and transport. The /2 oracle checks
original root signatures and derives the complete-prefix projection independently;
matching registry-signed lists alone never establish latest-root selection.
The supplied protected version selects /1 or /2 without negotiation. Both original
Evidence identities are modeled across receipt mint/use, and omitted-root coverage
runs its own-age check in the same call. Protocol and capacity details are in
[the platform specification](../../spec/swarm-envelope-2.md).
