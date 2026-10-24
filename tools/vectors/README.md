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
write command (`go run ./tools/vectors`) writes 559 named cases, the public keys
and sweep manifest/digest under `vectors/`; it does not materialize T/B/Z/U JSON.
`-sweeps` adds those 1660 cases (2219 total: 2122 negative, 97 positive).
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

The 1660 generated cases comprise T628 + B462 + Z147 + U423. U is stored in the
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

The original 14 groups use 70 bound columns and 56 earlier-failure controls to produce
271 Cartesian cases, six additional within-E7a cases and 126 operand controls:
403 original U cases. The added U-reference-* group crosses five earlier failures
with four valid-but-mismatched references (20 compounds): 423 U cases total.
Of 297 compound cases, 276 distinguish the earlier failure by a
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
