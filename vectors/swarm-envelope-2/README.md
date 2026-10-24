# Negative-first conformance witnesses

The normative contract is [the platform slice](../../spec/swarm-envelope-2.md).
`0-negative/` contains exact expected refusal codes and a `positive_control` id
under `1-positive/`. Every row has its own specific `claim`. Positive controls
prevent an always-refuse implementation from satisfying the examples.

Run from the repository root:

```sh
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -check
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all -check
python3 -B tools/vectorcheck/check.py --vectors .tmp/vectors-all
GOMAXPROCS=2 "$CURATOR_GO" vet ./tools/vectors
```

`input.envelope` and each `input.chain` element are canonical unpadded base64url
of exact received bytes, preserving duplicate members, lexical numbers, invalid
Unicode and whitespace limits. Chains are leaf first. `mode` selects envelope
mechanics, grant authorization, operator validation, message-signer input
admission or a domain-only signature probe. `fixture` supplies the
protected expected audience, key policy, time-provider outcome, durable watermark,
revocation snapshot evidence, id/replay lookups, exact binding and request.
`expected` pins the independently derived code and candidate persistence plan.
Every refusal has an empty plan. Acceptance returns ids and candidate watermark,
and an action id for an act; it is not a committed effect or storage receipt.
Signer-only acceptance returns the exact tag and preimage digest, not a
signature/effect receipt. Domain-only acceptance returns the configured tag
and verified key, not a consumer admission decision. Actual attestation and revocation envelopes are base64url bytes in fixture
maps (agent records addressed by the requested content id; devices by key id);
the checker independently verifies their root signatures, type/profile,
subject derivation, validity and current binding. `active_generations` is a
separate protected caller projection. `operator_attestations` contains signed
device records under `operator_root`, never device pins. Delivery context contains
actual room/to and base64url exact UTF-8 event text. Assurance is protected
request-bound evidence, not a member of the untrusted request. The offline
provider facts establish comparison behavior only, not live qualification.

The tools use the registrar's pinned CCJ-1 implementation only in the Go
generator. That public package fits directly; no local format fork is needed.
Python independently parses/canonicalizes and verifies strict Ed25519 using
prime-subgroup arithmetic, and P-256 with cryptography when available. Missing
cryptography reports PENDING and exits 2; it never reports full conformance.
No network is used by the checker. Go module resolution may download the pinned
public registrar dependency. Neither tool imports the future production verifier.

Only 797 named cases are tracked. All 1688 T/B/Z/U cases remain in the generator
and committed `sweeps.tsv` / `sweeps.sha256`; `-sweeps` materializes them for the
complete 2485-case check. See the [manifest format](../../tools/vectors/README.md).
Commands must run sequentially through any host-required resource runner.

Generator `-out DIR` writes named cases and the manifest; adding `-sweeps`
writes all cases. `-out DIR -check` compares every
expected JSON byte and refuses missing, changed or extra JSON files under the
two managed vector/key directories without rewriting. Python `--vectors DIR`
checks the copy's actual inputs and expectations; it does not import Go verdicts.
Use the Go inventory check alongside it: semantic checking alone does not prove
that a required case was not removed. Case counts/status are in the README.

To establish instrument sensitivity, copy `vectors` to a scratch directory,
flip one signature byte in positive PE1 without changing its expected accept,
then run both commands against that copy. The Go check must report PE1 byte
mismatch; Python must derive envelope_signature_invalid for PE1. Restore nothing
in the committed tree: make all plants in scratch. The checker checks real
signatures in the fixtures, not a boolean signature-valid input.

| Cases | Contract witnesses |
| --- | --- |
| E01–E45, PE1–PE7 | Parsing, canonicalization, ids, roles, domains, strict crypto, audience, provider/watermark availability, conflicting bytes, extra invalid signature, exact received-byte bounds, type/key-class profiles and actual signed preimage budget. E13 now rejects an agent approver at the profile gate; D43 separately proves cryptographic role binding. E27/E32/E35 exercise P-256 in the operator profile. PE2 is an Ed25519 agent control; PO1/PO2 cover P-256 operator keys. PE5 uses an Ed25519 author plus a operator-root-attested P-256 approver. E39 uses the operator lifetime bound and pairs with PO1. |
| G01–G37, PG1–PG8 | All delegation dimensions, root/leaf edges, 4/5 link boundary, time/caveats/watermark, revocation freshness/unavailability, registered actions, correlated targets and concrete request. |
| K01–K20 | Required attestation availability/validity, strict bytes/id derivation, purpose/class, active generation/owner/path/registration/epoch binding and three-outcome revocation, including grant issuers and subjects. |
| D01–D47, PD1–PD7 | Every directed pair among the original seven tags; X adds the two new tags, role/type mutation inside one message domain, exact case/space/CR rules. External rows prove tag/signature separation only; external body schemas are not simulated. |
| S01–S26, PS1–PS5 | Message signer accepts exactly swarma-msg/2, refuses grant/act/registrar/broker and unknown future-service tags, checks canonicality, exact size/depth boundaries and no envelope semantics. S07 uses a generic unregistered sentinel, not an invented signing-service witness tag. |
| R01–R12, PR1–PR4 | Review regressions for enum type safety, signed operator-only grant targets, unsupported broker names, key currency, presence currency and the envelope/handler qualification boundary. PR4 is a valid station grant alongside credential controls. |
| T0001–T0628 | Every other JSON type at each closed wire/request field, nested object and array entry across message, multi-signature message, populated-caveat grant, narrowing act and widening/account act. Exact ordered structural refusal and empty plan; caller provider/store snapshots remain typed external evidence. |
| J01–J15, PB1–PB2 | Attestation regressions: absent/null records and tuples, boolean/float/string/nonpositive registrations, missing required fields and malformed validity; empty/overlong/surrogate principal text; maximum safe integer and 255-byte text positive controls. |
| B0001–B0462 | Caller evidence and principal-tuple shape sweep in author, delegated issuer and grant leaf subject: missing/null and every wrong JSON type per required field, plus integral/fractional floats, nonpositive and unsafe registration numbers. |
| M01–M12, M19–M27, PM01–PM12 | Protected provenance matrix: root Ed25519/P-256, operator P-256 and agent Ed25519 in issuer, intermediate subject and leaf-subject positions. Valid provenance accepts for admitted profiles; PM10/PM11 refuse agent issuance; removed provenance refuses unavailable; non-current operator devices and contradictory algorithm/class claims refuse invalid. |
| I01–I21, PI1–PI5 | Caller-identity narrowing for message signing: exact key/author paths and byte comparison; foreign/disagreeing identities, missing/wrong types, aliases, duplicates, caller/policy unavailability and mandatory multi-agent enforcement. Role/action semantics remain receiver checks. Existing S21/S22 and PS2/PS3 bounds are unchanged. |
| O01–O18, PO1/PO2/PO4; PO3 now refuses | Exact consumer/binding/argument/epoch/key, single-use act, widening confirmation/provider facts, replay availability and record bound. |

These are bounded witnesses, not exhaustive property proofs or an implementation
of live effects. Provider confidence, signed-snapshot completeness,
protected pin custody, store availability and prior journal entries are explicit
external fixture facts. Persistent reservation, concurrency/crash recovery,
retention, caller argument validation, signature-provider qualification and live
consumer activation remain integration obligations. No surface table was supplied
for implementation coverage; this table maps the requested format witnesses,
not a production landing-gate surface or qualification claim.

The provenance matrix is independent of chain position and algorithm inference.
Each entry below is a correctly signed narrowing chain. Removing the key's
required provenance returns `key_binding_unavailable`; the three operator rows
also reject non-current authority as `key_binding_invalid`. Root P-256 controls
remain valid with non-current *device* facts, since their protected authority pin
is the applicable provenance. Every actual agent still needs its binding.

| Protected class | Delegated issuer | Intermediate subject | Leaf subject |
| --- | --- | --- | --- |
| Authority root Ed25519 | PM01 / M01 | PM02 / M02 | PM03 / M03 |
| Authority root P-256 | PM04 / M04 | PM05 / M05 | PM06 / M06 |
| Operator device P-256 | PM07 / M07 / M19 / M25 | PM08 / M08 / M20 / M26 | PM09 / M09 / M21 / M27 |
| Attested agent Ed25519 | PM10 / M10 / M22 | PM11 / M11 / M23 | PM12 / M12 / M24 |

PM entries accept except PM10/PM11, which now refuse `signature_profile_invalid`
for agent issuance (including an intermediate subject that issues the next link).
M01–M12 have removed provenance and refuse unavailable;
M19–M21 retain the device attestation but have non-current device authority and refuse invalid.
M22–M24 reject an Ed25519 key mislabeled by a device attestation; M25–M27 reject a
P-256 key mislabeled by an agent attestation.
A key may occur in multiple connected positions: a parent subject is necessarily
the next issuer. Envelope ids remain unique. No repeated-key ban is introduced.

| New cases | Ruling witnesses |
| --- | --- |
| C01–C14, PC1–PC4 | Required actual room/full recipient; exact text presence, UTF-8, lowercase digest and byte identity including empty text, newline and Unicode-normalization counterexamples. |
| A01–A29, PA1–PA7 | Actual signed issuer/profile/validity/binding evidence; 86400-second boundary, Ed25519 device refusal, revocation by attestation id or key, old-iat bypass refusal, unavailable/forged/foreign snapshots and future effective-from control, both root algorithms, attested devices without a direct key list, and the device/act owner join. |
| Z001–Z147 | Typed missing/null and wrong JSON types for every new attestation member, subject/binding field, room/to/digest and minimum-assurance member; unsupported A3 request assurance refuses unavailable. |
| Q01–Q06, PQ1–PQ3 | Minimum assurance level/presence equal-or-tighter delegation and request comparison in both directions. Widening refuses even with asserted confirmation/presence; narrowing remains the positive control. |
| X01–X32, PD8–PD9 | All 30 new directed cross-domain signature pairs, two own-domain controls, and message-signer refusal of both new domains. Combined with D there are all 72 directed pairs among nine tags. |

PO3 keeps its original case id but now lives under `0-negative`: no A3 provider
is qualified in v0. Old widening failure cases still exercise their earlier
specific refusals; their positive control is valid narrowing PO1. This does not
claim a widening success or a test-only activation path.

O05/O18 keep their original names and negative guarantees. Their evidence is now
missing device attestation / operator-root policy, so both return
`key_binding_unavailable`, replacing the old direct-key-list codes. PA6/PA7
accept root-attested devices with no direct device key list. A29 refuses a
valid device attested for another owner even when act and registration agree.

| Cases | Additional boundary witnesses |
| --- | --- |
| V/PV | Device owner byte-bound, required evidence/type and ordering regressions in message approver, grant device and narrowing act paths. Both inclusive bounds accept. |
| H/PH | Independent principal text/UID bounds; snapshot integer age, complete/rollback booleans, 0/64/65 entries and invalid nonmatching entries; protected time, delivery identifiers and act binding types/bounds. |

In a generated scratch tree, change one T/B/Z/U JSON byte without changing its
manifest, then run the generator with `-sweeps -out DIR -check`: it must report
the named case's byte mismatch. Restore that one scratch file, alter one
`sweeps.tsv` line and rerun: it must report `sweeps.tsv` byte mismatch. Changing
`sweeps.sha256` also fails comparison. The generator regenerates all sweep bytes
and the whole manifest before comparing; it never trusts a changed manifest to
supply expected bytes. No fixture file is rewritten by `-check`.

| Cases | Refusal precedence witnesses |
| --- | --- |
| N-O1-unknown-owner/epoch/target | Exact O16 signed input combined with each reported invalid protected binding; operation profile still wins. O16 and H-act-binding-* retain the two adjacent refusal controls; PO1 accepts. |
| U (generated) | 423 order-matrix cases: 271 original Cartesian combinations, 20 author-reference compounds, six additional within-row combinations, 126 operand controls, with PE1/PE5/PO1/PG1 accepted controls. 276 compounds distinguish order by code; 21 same-code compounds only establish the required refusal. |

The 1688 generated cases break down as T628/B462/Z147/U451; all are committed via
manifest and materialized on demand. The generator guide documents each group,
its representative bound columns and the earlier conditions it crosses.

| Cases | Content-addressed author and scoped issuer witnesses |
| --- | --- |
| W-substitute-*, W-only-newer, W-other-key, W-concurrent-substitute; PW-binding/PW-concurrent-* | Exact attestation identity despite stable keys, changed registration/master epoch, and concurrent same-generation attestations; no key-based fallback. |
| W-reference-*, W-expired-reference, W-revoked-reference; T0619–T0628 | Required canonical reference shape and full validity/revocation checks. |
| U-reference-* | Twenty combined-invalid cases place final reference equality after earlier envelope, time and attestation/revocation failures. |
| I-attestation-*; PI1–PI5 | Third signer path, aliases, all wrong JSON types, duplicates including decoded aliases, protected-resolution priority and mandatory multi-agent comparison. |
| W-agent-issuer; PM10/PM11 | Fully attested agent issuers are forbidden; other generic grant controls use a device issuer. |
| W-assertion-wrapper, W-webauthn-signature; PO1 | Closed entry schema and real WebAuthn construction refuse; raw-preimage signature by the same key accepts. |
| W-purpose5-snapshot/grant, W-revoker-attestation/scope/purpose/missing; PW-binding | Separately pinned registry revocation issuer, protected purpose and exact attestation-root scope. |
| W/PW-bound-* | Omitting snapshot stale at the publication deadline, containing snapshot effective, future from inactive before and effective at its boundary. |

| Cases | Exact signing-key binding |
| --- | --- |
| N02 / PN02 | Two admitted, validly attested agent keys; a valid signature by A over signed author B refuses `signer_unknown` at E6. The same author B signed by B accepts. |
| N02-grant / PN02-grant | A valid signature by the grant authority root over a leaf naming a different delegated issuer refuses `signer_unknown` at G2/E6. The exact issuer signature accepts. |

`operator-act/1` has no `issuer` or `author` member. Its signer-to-identity join
is the device attestation and owner binding at O2; existing A29 / PO1 cover a
valid device attested for a different owner and its valid neighbor.

| Cases | E6 ordering within grant-link admission |
| --- | --- |
| N-E6-issuer-before-subject-ed25519 / -p256; PN02-grant | A correctly signed issuer mismatch wins over an invalid, canonically encoded subject point: `signer_unknown` at G2/E6. |
| N-E6-profile-before-subject; PG1 | A matching issuer with a valid signature but a disallowed purpose-5 signing profile wins over invalid subject crypto: `signature_profile_invalid`. |
| N-E6-subject-only-ed25519 / -p256; PN02-grant | With issuer and profile admission restored, those same invalid points refuse `envelope_signature_invalid`; moving crypto later never removes it. |

| Registry-format cases | Contract and accepted neighbor |
| --- | --- |
| N-SVC-*; P-SVC-chain, PN02 | Explicit service identity; root→service(depth1, both rights)→agent(depth0, credential.lease), parent authority/narrowing, expiry/revocation and forbidden message/agent profile |
| N-JRN-*; P-JRN-genesis/suffix/retransmit | Unsigned hash-chain entries; registry checkpoint signature, exact current snapshot, protected witness, fork/rollback and every sequence/prev/time/head link |
| N-CAP-*; P-CAP-64/bytes8192 | At most64entries and8192received bytes independently; retained cumulative domain cannot be truncated or silently split |
| N-ORD-JRN-* and N-ORD-SVC-* | Named extensions of the U order matrix: J1→J2→J3→J4→J5→J6, evidence signature before required body fields, leaf evidence before later parent expiry |
| N-REG-domain-*, P-REG-domain-*; N-REG-signer-* | The38new directed pairs complete110pairs among11exact tags;2own-domain math controls; both registry tags refused by the message signer |

Journal entries reference original content ids, including registrar enrollment;
no registry signature substitutes for the offline publisher. Protected witness
facts are an interface boundary, not an implemented witness format/server. These
fixtures prove offline verdicts and candidate plans only; paging direction,
bootstrap, external continuity and deployment require separate qualification.

`P-JRN-reissue` and `N-JRN-reissue-old-snapshot`/`N-JRN-reissue-no-entry`
exercise D38 A's20-second unchanged-set reissue: actual new signed snapshot id,
its add entry and own checkpoint; old snapshot references and same-sequence
checkpoint replacement refuse. These do not qualify a publication scheduler,
witness intent/commit or publication-history completeness.
