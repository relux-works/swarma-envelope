# Independent checker

Entry point: `python3 -B tools/vectorcheck/check.py`, repository root.
Optional fixture root: `--vectors DIR` (default `vectors`). Python standard
library implements the CCJ-1 codec and strict Ed25519 verification. P-256 uses
`cryptography` if present; the validated environment used version 46.0.5.
No packages are installed by this tool. Without that dependency P-256 is PENDING
and exit status is 2, rather than success. It prints per-row mismatches and exits
1 on a semantic failure, or 0 only when all supplied cases and pairings pass.

This is a conformance oracle for fixed offline inputs, not an importable public
verifier API. It does not consult the generator or generated verdict code.
Use the Go byte inventory check in addition to it to detect case removal and
format drift. Default input contains 908 named semantic cases only. The complete
2596-case gate must generate the 1688 T/B/Z/U sweeps first:

```sh
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -check
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all -check
python3 -B tools/vectorcheck/check.py --vectors .tmp/vectors-all
```

Run these commands sequentially through any host-required resource runner.
Materialized sweep cases have the same schema, ids, claims, expected codes and
positive controls as named cases; another implementation may consume that tree
directly. The checker derives verdicts from actual inputs, independently of the
manifest. The [generator guide](../vectors/README.md) defines manifest integrity. All keys are public synthetic fixtures. Never send real acts or
secrets to a fixture directory.

The `signer` mode checks admissibility of full preimage bytes, with exact tag,
canonicality, 24,576-byte and depth-12 bounds. It does not execute a signer or
claim a signature was released. The `domain` mode checks exact tag bytes and
actual raw signatures independently of an envelope/body schema; external tag
rows qualify domain separation only, not the external service's admission.
The oracle parses actual CCJ-1 attestation/1 and revocation/1 envelopes,
recomputes ids and verifies root signatures. Caller inputs are protected roots,
current typed active-generation bindings, time/continuity and exact delivery
context. There is no attestation-valid flag or direct operator-device pin.
Root/subject key custody and live evidence publication remain external.

The generated T family sweeps wrong JSON types across every closed wire field
in message, grant, operator-act, signature, target and caveat records and the
closed grant request, including nested array entries and both operator target
forms. Each case pins its ordered structural refusal and empty plan. Opaque
argument children have no handler schema here; only the arguments object
container is typed. Typed caller provider/store snapshots are external evidence,
not wire records, and this family does not qualify their adapters. PR2 makes
explicit that accepting an envelope with an unexpected argument member does
not authorize dispatch.

The B family preserves shape checks over signed agent records and protected
current principal projections: missing, null, other JSON types and invalid registration
numbers in message-author, delegated-issuer and grant-leaf-subject intake.
The inherited fixture builders retain private construction blueprints to keep
all original regression names and failure classes. Before export they construct
signed attestation bytes (including deliberately malformed/forged negative
records), signed snapshots and separate current-generation bindings; none of
those construction status flags is an oracle input. PM/M cases exercise pinned
owner roots, operator-root-attested devices and service-root-attested agents in
all chain positions. PM10/PM11 now refuse agent issuance; agent leaves remain
admissible. Root provenance wins before device/agent classification.
C/PC covers actual delivery/text; A/PA covers signed evidence; Q/PQ covers
assurance attenuation/comparison and the unconditionally closed widening gate;
X adds every directed domain pair involving either new tag. Z checks the new
closed fields and evidence shapes. O05/O18 now return key_binding_unavailable
for missing device/root evidence, while PA6/PA7 prove no direct device key list
is required. A29 binds device owner to act/registration owner.

Signer-mode fixtures may enable `identity_check`; `multi_agent=true` always
enforces it. `caller_key_id` is the service-resolved attested active-generation
key id supplied as protected test context, not a new native request member.
The check reads exact signed-record `key`, `body.author` and
`body.author_attestation` after canonical admission. The first two equal that
key id; the third equals protected `caller_attestation_id`. I/PI cases pin
identity refusal causes
and demonstrate that role/action interpretation still belongs to the receiver.

V/PV cases cover device-owner bounds and availability across message approvers,
grant devices and narrowing acts: empty, 1 byte, 255 ASCII bytes, 255 multibyte
bytes, 256 ASCII bytes, 128 two-byte characters, signed/protected missing/null
and wrong types. Protected availability precedes signed-owner bounds. H/PH
cases cover independent principal strings/UIDs, snapshot age/entry bounds,
nonmatching invalid entries, protected delivery/act bindings and time decisions.
These cases qualify the oracle's comparison behavior; they do not qualify live
provider adapters or unspecified store cardinality limits.

The generated U family checks refusal precedence with independent earlier-only,
bound-only and accepted-source controls. Run the documented full `-sweeps` gate
to include all 451 matrix cases. Three committed N-O1-unknown-* cases retain the
exact O16 signed unknown operation while separately invalidating protected
owner, epoch or target. They must return act_operation_unknown before any
act_binding_mismatch. See the [matrix inventory](../vectors/README.md#refusal-order-matrix)
for group counts, cross-row/within-row coverage and same-code limits.

Message author lookup is by the signed author_attestation content id. The
returned evidence is fully verified, including current binding, validity and
the separately scoped registry snapshot, before exact author/id comparison
(`author_attestation_mismatch`). W/PW and U-reference-* cover stable-key
substitution and ordering; T0619–T0628 cover the new member's wrong types.
Signer narrowing compares three exact paths and extends existing
signer_identity_* refusals; I-attestation-* retains positive PI controls.
W-assertion-wrapper / W-webauthn-signature distinguish schema from raw crypto
refusal. Purpose-5 and registry-root cross-signing both refuse at K1.

W-grant-subject-record / W-grant-subject-before-revocation retain the earlier
subject-key derivation refusal in grants; the late author/reference mismatch
code is message-specific.


Y-context-* cases qualify explicit refusal of absent protected members. Context
is checked at consumption: G1 request, E4 role policy, E6 known keys, K1 grant
root and signer facts, E8 id journal, O3 presence and O4 replay state. Unknown
configured tags remain domain_unknown in domain-only probes. Null decisions
already defined by earlier cases remain unchanged; missing members never leak
Python lookup/attribute exceptions. The fixture runner metadata (mode, input,
expected result and positive-control id) is the harness schema, separate from
protected context. This oracle does not implement live provider or journal I/O.

E6 follows the normative issuer/author match, allowed profile, message preimage
size/depth, then strict crypto order. Grant subject-point crypto runs in the
last stage, after issuer/profile admission. `N-E6-*` pairs isolate both earlier
refusals and the subject-only strict-crypto operands with valid neighbors.

Registry-format rows use independent `service_identity` and `identity_journal`
logic derived from spec §§2.6–2.8/6. Service attestations bind the exact grant
root with protected grant-service purpose/owner, never an unsigned profile
selection. The journal checks real checkpoint signatures and unsigned hash-chain
ids, the exact complete current snapshot and protected external witness facts.
Explicit null entry prev and projection predecessor are values, not missing fields; absent
witness still refuses. Fork and rollback are distinct ordered refusals with no
plan. `N-ORD-*` compounds extend the U ordering claims as named cases, leaving
inherited manifest bytes intact. New tag math remains separate from authority;
the message signer refuses both. No live witness, enrollment or paging protocol
is implemented. Over-capacity current domains keep the existing fail-closed
count/byte rules rather than accepting truncated snapshots.

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
