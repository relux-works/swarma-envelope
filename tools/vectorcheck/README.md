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
format drift. Default input contains 510 named semantic cases only. The complete
1737-case gate must generate the 1227 T/B/Z sweeps first:

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
all chain positions. Root provenance wins before device/agent classification.
C/PC covers actual delivery/text; A/PA covers signed evidence; Q/PQ covers
assurance attenuation/comparison and the unconditionally closed widening gate;
X adds every directed domain pair involving either new tag. Z checks the new
closed fields and evidence shapes. O05/O18 now return key_binding_unavailable
for missing device/root evidence, while PA6/PA7 prove no direct device key list
is required. A29 binds device owner to act/registration owner.

Signer-mode fixtures may enable `identity_check`; `multi_agent=true` always
enforces it. `caller_key_id` is the service-resolved attested active-generation
key id supplied as protected test context, not a new native request member.
The check reads only exact signed-record `key` and `body.author`, after canonical
admission, and compares both to that id. I/PI cases pin identity refusal causes
and demonstrate that role/action interpretation still belongs to the receiver.

V/PV cases cover device-owner bounds and availability across message approvers,
grant devices and narrowing acts: empty, 1 byte, 255 ASCII bytes, 255 multibyte
bytes, 256 ASCII bytes, 128 two-byte characters, signed/protected missing/null
and wrong types. Protected availability precedes signed-owner bounds. H/PH
cases cover independent principal strings/UIDs, snapshot age/entry bounds,
nonmatching invalid entries, protected delivery/act bindings and time decisions.
These cases qualify the oracle's comparison behavior; they do not qualify live
provider adapters or unspecified store cardinality limits.
