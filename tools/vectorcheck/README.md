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
format drift. All keys are public synthetic fixtures. Never send real acts or
secrets to a fixture directory.

The `signer` mode checks admissibility of full preimage bytes, with exact tag,
canonicality, 24,576-byte and depth-12 bounds. It does not execute a signer or
claim a signature was released. The `domain` mode checks exact tag bytes and
actual raw signatures independently of an envelope/body schema; external tag
rows qualify domain separation only, not the external service's admission.
Agent attestation verdicts and expected principal tuples are separate explicit
caller inputs. This tool tests how they constrain acceptance, not how an
unpublished Keymaker certificate format is cryptographically verified.

The generated T family sweeps wrong JSON types across every closed wire field
in message, grant, operator-act, signature, target and caveat records and the
closed grant request, including nested array entries and both operator target
forms. Each case pins its ordered structural refusal and empty plan. Opaque
argument children have no handler schema here; only the arguments object
container is typed. Typed caller provider/store snapshots are external evidence,
not wire records, and this family does not qualify their adapters. PR2 makes
explicit that accepting an envelope with an unexpected argument member does
not authorize dispatch.
