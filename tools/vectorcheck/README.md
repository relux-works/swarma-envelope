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
