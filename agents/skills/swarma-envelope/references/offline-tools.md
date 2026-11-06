# Existing offline conformance tools

Use these commands only when offline corpus work is actually requested and
execution is authorized. They are reference commands, not required skill-loading
steps or evidence of a run. Work from the repository root with an already
selected Go 1.26+ binary in `CURATOR_GO`. Respect the host's resource runner.
Use caller-owned ignored `.tmp/` for generated corpus/logs; do not generate over
the tracked fixtures during ordinary usage.

```sh
# Compare committed named cases, public test keys and the sweep manifest; no writes.
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -check
# Materialize full offline fixtures in scratch, then compare that same inventory.
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all -check
# Independent legacy-corpus checker, using an already provisioned Python environment.
python3 -B tools/vectorcheck/check.py --vectors .tmp/vectors-all
```

[tools/vectors/main.go](../../../../tools/vectors/main.go) declares `-out`
(default `vectors`), `-check` and `-sweeps`. Without `-check` it writes fixtures;
the default write invocation targets tracked `vectors/`. `-check` regenerates
expected bytes in memory, compares managed files and rejects unexpected JSON
under its two managed trees. It does not delete stale files. `-sweeps` materializes
the manifest's mechanical cases. Details:
[generator contract](../../../../tools/vectors/README.md).

[tools/vectorcheck/check.py](../../../../tools/vectorcheck/check.py) declares
`--vectors` (default `vectors`). It derives verdicts and checks expected plans
and positive pairing. Exit 0 means the supplied corpus matches, 1 means a
mismatch or no vectors, and 2 means P-256 checking is pending because
`cryptography` is unavailable. The checker uses pure Python Ed25519 and an
external `cryptography` implementation for P-256; unavailable P-256 is not a
pass. See the [checker contract](../../../../tools/vectorcheck/README.md) and
[pinned CI dependency list](../../../../tools/vectorcheck/requirements-ci.txt).
Dependency installation is not a step in this skill.

Corpus controls are offline evidence, with public synthetic keys only; they
qualify no native key, issuer presence/custody, durable consumer or effect.
The legacy corpus and independent checker do **not** qualify the newer publisher
profile as an independent v2 oracle, tag/release or non-Go consumer. The
dedicated [grant-revocation2 fixtures](../../../../verifier/testdata/grant-revocation2/README.md)
exercise the Go API only and do not extend that independent corpus. An inventory
pass, source pin or documentation validation cannot replace those open gates.
