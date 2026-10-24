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
write command (`go run ./tools/vectors`) writes 510 named cases, the public keys
and sweep manifest/digest under `vectors/`; it does not materialize T/B/Z JSON.
`-sweeps` adds those 1227 cases (1737 total: 1643 negative, 94 positive).
The inventory check also rejects unexpected JSON under both managed trees,
including accidentally materialized sweeps when `-sweeps` is absent. Generation
does not remove obsolete files; remove only reviewed stale paths explicitly.

## Sweep manifest

`swarm-envelope-2/sweeps.tsv` is UTF-8, sorted by case id in ascending ASCII
order, with exactly one LF-terminated line per T/B/Z case and no header:

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

Work in a generated scratch copy. Change one byte in a T/B/Z case (for example,
inside its claim). `-sweeps -out DIR -check` must exit 1 and name that JSON byte
mismatch. Restore the one scratch file, change one TSV line, then repeat: it
must exit 1 and name the manifest mismatch. Restore it and repeat with a changed
manifest digest if desired. A green original copy is the positive control.

For independent crypto sensitivity, flip one signature byte in PE1 while
retaining expected accept. The inventory check must fail on PE1; the Python
checker must derive `envelope_signature_invalid` for PE1 and exit 1. Keep all
plants outside tracked files. These controls prove detection of these bounded
defects, not exhaustive resistance to every generator/checker defect.
