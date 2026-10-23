# Negative-first conformance witnesses

The normative contract is [the platform slice](../../spec/swarm-envelope-2.md).
`0-negative/` contains exact expected refusal codes and a `positive_control` id
under `1-positive/`. Every row has its own specific `claim`. Positive controls
prevent an always-refuse implementation from satisfying the examples.

Run from the repository root:

```sh
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -check
python3 -B tools/vectorcheck/check.py
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
and verified key, not a consumer admission decision. Agent key evidence and
protected expected bindings are independent fixture inputs; the checker tests
status, bytes/id, purpose, active generation, binding and validity without
inventing Keymaker attestation bytes.

The tools use the registrar's pinned CCJ-1 implementation only in the Go
generator. That public package fits directly; no local format fork is needed.
Python independently parses/canonicalizes and verifies strict Ed25519 using
prime-subgroup arithmetic, and P-256 with cryptography when available. Missing
cryptography reports PENDING and exits 2; it never reports full conformance.
No network is used by the checker. Go module resolution may download the pinned
public registrar dependency. Neither tool imports the future production verifier.

Generator `-out DIR` writes a fixture copy; `-out DIR -check` compares every
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
| E01–E45, PE1–PE7 | Parsing, canonicalization, ids, roles, domains, strict crypto, audience, provider/watermark availability, conflicting bytes, extra invalid signature, exact received-byte bounds, type/key-class profiles and actual signed preimage budget. E13 now rejects an agent approver at the profile gate; D43 separately proves cryptographic role binding. E27/E32/E35 exercise P-256 in the operator profile. PE2 is an Ed25519 agent control; PO1/PO2 cover P-256 operator keys. PE5 uses an Ed25519 author plus a separately pinned P-256 approver. E39 uses the operator lifetime bound and pairs with PO1. |
| G01–G37, PG1–PG8 | All delegation dimensions, root/leaf edges, 4/5 link boundary, time/caveats/watermark, revocation freshness/unavailability, registered actions, correlated targets and concrete request. |
| K01–K20 | Required attestation availability/validity, strict bytes/id derivation, purpose/class, active generation/owner/path/registration/epoch binding and three-outcome revocation, including grant issuers and subjects. |
| D01–D47, PD1–PD7 | Every directed pair among all seven published tags, role/type mutation inside one message domain, exact case/space/CR rules. External rows prove tag/signature separation only; external body schemas are not simulated. |
| S01–S26, PS1–PS5 | Message signer accepts exactly swarma-msg/2, refuses grant/act/registrar/broker and unknown future-service tags, checks canonicality, exact size/depth boundaries and no envelope semantics. S07 uses a generic unregistered sentinel, not an invented signing-service witness tag. |
| O01–O18, PO1–PO4 | Exact consumer/binding/argument/epoch/key, single-use act, widening confirmation/provider facts, replay availability and record bound. |

These are bounded witnesses, not exhaustive property proofs or an implementation
of live effects. Provider confidence, revocation authenticity/completeness,
protected pin custody, store availability and prior journal entries are explicit
external fixture facts. Persistent reservation, concurrency/crash recovery,
retention, caller argument validation, signature-provider qualification and live
consumer activation remain integration obligations. No surface table was supplied
for implementation coverage; this table maps the requested format witnesses,
not a production landing-gate surface or qualification claim.
