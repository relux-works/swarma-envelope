# Grant publisher Go fixtures

These dedicated Go-only signed fixtures use the existing conformance JSON
transport and test-only public software keys. They do not change the legacy
v0 corpus, generator inventory, manifest or independent Python checker.
They are not independent v2 oracle, release, tag or deployment qualification.

Each case calls public `Authorize` with a valid depth-zero, owner-root-signed
`grant/1`, a valid subject attestation, trusted time/watermark and signed
revocation evidence. All publisher-specific refusals here reach G7, where
binding invalid maps to `revocation_invalid`; refusals return no plan.
The positive grants return their exact ID, watermark and `until_expiry` use.

| Fixture | Contract expectation / nearest positive |
| --- | --- |
| GP2-valid | Owner-root-appointed Ed25519 profile 2 and fresh ordinary Ed25519 snapshot admit. |
| GP1-valid | Existing P-256 profile 1 with fresh low-S P-256 snapshot admits. |
| GP2-profile1-ed | Profile 1 cannot bind an Ed25519 subject; GP2-valid. |
| GP2-p256-subject | Profile 2 cannot bind a P-256 subject; GP1-valid. |
| GP2-wrong-snapshot-signer | Publisher P remains the issuer and signature key and has a correct content ID; Q signs the exact claimed-P preimage, so signature verification refuses; GP2-valid. |

`TestGrantRevocation2Fixtures` uses the existing paired conformance runner.
Expected verdicts and plans were written from the contract, without querying
the verifier for expected output. Other executable negatives cover appointment,
all six type-compatible pins, key encoding and point validation, purpose,
windows, freshness, missing facts and revoked entries. Pure library controls
prove no native key, custody, durable union, receiver or effect property.
