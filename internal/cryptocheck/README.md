This package shares strict Ed25519 point validation between key and signature
checks inside a single verifier operation. A scope retains at most 128 successful
checks, each bound to all 32 encoded bytes. At capacity or without a scope, the
original arithmetic runs. Invalid points are never retained.

The verifier creates its own scope in consumerFacts. It is absent from public
Context, Verifier, Evidence, Result and receipts, and cannot cross public calls.
Separate message verification, grant authorization, advisory verification and
final verification start independently. Public record functions use no scope.

Every signature still checks its encoding, R membership, scalar bound and
standard-library equation. A cached point result says only that the exact point
is canonical, on curve, nonidentity and prime order. It grants no authorization
and says nothing about signatures, policy, currentness, revocation or time.


BIP-340 dispatch verifies SHA256 of the unchanged full preimage with pinned
btcec/v2 v2.3.5, verify-only. Its parser reduces s, so original received r<p
and s<n are enforced first; no low-S rule is imported from P-256. x-only key
admission uses the dependency's even-y lift and exact32 bytes. This path uses
no scope cache; a cached Edwards point cannot establish secp256k1 membership.
TestBIP340OfficialFixed32AndCapability checks all official original32 operands
and explicitly reports the four official valid arbitrary-message capability
limits. TestBIP340OriginalScalarBounds separately checks the parser boundary.
