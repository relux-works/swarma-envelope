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
