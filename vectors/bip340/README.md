# Public test-only BIP-340 corpus

46 deterministic vectors: 3 positive and 43 negative. Synthetic test-only
keys; never deploy them. Generated separately by `tools/vectors -bip340` and
checked independently by `tools/bip340check`. Every negative names a valid
positive control. Expected ordered refusals and complete plans are checked by
both the independent Go checker and the actual public APIs in TestBIP340Vectors.

The corpus covers exact original SHA256/preimage/domain, high-s acceptance,
strict key/scalar encodings, both algorithm-confusion directions, profile
roles and full agent provenance/time/revocation/generation/delivery binding.
[Official algorithm vectors](../../tools/bip340check/testdata/official/README.md)
and additional actual-boundary Go role tests supplement these operands.
Legacy vector bytes and Python checker remain unchanged; no full arbitrary-
message production capability or operational provider qualification is claimed.
