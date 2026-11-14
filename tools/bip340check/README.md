# Independent BIP-340 checks

Test/tool-only, never a production verifier or key holder. The public
`oracle/` implementation derives lift_x, affine point arithmetic and public
Verify directly from the pinned BIP-340 specification using stdlib/math/big.
It shares no btcec/decred arithmetic, production record/verifier parsing or
point/signature helper. TestOracleTransitiveIndependence walks the actual
`go list -deps -json` closure and admits only this oracle plus stdlib packages.
A real isolated import-graph control proves transitive dependency detection.

The [pinned official CSV](testdata/official/README.md) grounds expected results;
agreement alone is not correctness. All 19 original vectors pass the oracle,
including 0/1/17/100-byte valid messages. Production's
TestBIP340OfficialFixed32AndCapability checks the 15 original32 vectors and
prints explicit capability observations for indices15–18: official_expected=true,
supported_by_fixed32_dependency=false, observed_verify=false. Those four
observations are not passing production vectors. The envelope's supported
domain is SHA256(the unchanged complete original preimage), exactly32bytes.

The command also independently reconstructs the new corpus's exact domain,
canonical fixture preimage and SHA256, checks signature math, verifies actual
Ed25519 root-signed attestation/revocation records and checks profile, protected
generation, exact author/key/reference, time, revocation, audience and delivered
body binding. It computes the complete expected candidate plan and empty
refusal plans. Its supported fixture modes are `envelope` and `domain`, with
ASCII keys/strings and integral JSON; it is not a second general Unicode CCJ
codec, legacy checker, consumer authority checker or source-authenticity proof.
Every new profile vector is independently checked. Additional forbidden roles
are tested at their actual verifier boundary in Go.

From repository root, with Go1.26+ selected in CURATOR_GO:

```sh
# Only new profile fixtures; no writes with -check.
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -bip340 -check
# Generate in caller-owned ignored scratch, then independently check it.
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -bip340 -out .temp/bip340
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/bip340check -vectors .temp/bip340/bip340
# Committed corpus plus all official oracle results.
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/bip340check
# Production original32 observations, protocol tests and independence gate.
GOMAXPROCS=2 "$CURATOR_GO" test -p 1 ./record ./internal/cryptocheck ./verifier ./tools/bip340check ./tools/bip340check/oracle -run 'TestBIP340|TestOfficial|TestIndependentBIP340|TestOracleTransitive' -count=1 -v
# Each plant MUST fail with exit1 and the indicated applied/mismatch diagnostic.
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/bip340check -plant valid-refused
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/bip340check -plant invalid-accepted
```

The first plant changes only observed oracle verdict0 to false against official
TRUE; the second changes observed verdict5 to true against official FALSE.
Expected results and input bytes never change. A missing plant, hash mismatch,
setup failure or crash cannot satisfy TestOfficialBidirectionalControls or the
matching CI checks. Neither plant fabricates disagreements between correct
verifiers. Stdout/stderr logs belong in caller-owned `.temp/` directories.

Production uses btcec/v2 v2.3.5 under its ISC license, transitively
chainhash v1.0.1, secp256k1/v4 v4.0.1 and blake256 v1.0.0. Exact sums are in
go.sum. Original r<p and s<n checks precede the reducing dependency parser;
TestBIP340OriginalScalarBounds checks that boundary beside valid encodings.
No test asserts a practical full-verifier forgery from s=n parser acceptance.
No signing call is made by production packages; deterministic public signing
helpers exist only in tools/tests.
