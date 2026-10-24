# Record bytes and signatures

`github.com/relux-works/waggle/record` supplies bounded, duplicate-free parsing,
registrar CCJ-1 canonicalization, content ids, signed-record preimages, strict
Ed25519 and P-256 verification, exact registered-domain probes, and message
signer admission. All crypto is from the Go standard library; public Edwards
point/subgroup checks explicitly narrow standard Ed25519 verification.

`AdmitSigner` enforces length, exact domain, canonical payload/depth, then the
optional or mandatory three-path `IdentityPolicy`. `MultiAgent` always enables
identity narrowing; a malformed/unavailable policy must set `Invalid`.
Resolved caller key and attestation id belong to the provider. The provider
signs the original bytes only after admission; this package holds no private
key, invokes no signer and releases no signature. Codec-only admission may
accept bodies the receiver must reject.

`Parse` bounds input size before copying or parsing and bounds containers
before registrar parsing. `Canonical` is the generic registrar CCJ-1 encoder,
not receiver schema admission. `KeyBytes` checks spelling/encoding/length;
`ValidateKey` additionally checks strict curve points. `VerifySignature` checks
raw signature math, not a type/role/authority profile. `CheckDomain` covers the
closed twelve-tag registry, including domains whose schemas are external; it
does not implement their admission. Use `verifier` for platform semantics.

Errors have a stable `Error.Code`; error messages contain no received bytes.
There is no I/O, mutable global state or provider callback. Input and returned
byte/object values belong to the caller. See [verifier validation](../verifier/README.md#validation)
for API inventories, conformance, race and fuzz commands. All build/test logs
and scratch corpora belong in ignored `.tmp/`.

The closed registry also contains `swarma-registry journal-entry/1` and
`swarma-registry checkpoint/1`. `Tag`/`ContentID` cover their type domains;
`CheckDomain` is raw math only and cannot admit an individually signed journal
entry or confer registry/commit-signer authority. Both tags remain refused by
`AdmitSigner`. Run the new domain controls with
`GOMAXPROCS=2 "$CURATOR_GO" test ./record -run '^TestRegistryDomains$' -count=1`.

`freshness/1` registers exactly `swarma-registry freshness/1`; the message
signer refuses it. Mathematical signature/domain verification supplies no
registry role, checkpoint binding, snapshot currency or publication continuity.
