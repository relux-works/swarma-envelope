# Pure Go API usage

Use the public import prefix `github.com/relux-works/swarma-envelope/`. Select the
protocol explicitly: the implemented platform uses `swarm-envelope/2`, with the
exact message signing tag `swarma-msg/2`. Historical SSHSIG commands/providers in
[waggle.md](../../../../spec/waggle.md) are not this API. See the
[platform contract](../../../../spec/swarm-envelope-2.md) for profile-specific
formats; a type/tag version does not qualify a release or a consumer.

## Bytes and signer admission

[record.go](../../../../record/record.go) supplies `Parse`, `Canonical`,
`ContentID`, `SigningPreimage`, `AdmitSigner` and `CheckDomain`;
[crypto.go](../../../../record/crypto.go) supplies strict key/signature checks.
`Canonical` encodes CCJ-1, not a receiver schema. `VerifySignature` and
`CheckDomain` check signature math/domain separation, not role or effect
authority. `AdmitSigner` admits original canonical message preimages without
holding a private key, invoking a signer or releasing a signature.

This inert codec-only positive and its adjacent refusal use the same bytes and
current `AdmitSigner` contract. The expected output follows static branch
inspection, not a compilation/run of this example:

```go
package main

import (
    "fmt"
    "github.com/relux-works/swarma-envelope/record"
)

func main() {
    raw := []byte("swarma-msg/2\n{}")
    admitted, err := record.AdmitSigner(raw, record.IdentityPolicy{})
    fmt.Println(admitted.Tag, err) // swarma-msg/2 <nil>

    admitted, err = record.AdmitSigner(raw, record.IdentityPolicy{MultiAgent: true})
    fmt.Println(admitted.Tag == "", err) // true signer_identity_unavailable
}
```

The positive is not a valid receiver message or permission to sign. The refusal
is meaningful: `MultiAgent` forces identity narrowing even when `Check` is false;
missing protected caller key/attestation cannot become permissive defaults.
For real narrowing, the provider independently resolves the active caller key
and attestation ID; the admitted `key`, `body.author` and
`body.author_attestation` must match those facts. Mark unavailable/malformed
policy `Invalid`. The exact domain remains message-only. See
[record contract](../../../../record/README.md) and the existing
[codec-only example](../../../../record/example_test.go).

## Protected evidence and verification

Construct snapshots with `verifier.Present(value)` and check its error, populate
`verifier.Context`, then call `verifier.New(context)`. Zero `Evidence` means
unavailable; explicit null is not an available empty collection. Use the exact
in-process shapes in the [package contract](../../../../verifier/README.md),
normally `map[string]any`, `[]any`, `int64` and raw signed `[]byte` values.
`Present` copies/bounds supported values; it does not authenticate their source.
See [types.go](../../../../verifier/types.go) and
[the pure boundary](../../../../verifier/doc.go).

| Request | Implemented entrypoint and boundary |
| --- | --- |
| Receive a platform message | `Verifier.VerifyMessage`: author/approver evidence, delivery, time and journal checks |
| Authorize a grant chain | `Verifier.Authorize`: leaf-first chain and separately protected request |
| Verify an ordinary operator act | `Verifier.VerifyOperator`: full operator pipeline; owner-DM operations still refuse as `act_operation_unknown` |
| Inspect an envelope candidate | `Verifier.VerifyEnvelope`: common envelope checks, not full grant/operator authority |
| Check signed evidence | `Verifier.VerifyAttestation`, `Verifier.VerifyServiceAttestation`, `Verifier.CheckRevocation`; only `NotRevoked` permits progress |
| Check journal/currency proofs | `Verifier.VerifyJournal`, `Verifier.VerifyFreshness`, explicit `Verifier.VerifyFreshnessReanchor` |

`CheckRevocation` checks signed snapshots for its exact protected root; it does
not resolve or follow a grant publisher. Supplying the publisher key as `root`
is not the publisher-aware grant-chain route.

See [verification](../../../../verifier/verify.go),
[standalone checks](../../../../verifier/evidence.go),
[service checks](../../../../verifier/service.go) and the
[API inventory](../../../../verifier/api.txt). Refusals return an empty `Plan`;
acceptance yields a candidate plan, never persistence, reservation or effects.
`OperatorRecordCode` maps to coarse consumer refusals; preserve the original
fine code in local audit. Failed/unavailable Commit uses `state_unavailable`.

Root currency is explicitly selected with `Context.RegistryCurrencyVersion=2`;
0/1 retains legacy behavior. Successful full freshness verification can mint an
opaque process-local `FreshnessReceipt`. Retain the original `SignedSnapshots`
and, for /2, `SnapshotJournal` Evidence identities. Rebuilding even identical
snapshots invalidates composition; serialized receipt data supplies no authority.
Persist admitted anchors, watermarks, pins/index and audit atomically before
use; refresh authenticated witness/time/current facts at the consumer boundary.
Invalid supplied receipts never fall back to receipt absence. See
[receipt code](../../../../verifier/receipt.go),
[/2 receipt binding](../../../../verifier/currency_receipt.go) and the
[currency contract](../../../../verifier/README.md#root-currency-profile-2).

Grant-domain publishers retain strict pairing: `grant-revocation-1` requires
P-256 (`p256`, `P-256`, 33 public bytes); `grant-revocation-2` requires Ed25519
(`ed25519`, `Ed25519`, 32 bytes). No cross-profile substitution is admitted.
The owner grant root signs the publisher appointment; its verified publisher
key is admitted only for grant-domain snapshots. Snapshot `max_age` remains positive and at
most **60 seconds**. See `grantPublisher` and `snapshotHeader` in
[evidence.go](../../../../verifier/evidence.go). These internal helpers describe
the contract; they are not public extension points.
Direct consumers should use `Verifier.Authorize` for grant chains or
`Verifier.VerifyAttestation` for attestations; those routes resolve the appointed
publisher where the grant domain applies.

## Owner-act data, preparation and supplied signatures

Read [owneracts/README.md](../../../../owneracts/README.md) for exact schemas and
local errors. `owneracts.Parse` admits closed canonical arguments;
`owneracts.ParseBody` admits canonical unsigned bodies; `owneracts.Map` derives
the complete text, arguments, digest, body, content ID and raw signing preimage.
Their ordinary mutable outputs confer no authority. The only selectors are
`owner-dm.bind`, `owner-dm.unbind`, `owner-dm.mirror-enable`; reserved
`launch.approve`, `host.change` and unknown operations refuse.

`verifier.PrepareOwnerAct` binds the complete original body and separately
received arguments to independently protected enrollment, installed profile and
full catalogs. Its immutable unsigned `OwnerActSigningPlan` exposes detached
copies through `Snapshot()`. `Render` is delivered text; `Review` is the separate
full escaped plain-text review; neither replaces the original `SigningPreimage`.
`confirmed` is proposed data, never proof of confirmation. See
[preparation source](../../../../verifier/owner_act_prepare.go) and
[the preparation contract](../../../../verifier/README.md#unsigned-owner-act-signing-preparation).

`verifier.AssembleOwnerAct` checks an already supplied raw64 low-S P-256
signature against the original private plan and exact returned key, then emits
immutable signed intent. `VerifiedOwnerActEnvelope.Bytes()` returns an owned
copy. `verifier.AssembleOwnerActNativeP256` explicitly admits only 8..72 canonical
DER bytes, converts to raw64 low-S and delegates verification; raw assembly and
consumer wire input still reject DER/high-S. `verifier.NativeP256KeyID` converts
exactly 65 binary uncompressed SEC1 P-256 bytes into the ordinary compressed
`p256:` key ID. These representation paths establish no native origin, custody,
presence or key-use permission. See [assembly](../../../../verifier/owner_act_assemble.go),
[DER conversion](../../../../verifier/owner_act_native_p256.go) and
[public-key conversion](../../../../verifier/native_p256_public_key.go).

`verifier.ParseOwnerActRequestFrame` admits a complete bounded `SEACT001` slice;
`verifier.EncodeOwnerActResultFrame` emits `SEOUT001`. Framing is grammar/encoding
only: it observes no pipe EOF, resolves no enrollment and authenticates no
correlation. See [frame source](../../../../verifier/owner_act_frame.go).

The distinct `Verifier.VerifyOwnerAct` route consumes separately received
envelope, arguments and delivered text plus independent `OwnerActContext`.
Every call requires a genuine /2 receipt. Eligible unbind can return a candidate
plan; bind and mirror-enable remain closed widening (`act_a3_inactive`). See
[owner-act verifier](../../../../verifier/owner_act.go) and
[its contract](../../../../verifier/README.md#owner-act-candidate-verification).

Actual extension seams are caller construction of the documented protected
contexts/evidence and composition of these public functions. No dynamic handler,
plugin registry, native key operation, transport or once-consuming Finalize is
implemented. Protected source authenticity/currentness, owner presence, native
lifecycle, durable replay/history, serialized Commit/effects and deployment
remain external; do not synthesize those premises to make an example accept.
