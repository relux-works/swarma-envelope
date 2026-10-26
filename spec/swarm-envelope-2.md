# Platform signed records, slice v0

Status: proposed normative contract; no production verifier or consumer activation.
MUST, MUST NOT, SHOULD and MAY are requirement words. All byte counts refer to
UTF-8 bytes, not characters. Refusal codes in §6 are stable within this draft.

## 1. Scope, ownership and existing waggle

This slice defines `swarm-envelope/2`, general `grant/1`, `operator-act/1`, `attestation/1`, shared `revocation/1`, unsigned `journal-entry/1` and registry-signed `checkpoint/1`.
The platform choice of CCJ-1 plus an explicit domain tag is settled; SSHSIG is
not the platform-service encoding. The exact v0 schemas remain under review.
For platform services it supersedes the SSHSIG encoding and verification rules
in [waggle v5.2 §§4, 19](https://github.com/relux-works/waggle/blob/c618202899a196a9d5a1f56fa5c003ebf3fd2d91/spec/waggle.md).
SSHSIG remains a separate repository/offline proposal, including board acts
and role delegation in Amendment A1. A receiver MUST select its protocol from
protected channel configuration. It MUST NOT try SSHSIG after this verifier
refuses, convert an SSHSIG signature into this format, or import the board's
role/budget semantics into general grants. A1 policy is not implemented here.
This boundary also supersedes v5.2's permissive dropping of invalid signatures:
every attached signature in this slice MUST pass. Transport is not authority.

waggle owns these formats and the future verifier. Consumers MUST pin a reviewed
main commit and change that pin through their own review. The pure `record` and `verifier` packages implement the offline contract;
§6 remains normative and no consumer activation is implied.

Owner decision, 2026-10-24: the owner registry and rollback witness are to run
on one separately administered trust node outside the agent platform's
administrative domain. The platform has no administrative access there;
agents have no root access. The registry is the only authoritative writer of
keys, attestations, grants, revocations and identity journals: it stores, orders
and publishes records, preserving their original signers as specified in §2.6.
Owner decision, 2026-10-25: the registry-owner key is held by a separate
signer process under its own account on the trust node. It signs only the
pre-approved `revocation/1` snapshot, `checkpoint/1`, `freshness/1`,
`checkpoint/2` and `freshness/2` profiles
and MUST refuse every other record type or profile, consistent with D30. The
registry service process that stores and orders records MUST never hold that key.
Consumers require currency within 60 seconds, with stricter protected age
and continuity policy: snapshot-own issuance under §2.6, or the complete
§2.9 signed freshness and fresh authenticated witness read for an unchanged
base. No old base alone supplies currency. Until this node exists,
the current mode remains pinned roots and caller-supplied snapshots. This
slice specifies that deployment boundary; it deploys no registry or witness.

Public design inputs (pinned, informative except explicit consumer mappings):

- [Registrar §2 and public packages](https://github.com/relux-works/swarma-registrar/blob/5f44ebf3f78829144aa7864ca2e4ad62bea43eb5/spec/registrar.md): CCJ-1 and key encodings.
- [Broker §§6–8, 14](https://github.com/relux-works/swarma-credential-broker/blob/1a97d68e2f352135580c5f53098ced5f56b6a1db/spec/broker.md): chain, revocation, binding and operator boundaries.
- [Broker R1](https://github.com/relux-works/swarma-credential-broker/blob/1a97d68e2f352135580c5f53098ced5f56b6a1db/spec/v0-codex-refresher.md#2-interim-authority-and-identities): static admission remains in v0.
- [Keymaker §§5, 7, 10, 14–15](https://github.com/relux-works/swarma-keymaker/blob/243a330d331c07c57aa0497c348995f66c74d08e/spec/keymaker.md): operator-record consumer.
- [Station authority](https://github.com/relux-works/curator-spec/blob/d6c40195962d9fa3ccafa2c2001c2312c6c5e086/cips/CIP-0024-agent-stations.md#root-context-and-authority),
  [credential authority](https://github.com/relux-works/curator-spec/blob/d6c40195962d9fa3ccafa2c2001c2312c6c5e086/cips/CIP-0011-credential-broker-and-agent-users.md),
  [credential binding](https://github.com/relux-works/curator-spec/blob/d6c40195962d9fa3ccafa2c2001c2312c6c5e086/cips/CIP-0010-credentials-setup-token-and-inherited-auth.md),
  [carrier registration](https://github.com/relux-works/curator-spec/blob/d6c40195962d9fa3ccafa2c2001c2312c6c5e086/cips/CIP-0019-carrier-admission-by-public-key.md).

## 2. Envelope and bytes

### 2.1 Closed schemas and limits

An envelope has exactly these four required members:

```text
{version: "swarm-envelope/2", body: object,
 id: "sha256:<64 lowercase hex>",
 signatures: [{role: "author" | "approver" | "delegate", key: key-id, sig: base64url}]}
```

The signature list is a compatible extension of a single-signature container: a
single signer uses a one-entry list; consumers MUST NOT select an arbitrary
entry or drop invalid entries. There MUST be 1–8 signatures with no duplicate `(role,key)` pair. Other roles
are reserved and MUST refuse. A role never confers authority by itself. Required
roles and admitted keys come from the caller's protected policy. Grants require
exactly one `author` signature by `issuer`; operator acts exactly one `approver`
from a device attested by the pinned operator root. A message requires `author` by its `author`
Ed25519 agent key; optional `approver` signatures MUST use root-attested P-256
operator device keys. Extra signatures require caller policy and MUST all verify. Device trust comes
from the operator root and signed attestation, not a second device-key pin list.
The accepted algorithm/role/type matrix in §2.4 is exhaustive. Recognizing a
role name does not mean a v0 profile admits it.

All objects are closed: unknown/missing fields and wrong JSON types MUST refuse,
including nested objects. The JSON reader MUST enforce limits while reading:
65,536 bytes per envelope, 16 container levels (root = 1), 8,192 bytes per string,
64 entries per array except signatures (8) and chain (4). An operator envelope
has a stricter 8,192-byte limit, measured on the whole received object including
signatures. Aggregate chain intake is at most 262,144 bytes. Readers MUST bound
allocated work before parsing. The v0 types are only `grant/1`, `operator-act/1`
the minimal signed `message/1` below, and the separately profiled
`attestation/1` / `revocation/1` records in §2.6; another type needs a reviewed version.

The common body members are `type`, `aud`, `nonce`, `iat`, `exp`. `aud` is one
exact service identifier, 1–255 printable ASCII bytes without whitespace.
`nonce` is canonical unpadded base64url encoding of 16 independently random
bytes. Production signers MUST use a CSPRNG; fixed vector values are test-only.
Times MUST be exactly `YYYY-MM-DDTHH:MM:SSZ`, real Gregorian dates, years
1970–9999, no offsets, fractions or leap seconds. `iat < exp`. Operator acts
and messages have lifetime at most 120 seconds; grants have no implicit renewal
or maximum lifetime beyond the chain and protected consumer policy.

`message/1` adds exactly `author`, `author_attestation`, `action`, `target`, `arguments` (an object),
`room`, `to`, `body_sha256`. `room` and `to` MUST be strings of 1–255 bytes,
each byte ASCII 0x21–0x7e. They are opaque exact full carrier identifiers,
never aliases or display names; the carrier adapter MUST supply its actual
canonical room id and full recipient id. The alphabet alone does not resolve
an alias. Protected delivery context supplies the actual room and the recipient
being verified; both MUST equal the signed strings byte for byte. Forwarding
into another room or to another recipient MUST refuse independently of `aud`.
`body_sha256` is REQUIRED on every message: exactly 64 lowercase hex digits,
SHA-256 of the exact UTF-8 bytes of accompanying human-readable event text.
It has no `sha256:` prefix. Delivered text MUST be present, even when empty;
the empty string hash is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
The verifier MUST recompute it over the actual delivered bytes, without Unicode
normalization, newline tolerance or reconstructing text from `arguments`.
Invalid UTF-8 refuses. These are additional integrity bindings, not authority.
Arguments MUST pass the caller-selected registered action schema at admission.
Envelope-only vectors use synthetic argument objects for codec/size controls;
they check envelope mechanics and publish no general message payload grammar,
session commands or board policy. Authentication alone MUST NOT authorize
message delivery or execution. The receiving consumer MUST validate the complete
arguments object against its registered action/handler schema, reject unknown
members and invalid values for that schema, and authorize the concrete action
and target before dispatch. Envelope-only acceptance can include unexpected
argument members; it proves neither handler-schema validity nor authority.

`author_attestation` is required and is the canonical `sha256:<64 lowercase hex>`
content id (§2.2) of the exact attestation/1 envelope attesting `author`. It is
inside the signed body; it is not an unsigned lookup hint.

### 2.2 CCJ-1 and preimages

Body canonicalization MUST use registrar §2 CCJ-1: scalar-sorted object names,
array order preserved, shortest decimal integers, no Unicode normalization,
UTF-8 output, minimal JSON escapes (no escaping slash, angle brackets, ampersand
or non-ASCII scalars). Input MAY have noncanonical whitespace/order/escapes.
Duplicate names at every depth (also escaped aliases), invalid UTF-8/BOM,
lone surrogates, floats/exponents, negative zero, and integers outside
[-9007199254740991, 9007199254740991] MUST refuse. Bodies MUST NOT contain
signature metadata, and canonicalization MUST NOT recursively strip `sig`.

The caller supplies the expected type T from the protected channel. D is the
exact tag assigned to T in §2.4; the body type MUST equal T. For a signature
entry with role R and key id K, define the **signed record** as exactly
`{body:body,key:K,role:R,version:"swarm-envelope/2"}`. Its member order on the
wire below is illustrative; CCJ-1 supplies the byte order.

```text
content_preimage = ASCII(D) || 0x0a || CCJ-1(body)
id = "sha256:" || lowercase_hex(SHA-256(content_preimage))
signed_record = {body: body, key: K, role: R, version: "swarm-envelope/2"}
preimage = signature_preimage = ASCII(D) || 0x0a || CCJ-1(signed_record)
```

**`preimage` is the complete byte sequence supplied to a signer.** The content
hash input is separately named `content_preimage`: it is not the signing input.
There is no trailing newline in either. The envelope id and signatures are
outside the signed record; the version, role, key id and complete body are
inside it. The body's `type` is therefore signed even though the message tag
is fixed. All message roles use the same tag and the same construction with a
different signed `role` value. A signature for one role, key, version or type
MUST NOT verify after replacing that value. An id alone does not bind a role.

This is one domain/LF/CCJ-1 construction with two explicit payload schemas.
The signature payload is the protected signed record, not bare body bytes.
Receivers MUST reconstruct it from their expected type, fixed version and the
entry, never accept an arbitrary preimage in place of a verified envelope.
Neither a message signer nor a carrier selects the expected type for a receiver.
Raw-preimage entry points MUST compare the tag up to the first LF byte exactly;
envelope verifiers construct that exact tag themselves. No old `waggle` tag or
role-specific tag is a compatibility alias. Existing draft signatures must be
regenerated, not relabelled.

A caller-owned id journal MUST retain the exact accepted wire bytes. An already
seen id with different bytes MUST refuse `envelope_conflict`, including changed
signature arrays or whitespace. Assembly MUST finish before first publication;
retries MUST resend identical bytes. Identical bytes may be deduplicated for
messages by consumer policy; they MUST NOT authorize a second operator act.
A content-addressed id does not replace a single-use action id.

### 2.3 Cryptography

Base64url MUST be unpadded, URL alphabet only, with zero unused trailing bits;
decode/re-encode MUST yield the original. Signature bytes are exactly 64.

`ed25519:` key ids contain 32 bytes. Both public key and signature R MUST be
canonical curve points in the prime-order subgroup, excluding identity; reject
small-order and mixed-order points. S MUST be in [0,L), with
L = 2^252 + 27742317777372353535851937790883648493. Verify ordinary Ed25519
on `signature_preimage`, without prehash or context variants.

`p256:` key ids contain a 33-byte compressed SEC1 point, prefix 02 or 03,
x below the field prime, on curve, nonidentity, matching parity. ECDSA uses
SHA-256(signature_preimage), raw big-endian 32-byte r || 32-byte s, with
1 <= r,s < n and s <= floor(n/2). DER, uncompressed points, high-S, other
curves/algorithms and algorithm inference MUST refuse. No SSHSIG or FIDO wrapper
is admitted. User presence is a signer-provider enrollment requirement, not an
invented ECDSA flag. Unsupported presence evidence MUST fail closed.

### 2.4 Exact domain registry and key profiles

A tag is 1–96 bytes, each in ASCII 0x20–0x7e inclusive. LF (0x0a), CR (0x0d),
all other control bytes, DEL and non-ASCII bytes are forbidden. The first 0x0a
is the one delimiter; the complete remainder MUST be CCJ-1 bytes. No trimming,
case folding, Unicode normalization or prefix/pattern acceptance is permitted.
Leading/trailing spaces satisfy the byte alphabet but are not aliases for a
registered tag. New literal tags enter only through a reviewed change to this
closed table; caller configuration cannot register an alias.

| Exact ASCII tag | Assigned content / owner | Message signer membership |
| --- | --- | --- |
| `swarma-msg/2` | message/1 signed record; this specification | Accepted exactly |
| `swarma-waggle grant/1` | General grant/1; this specification | Refused |
| `swarma-waggle operator-act/1` | operator-act/1; this specification | Refused |
| `swarma-attestation attestation/1` | Root-issued key attestation; §2.6 | Refused |
| `swarma-attestation revocation/1` | Root-issued shared revocation snapshot; §2.6 | Refused |
| `swarma-registrar registration/1` | Registrar registration; registrar §2 | Refused |
| `swarma-registrar enrollment/1` | Registrar enrollment; registrar §2 | Refused |
| `swarma-credential-broker grant/1` | Broker's separate closed grant; broker §6 | Refused |
| `swarma-credential-broker revocation/1` | Broker's revocation; broker §6.4 | Refused |
| `swarma-registry journal-entry/1` | Unsigned identity-journal content id; §2.7 | Refused |
| `swarma-registry checkpoint/1` | Registry-signed checkpoint; §2.7 | Refused |
| `swarma-registry freshness/1` | Registry-owner signed snapshot freshness (§2.9) | Refused |
| `swarma-registry checkpoint/2` | Registry-owner signed root-set checkpoint (§2.7) | Refused |
| `swarma-registry freshness/2` | Registry-owner signed root-set currency (§2.9) | Refused |
| Unpublished signing-service witness domain (no literal assigned here) | Signing service owns publication; placeholder is NOT a registered tag | Refused until separately published; never implicitly admitted |

All fourteen published literals above MUST be pairwise distinct. Prefix uniqueness
is not required: even if one tag is a prefix of another, at the shorter tag's
end one preimage has LF while the other has a non-LF tag byte. Exact tag plus
LF already separates them. In particular `swarma-msg/20` is not accepted merely
because it shares bytes with `swarma-msg/2`.

**Decision: one fixed message tag.** Type, role, version and key binding live
inside the signed record (§2.2). This keeps the signer's admissibility check to
one exact byte comparison and a canonicality/limit check, while receivers bind
all semantic distinctions. A growing role/type tag grammar would add signer
configuration without removing the need for receiver schema and authority
checks. Grants and operator acts are outside the message-signing namespace.

The accepted signature profiles are exhaustive:

| Expected type | Signature role | Key class / algorithm | Required provenance |
| --- | --- | --- | --- |
| message/1 | author | Agent / Ed25519 | Verified root-signed attestation/1 and current generation binding (§2.6); key equals body.author and exact verified attestation id equals body.author_attestation |
| message/1 | approver, optional or caller-required | Operator device / P-256 low-S | Pinned operator root, verified operator-device attestation, current revocation and caller policy |
| grant/1 | author, exactly one | Grant authority / Ed25519 or P-256 low-S | Pinned owner root, parent-authorized operator device, or parent-authorized service key with §2.6 provenance; agent keys are subjects/leaves only |
| operator-act/1 | approver, exactly one | Operator device / P-256 low-S | Pinned operator root, verified operator-device attestation and §4 act checks |

An operator **device** key MUST be P-256; an agent key MUST be Ed25519. A pinned
grant root is a separate authority key and need not be an operator device.
All other combinations MUST refuse `signature_profile_invalid`: in particular
P-256 agent authors, Ed25519 operator acts and agent approvers/delegates. The
`delegate` role is reserved without an admitted v0 profile. An optional message
approver is a signature on content, not a replacement operator act or an A3
claim. Grant authority still requires the complete chain; key class is no grant.
An agent key MUST NOT issue grant/1 in v0, even with a valid parent grant and
current agent attestation. K1 verifies required provenance before returning
`signature_profile_invalid` for an agent issuer. Agent subjects and leaves
remain admissible. An agent-issued-grant profile needs explicit signed
attestation binding in a later version; no such profile is implied here.
A K3 message signer cannot issue a grant: a separately qualified grant-domain
signer would be required. This specification publishes no such Keymaker method.

An operator-device signer provider MUST produce a raw 64-byte P-256 low-S
signature over the exact §2.2 preimage (for example, using a platform secure
element). FIDO/WebAuthn assertions are outside v0: they sign authenticatorData ||
SHA-256(clientDataJSON), not this preimage. Extra assertion members in a signature
entry MUST refuse the closed schema (`envelope_malformed` at E2). A mathematically
valid signature over that WebAuthn construction, even with the preimage or its
content id as challenge, MUST refuse `envelope_signature_invalid` at E6 when
presented as `sig`. No assertion wrapping, challenge extraction or signature
translation is permitted. A future WebAuthn proof profile needs its own tag and
record, not a reinterpretation of these bytes.

### 2.5 Message signer provider: opaque canonical bytes

Keymaker's message byte signer is the first signing consumer of this format.
The signer-provider interface is:

```text
SignMessage(full_preimage_bytes) -> {key_id, raw_signature_64_bytes} | refusal
```

The provider's key resolved for each caller is Ed25519. It MUST check, in order:

1. Full preimage length <=24,576 bytes, before allocation/signing.
2. A first LF exists; bytes before it satisfy the tag alphabet/length in §2.4.
3. Those bytes equal exactly `swarma-msg/2`.
4. The remainder is canonical CCJ-1: parse/re-encode MUST equal the received
   remainder byte for byte, with depth <=12 (root container = 1), strings
   <=8,192 bytes and arrays <=64 entries, plus every CCJ-1 rejection rule.

A provider MAY additionally enforce caller identity. This check is REQUIRED
for a provider that holds keys for several agents; it cannot be disabled by a
caller option. After steps 1–4 it resolves the attested Ed25519 key id for the
calling OS identity and its active generation, using the signing service's
existing identity/attestation mechanism and §2.6's key-id derivation. It also
resolves the exact content id of that caller's current, fully verified attestation. This is
protected service context, never a key selector or asserted identity supplied
inside the signing request. Unavailable or invalid identity resolution refuses.

The check extracts exactly three identity paths from the canonical signed record:

| Path | Required value |
| --- | --- |
| `key` | Top-level signed-record key id, a string |
| `body.author` | Message author key id, a string inside the body object |
| `body.author_attestation` | Content id of the caller's current attestation, a string inside the body object |

Each path is extracted exactly once, with those exact member names, no aliases,
no first/last-member choice and no fallback to other fields. CCJ-1 already
rejects duplicate decoded members, including escaped aliases, before this
check. A missing path, non-object path container or wrongly typed member
refuses. The first two strings MUST equal the caller's resolved attested key id;
the third MUST equal the service-resolved current attestation content id, all
byte for byte before signing. Missing service resolution refuses
`signer_identity_unavailable`; missing/wrongly typed record paths refuse
`signer_identity_malformed`; unequal values use the existing
`signer_identity_mismatch`. Absence never equals absence; agreement between
foreign identities is insufficient.
The check applies only in the exact message domain; grant and operator-act tags
already refuse at step 3. Nothing else in the body is interpreted.

This check narrows what bytes the provider signs. It does not replace any
receiver schema, signature-profile, attestation, grant, revocation or authority
check. A single-agent provider without this optional narrowing retains the
base codec-only admission contract (PS1–PS5); a multi-agent provider must apply
both contracts. PI1–PI5, I01–I21 and I-attestation-* exercise the additional check.

It MUST sign the original complete bytes, without changing whitespace, adding a
newline, reconstructing an envelope or deciding action, role, type, audience,
grants or operator authority. Codec parsing and the conditional identity paths
above are the only record inspection. The signature is ordinary Ed25519, not a signature on
the content id or a second hash. The key id MUST be derived from the bound public
key by §2.3 and returned with the raw signature. Refusal releases no signature.
Existing caller/kernel identity checks remain the signing service's boundary;
the rules here add no caller-controlled key selector or native method grammar.

The provider may still sign a canonical record claiming `approver` or another
body type under the fixed message tag, even after identity narrowing succeeds.
That does not authorize the claim: receivers MUST enforce §2.4 and reconstruct
the tag for their caller-selected type. Operator/grant verifiers cannot reuse
that signature. PS5 and conformance vectors E13, D43 and D44 distinguish these two responsibilities.
The operator device provider is separate: it signs the act domain using P-256
low-S and satisfies §4's presence/confirmation obligations; it is never this
message signer under another tag.

**Frame budget assumption for the future native adapter:** the full preimage
travels as canonical unpadded base64url in JSON, or in an equally bounded opaque
byte carrier, with at most 4,096 bytes for every other request field and JSON
syntax. At the 24,576-byte input bound base64url is exactly 32,768 bytes. Thus a
JSON payload is at most 36,864 bytes, or 36,868 including a 4-byte header, leaving
28,668 bytes below even a 65,536-byte total-frame ceiling. The native owner MUST
publish and enforce that metadata budget; arbitrary JSON escaping of raw bytes
is not an equivalent carrier. No request field names are invented here.
The canonical signed record cap of 12 also leaves four container levels below
the native depth-16 ceiling; a base64url string adds no decoded JSON nesting to
the outer frame. The complete native request still MUST enforce depth <=16.
Both signer and message verifier MUST enforce the preimage budget and depth.

### 2.6 Root-signed attestations and shared revocation

`attestation/1` and `revocation/1` use the four-member envelope and §2.2's
content-id and signed-record construction with their own exact tags in §2.4.
They do not use the message/grant common schema. Before any signed evidence is
consumed, protected root pins for the four root roles (purpose-5 signing service,
registry-owner revocation, operator, and grant owner) MUST be pairwise distinct
key ids. No overlap between these roles is allowed. The operator root signing
both its device attestations and its snapshots is one role, not an exception
between roles. Reusing a root key as a subject is governed separately by the
subject profile and does not create another root role. Compare present protected
pins before per-record lookup/admission; missing or malformed policy retains its
purpose-specific unavailable/invalid checks. An overlap refuses
`key_binding_invalid` at the start of K1, or O2 after O1 and before currency;
G7 maps it to `revocation_invalid` before snapshot intake if not encountered
earlier. A grant key admitted directly as its configured authority root consumes
no attestation at K1; a root-only chain may first consume signed evidence at
G7. E1–T2 and the E6 direct-signing profile still precede these gates.
No signed bytes, alternate pins or successful cryptography can widen a root's
record language. Evidence processing is then ordered:
required outer fields and duplicate-free bounded parse; required type/issuer and
single author signature header; expected type/root, content id and strict root
signature; complete purpose-specific typed body/current binding, profile and
time; then signed issuer snapshot. A bad earlier signature is invalid even if a
later body field is missing. Snapshot processing verifies the same header/id/
root signature, then its complete typed body, freshness/continuity and all entry
shapes before matching revocations. Each has exactly one `author`
signature by its body `issuer`, a directly pinned root. Roots MAY be Ed25519
or P-256 low-S; devices MUST be P-256 low-S. Each complete evidence envelope
MUST be <=8,192 bytes, depth <=16, with the shared CCJ-1/string/array limits.
There is no intermediate certificate chain, implicit root discovery or network
fetch. A root pin includes its protected purpose; signing-service roots MUST
have integer key purpose 5. The caller MUST NOT promote a subject to a root.
Issuers MUST validate the same body/profile/time bounds before signing that
verifiers enforce; offline fixtures do not qualify the live issuer.

D30 record and storage roles are explicit; present keys in these different
roles MUST be distinct. Agent and operator-device subject keys also cannot
select a service or commit/publisher role through overlapping protected maps.
Unused new roles need not be configured on inherited intake paths; provisioning
must still preserve global role separation. The verifier compares every role
that the protected configuration makes present.

| D30 role | Protected source | Admitted record language |
| --- | --- | --- |
| Purpose-5 signing-service root | service root key/purpose5 | Agent attestation/1 only |
| Registry-owner root | registry-revocation root/purpose/scope | Scoped revocation/1, §2.7 checkpoint/1 and checkpoint/2, §2.9 freshness/1 and freshness/2 only |
| Operator root | operator pin | Operator-device attestations and its own snapshots |
| Grant-owner root | grant pin; explicit grant-service purpose/owner for attestations | Grant/1, own revocation/1, explicitly configured service attestations |
| Grant-service subject | Exact service-attestation collection and §2.6 profile | Parent-authorized grant/1 only |
| Offline enrollment publisher | Separate publisher key | Registrar enrollment/1 only, external to this verifier's record admission |
| Repository commit signer | Separate commit-signing key | NO protocol record type; repository commits are storage/transport only |

The registry-owner revocation root in D30 is the registry's signing key on
§1's separate trust node. Its authoritative-writer role does not re-sign
content: agent `attestation/1` retains the purpose-5 service signature, device
attestations retain the operator-root signature, and grants retain their
original grant-authority signatures. Registrar `enrollment/1` records retain their offline
publisher Ed25519 key; the registry service stores and serves them but MUST NOT
sign them online. Online enrollment signing would require a separate registrar
decision; this reference adds no S0 record profile or tag. The registry key
signs only `revocation/1` snapshots, §2.7 identity-journal checkpoints and
§2.9 freshness/1 and freshness/2. Operator-device
snapshots retain their existing operator-root signature rule; the registry
may store and publish them without substituting its signature. D30's distinct
keys remain mandatory even when roles are hosted on the same node. Neither
registry storage nor publication can promote the registry key into a grant
owner, operator or purpose-5 service root.

Owner decision, 2026-10-24: operator-root recovery requires a separately held,
pre-attested recovery means whose ONLY power is replacing or revoking the
operator root. The next form is a threshold of two of three custodians. S0
specifies no recovery record and registers no recovery tag; v0 verifiers MUST
refuse root replacement or recovery claims as authority. Existing agent/device
attestations do not confer that power. A future recovery record MUST have its
own reviewed type/tag and qualified recovery policy. Neither the generic
envelope/signature list nor the root-policy model may assume a single recovery
signer: the existing limit of eight signatures with unique `(role,key)` pairs
leaves room for the threshold form. Single-signature restrictions on existing
attestation, grant and act profiles do not constrain that future type.

An attestation body has exactly these required members:

| Member | Constraint |
| --- | --- |
| `type`, `issuer` | Exactly `attestation/1`, pinned issuing root key id. |
| `subject` | Exactly `{algorithm,key_id,public_bytes}`; algorithm is `Ed25519` or `P-256`; canonical unpadded base64url raw public bytes. `key_id` MUST equal `ed25519:` + encoding of the 32 bytes, or `p256:` + encoding of the 33 compressed SEC1 bytes. Strict §2.3 point checks apply. |
| `key_class`, `purpose` | Agent: exactly `agent`, `swarma-msg`. Operator device: both exactly `operator-device`. Service: `service`, `grant-service`. |
| `roles`, `actions` | Sorted unique closed lists. Agent: `["author"]`, `["message.sign"]`. Operator device: `["act","approver"]`, `["act.sign","grant.sign","message.approve"]`. Service: `["author"]`, `["grant.sign"]`. These limit the identity/signing profile; they grant no concrete action/target authority. |
| `iat`, `exp` | Exact timestamps; start-inclusive/end-exclusive under min/max time. Positive interval. Agent and service windows MUST be <=86,400 seconds, checked by both issuer and verifier. Device expiry is required, bounded further by protected policy. |
| `binding` | Purpose-specific closed object below. |

Agent binding has exactly `{uid,generation,registration_number,master_epoch,
owner,path}`. UID is a JSON integer in [0,4294967294]; registration_number a
JSON integer in [1,9007199254740991]. The other four fields are nonempty valid
UTF-8 strings of at most 255 bytes, compared without normalization. All fields
MUST equal protected current active-generation evidence supplied by the caller;
that evidence adds exactly the boolean `active`, which MUST be true. Both
objects MUST be independently type-checked before comparison: `true`, `1.0`,
strings or equal invalid numbers never authenticate registration 1. Reusable
UID alone never identifies an active generation. `master_epoch` is the signing
service master epoch; it replaces the earlier semantic `epoch` projection name.
A valid agent author attestation establishes A1 origin, not session approval.
For agent keys, the signing service's binding revoke remains authoritative;
shared records distribute that withdrawal to receivers and do not undo it.

Operator-device binding is exactly `{owner}`: the exact protected owner,
nonempty UTF-8 <=255 bytes. After verified evidence/profile admission, check
protected-owner availability and type first, independently enforce the 1–255
UTF-8-byte bound on both signed and protected owners, then compare. Missing/null
protected owners are unavailable; invalid types, empty or oversized owners are
invalid, even when both values are equal. The operator root attests the device; direct device
pins are not an alternative. Device algorithm MUST be P-256, even when its
root uses Ed25519. Current owner authority remains a separate mandatory fact.
For an act, the attested owner MUST also equal the act owner and protected registration owner;
independent successful comparisons to two different owners are insufficient.
Ed25519 FIDO devices and Matrix-master/OMEMO attestations are deferred.

For a message author, the verifier MUST resolve attestation bytes by the signed
`author_attestation` content id using §6, never by "the current attestation for
this key" and never by fallback to a newer record. Fully verify that returned
attestation through this entire subpipeline, including its own subject key,
protected current binding, validity and registry-owner revocation. Then verify
current authority, attestation and snapshot evidence for EVERY message approver
in signature-array order. Only after all that message K1 evidence succeeds,
require its subject key id = `author` and its content id = `author_attestation`,
both byte for byte; otherwise refuse `author_attestation_mismatch` at the end
of K1, after earlier evidence refusals. Missing referenced bytes are unavailable.
Two concurrent valid attestations for the same key/generation are distinct;
only the referenced one may authenticate this message. Current binding includes
registration_number and master_epoch even when generation itself is unchanged.

A **grant-service** subject is a third `attestation/1` profile, distinct
from the purpose-5 signing-service root. Its `key_class` is exactly `service`,
`purpose` exactly `grant-service`, `roles` exactly `["author"]`, `actions`
exactly `["grant.sign"]`, algorithm exactly Ed25519. Its closed binding is
`{owner}` with the same independent 1–255 UTF-8-byte checks as device owners.
Its validity is positive and at most 86,400 seconds. The issuer is the exact
pinned grant-owner root, with an additional protected `grant-service` purpose
and owner bound to that same pin. This is an explicit additional language for
that root, not implicit promotion by a subject or a registry signature. Using
one existing grant authority avoids a fifth attestation root while the protected
purpose keeps ordinary grant-root possession/configuration from silently
selecting this profile. Required purpose/owner or attestation bytes absent/null
refuses `key_binding_unavailable`; malformed/incorrect evidence refuses
`key_binding_invalid` at K1. Resolve service attestations by the exact requested
key from a protected collection, verify the complete signed record, subject
identity, owner, profile, time and grant-owner snapshot. A service attestation
is identity evidence only, never a parent grant or action authority.

A grant-service key is its own D30 subject role. It MUST differ from every
protected root role, commit signer and enrollment publisher, and from keys
present in protected current-agent or operator-device collections. Check these
present-role collisions before signed evidence at K1/O2, or G7 as already
specified. The protected collections identify expected roles; an unsigned
`key_class` claim cannot select service verification. Agent attestations
presented in the service collection refuse even with otherwise valid crypto.
Service keys may sign only `grant/1`, never message, act, attestation, revocation
or checkpoint records. Known service and commit-signing keys are excluded at
the E6 profile gate. Root admission on evidence/checkpoint paths remains exact.
A service key issuing a link MUST have a parent grant addressed to that key,
with depth at least 1 and covering the child under all existing G3/G4 rules.
A self-rooted service chain refuses `grant_root_unknown`; attestation alone
never supplies the missing parent. Agent issuers remain forbidden under D24.

Grant-service keys and their attestations use the existing grant-owner signed
revocation domain. G7 still checks every chain issuer, subject and grant id;
K1 additionally checks the service key/attestation there. Expired or revoked
parent authority invalidates the whole chain, with no historical-iat bypass.
A leaf whose own interval remains current after its parent expires is already
non-narrowing; T2 at G2 wins before that later G4 failure. Such a compound is a
negative ordering witness, not an admissible lifetime exception.

D30 also reserves a **repository commit signer** role. Its protected key MUST
be distinct from all record roles and from the offline enrollment publisher;
the publisher MUST also differ from the registry key. Neither role is a
registry, grant or attestation root. Commit-signing keys are accepted by no
protocol-record verifier; low-level domain/signature math alone confers no
role admission. Git signatures authenticate storage/transport only. Existing
records need not configure unused roles, but every present pin is compared.

The caller supplies content-addressed signed agent attestation bytes, protected
current-attestation ids for grant agent subjects, device attestation bytes keyed
by device key id, the protected signing-service root/purpose, registry revocation
root/purpose/scope, and operator root, protected active
bindings, trusted time, and signed snapshots. A caller-supplied `valid` flag is
not attestation evidence. Missing/null maps, records, required fields or current
bindings return `key_binding_unavailable`; wrong types, invalid shape, crypto,
root, purpose, permissions, key derivation, mismatched/inactive binding or
validity return `key_binding_invalid`. A parsed record with a missing required
field returns unavailable; non-CCJ/invalidly encoded bytes return invalid.
For grant agent subjects, subject-key derivation remains against the requested
key before current-binding/revocation checks; a mismatch is key_binding_invalid.
The late author_attestation_mismatch code is specific to message authors.
Only complete cryptographically verified records proceed. Absence MUST NOT
compare equal to absence. Every refusal returns an empty plan.

Shared `revocation/1` is a complete signed snapshot for exactly one issuing
root. Its body is exactly `{type,issuer,issued_at,complete,entries}`:

- `type` is `revocation/1`; `issuer` equals the pinned root and signature key.
- `issued_at` is an exact timestamp; `complete` is a boolean and MUST be true.
- `entries` is an array of at most 64 closed `{kind,id,from}` objects. `kind`
  is `key` or `record`; `id` is respectively a canonical subject key id or
  content id (attestation, grant or act in this root authority domain). `from`
  is an exact timestamp. An empty list is valid only in a verified complete snapshot.

The purpose-5 signing-service root signs **only attestation/1 for agent keys**.
This restriction applies on every intake path: direct signers, attestation
issuers of all classes, and snapshot issuers in every authority domain.
The pairwise root-role rule above is enforced before consuming any such signed
evidence; in particular a purpose-5/operator overlap refuses at K1 or O2 with
`key_binding_invalid`, before device attestation or snapshot verification. Its key MUST
NOT sign message/grant/act profiles; conflicting additional pins cannot widen
that language (`signature_profile_invalid` at E6). For agent keys
and their attestations, revocation/1 MUST instead be signed by a separately
pinned registry-owner root. Its protected purpose is `registry-revocation`, and
protected configuration MUST bind it to the exact attestation root whose
subjects and records it may revoke. Its key MUST differ from that attestation
root. RootPolicy (§6) supplies the pin, purpose and scope; no key gains another
signing language implicitly. A purpose-5-root-signed revocation snapshot, a
revocation-root-signed attestation, wrong revoker purpose or wrong scope MUST
refuse `key_binding_invalid` at K1; missing policy is unavailable. The signing
service's binding revoke remains authoritative; snapshots distribute it.
Operator-device revocation is unchanged: the pinned operator root signs its
device attestations and its domain's revocation snapshots. Owner grant snapshots
remain signed by the pinned grant root. Each root is authorized only for its
explicitly configured record languages and authority domain.

Only the protected revocation issuer for that domain may revoke its
subjects/records. Key and attestation-id
revocations are cumulative across the complete snapshot sequence: issuers MUST
retain every entry, including future-effective entries, and MUST NOT remove it,
move `from` later, or issue a newer clearing snapshot. A changed snapshot MUST
have a strictly increasing `issued_at`; equal timestamps permit only identical
record retransmission. Continuity MUST fence conflicting same-time records as
well as rollback; unavailable continuity fails closed. A complete snapshot
cannot silently truncate entries to meet the wire bound. Matching works as
follows: either matching entry refuses from its stated time,
when `from <= max(now,W)`. Future entries have no effect before that boundary.
All entries MUST be structurally validated before evaluating any match. The
caller supplies rollback continuity and a positive integer maximum age <=60 s;
issued_at MUST be <=min(now,W), age measured at max(now,W). Unavailable/stale,
future-issued, incomplete or rolled-back snapshots return unavailable; invalid
snapshot encoding/signature/issuer returns invalid. No unsigned or default
empty set is accepted. The derived outcome remains exactly `not_revoked`,
`revoked`, `unavailable`; invalid evidence is a definite refusal, never a fourth
successful outcome. §6 maps these facts to intake-specific refusal codes.

Let S be `issued_at` of the first signed complete snapshot containing an entry,
A the configured maximum age (0 < A <=60 s), and F its `from`. Under these
cumulative, complete, unique-issuance and rollback-continuity rules, an already
effective entry takes effect at every conforming verification/effect gate no
later than S+A, and never before F (time is measured by the protected min/max
policy). Before S, this profile promises nothing about withdrawal: the issuer
has not signed its publication. Any snapshot omitting the entry must have an
issuance time strictly below S and is stale by S+A; every admissible snapshot
at or after S contains it. Missing or discontinuous evidence refuses as well.
For a future F > S+A the exact bound is max(S+A,F): it cannot take effect before
F, and by then an omitting snapshot is stale. An unqualified S+A deadline would
contradict a future `from`. This is a snapshot-distribution guarantee, not an
end-to-end platform completion promise or a guarantee before issuance.

Historical verification (whether a signature was valid at its claimed time)
is outside v0. Authorization checks current snapshots at verification/effect
admission. A self-declared old `iat` MUST NOT bypass a currently effective
revocation. Consumers MUST serialize snapshot currency with their effect gate.

Provenance is independent of chain position: the directly pinned owner grant
root wins first, even when it is an intermediate or leaf subject or also a
device. Otherwise an explicitly selected grant-service attestation under the
protected grant-root purpose/owner supplies service provenance; its D30 role
cannot overlap a root, current agent or operator device. Otherwise an
operator-device attestation under the pinned operator root supplies device
provenance; otherwise, for a subject/leaf only, an agent attestation under the
purpose-5 service root and current generation supplies agent provenance. A
verified agent used as an issuer refuses the profile at K1.
Algorithm or position alone never supplies provenance. Missing required
attestation refuses unavailable; a contradictory profile refuses invalid.
Every non-root issuer and subject, including the leaf, is checked (K19/K20);
no chain position enables agent grant issuance.
Attestation proves identity and its purpose-scoped signing profile, never grant
rights; all chain/action/target/revocation checks remain mandatory. The grant
signature role `author` denotes its chain-authorized issuer slot, not
an A2/A3 claim or permission to use a message signer for that domain. A separate
grant-domain signing provider remains required. A message signer
still MUST refuse grant/act/attestation/revocation domains; no new Keymaker
signing method is created here.

### 2.7 Identity journal and checkpoints

The following defaults are subject to content review (D33–D36). Git layout is
informative storage/transport and is not specified. Enrollment remains the
registrar's offline publisher-signed record; the registry references its
content id, never re-signs it or admits its contents through this journal.
A journal authenticates ordering/references, not the referenced record's
schema, provenance or action authority. Consumers must verify those records
under their original profiles before use.

An unsigned entry is exactly `{version,body,id}`; version is
`swarm-envelope/2`. No `signatures` member is permitted. The id is SHA-256 of
`swarma-registry journal-entry/1` + LF + CCJ-1(body). Its body is exactly:

| Member | Rule |
| --- | --- |
| `type` | `journal-entry/1` |
| `registry`, `owner` | Exact registry-owner key id and protected owner (1–255 UTF-8 bytes); registry is a key id, not a URL or repository name |
| `seq` | JSON integer 1–9007199254740991 |
| `prev` | Previous entry content id; null if and only if seq=1 |
| `at` | Exact §2.1 timestamp; non-decreasing across entries; copied verbatim by the external witness |
| `op` | Exactly `add` or `revoke` |
| `record_type` | Exactly `attestation/1`, `grant/1`, `revocation/1` or `enrollment/1` |
| `record` | Content id of the stored original signed record |

A checkpoint uses the four-member envelope, own exact tag
`swarma-registry checkpoint/1`, the existing content-id and signing-preimage
construction, and exactly one `author` signature by its body.registry. Its
body is exactly `{type,registry,owner,seq,head,at,snapshot}`. Type is
`checkpoint/1`; registry/owner/seq/at have the entry rules. `head` is the entry
id at seq. `snapshot` is the exact id of the caller-supplied current complete
registry-owner `revocation/1`. No `issuer` alias is added: this new profile
explicitly signs `registry`. Its pin is the existing D30 registry role, with
its existing registry-revocation purpose/scope. Neither commit signer nor
enrollment publisher is an alternative. Strict root crypto is mandatory.

Each complete entry/checkpoint is at most 8,192 bytes, depth16, with the shared
string and array bounds. Verify at most64 entries plus at most2 checkpoints
(candidate and optional fork evidence) per call, at most540672 received bytes.
This is a bounded suffix, not a limit on total journal length. The caller
supplies an already verified witness head-projection fact, exactly
`{registry_id,owner,registry_seq,registry_head,checkpoint_id,previous_checkpoint_id}`.
`registry_id` is the protected registry-owner root key id; owner is the exact
§2.6 owner. `registry_seq` is a positive safe integer; registry_head and both
non-null checkpoint references are content ids. previous_checkpoint_id is
null only for externally authorized registry genesis; otherwise it identifies
the last resolved predecessor and MUST differ from checkpoint_id. The external
witness verifier establishes that ancestry and any genesis authorization.
This API checks the exact shape, scope, bounds and reference encodings, not
witness wire, signature, publication or authorization. Missing/null facts
refuse unavailable; malformed facts refuse invalid. There is no seq0 anchor
or automatic bootstrap. A received self-asserted tuple is not evidence.
The external witness must preserve checkpoint.at verbatim: both journal and
checkpoint `at` use exactly §2.1's timestamp form, with no translation or
fractional precision. No timestamp is added to this six-field interface.

Every suffix advancing beyond registry_seq MUST start with the authenticated
prior-head entry (seq=registry_seq, id=registry_head). It occupies one of the64
entry places. Recompute its id and verify scope before using its timestamp.
Every subsequent seq is exactly previous+1, `prev` equals the previous id,
and `at` is non-decreasing from the anchor onward, never after checkpoint.at.
The anchor proves prior ENTRY time, not prior CHECKPOINT time.

For advancing calls, the protected id journal MUST also resolve exact prior
checkpoint bytes under witness.checkpoint_id. Authenticate their bounded
schema, id, registry root signature, scope and owner, then require their seq
and head equal the verified witness's registry_seq/registry_head. No current-age
rule applies to this prior evidence. Require candidate.at>=prior.at separately;
a missing/unavailable prior checkpoint refuses `journal_unavailable`, invalid
or mismatched bytes refuse `checkpoint_invalid`, backward checkpoint time
refuses `journal_rollback`. This is J5a after fork/sequence rollback and before
entry-anchor admission. Missing/wrong-position anchor refuses
`journal_anchor_required` at J6 before per-entry validation. No timestamp is
added to JournalWitness. Registry intake, witness bridges and other consumers
comparing entry times must supply both authenticated prior records; the
six-field projection alone supplies neither timestamp.

Recompute every entry id and bind registry/owner. Final seq/id MUST equal
checkpoint.seq/head. Non-advancing exact witnessed seq/head/checkpoint-id
retransmission needs no prior checkpoint bytes and may supply zero entries.
Candidate checkpoint and current snapshot are no older than protected
max_age<=60 seconds, neither issued in the future under min(now,W), and
snapshot.issued_at<=checkpoint.at. The existing complete, cumulative, unique
issued_at, freshness and rollback-continuity snapshot rules apply unchanged.
A stale/missing/discontinuous snapshot or required witness refuses; there is
no default empty revocation set.

Two fully admitted current checkpoints for the same registry/owner and seq
but different heads OR checkpoint content ids are fork evidence: return
`journal_fork` with empty plan. The protected projection at the same seq with
a different head OR checkpoint id is also a fork. A lower candidate seq than
registry_seq is `journal_rollback`. A consistent projection proceeds to the
bounded chain checks; equality of head alone never suppresses a checkpoint fork.
Authenticate the optional second checkpoint completely before using it as
fork evidence; corrupt unrelated bytes are not evidence of a fork. Invalid
entry ids/scope refuse `journal_entry_invalid`; discontinuous seq/prev/time or
final head refuses `journal_chain_broken`. The first-failure order is in §6.
Successful verification returns a candidate plan naming the checkpoint id and
watermark, not an effect or witness-update permit. The caller atomically
persists those exact verified checkpoint bytes and monotonic watermark before
using its journal view, and separately applies the witness owner's update
contract. Journal acceptance replaces neither id-binding nor replay journals.

Snapshot reissue uses decided D38 option B (§2.9): unchanged revocation/1
bytes stay outside the journal while a separate signed freshness record binds
them to the current checkpoint. A changed cumulative snapshot still requires
its new journal entry/checkpoint. The former option A (each unchanged reissue
gets its own journal entry/checkpoint and witness intent/commit) is rejected.
Inherited journal vectors remain generic format witnesses, not a publication
policy recommendation. Live publication transactions remain unqualified.

#### Checkpoint/2 and the complete-prefix index (D42)

The legacy /1 bodies above remain closed and byte-for-byte unchanged.
`checkpoint/2` uses the normal swarm-envelope/2 signed envelope, exactly one
registry-owner author signature, tag `swarma-registry checkpoint/2`, and the
exact body `{type,registry,owner,seq,head,at,snapshots}`. Type is checkpoint/2;
other scalar grammars are inherited. Content id is SHA-256(tag + LF +
CCJ-1(body)); signing bytes are tag + LF + CCJ-1({body,key,role,version}).
The registry signs currency selection, never another root's snapshot content.
The registry isolated signer accepts these closed /2 profiles only with protected
role pins; it never obtains pins from a received body.

`snapshots` is a closed ordered set of 1..3 closed objects
`{root_role,root_key_id,snapshot_id}`. Roles are exactly grant, operator and
registry-owner, sorted ascending by ASCII `(root_role,root_key_id)` (thus grant,
operator, registry-owner). Registry-owner is mandatory; the other two are
optional. Duplicate roles or keys, extra members and unsorted arrays refuse.
Every key must equal the corresponding protected GrantRoot, OperatorRoot or
AgentRevocationRoot.key pin, with wider D30 separation preserved. Snapshot ids
are canonical content ids. The CCJ-1 element byte template is
`{"root_key_id":"K","root_role":"grant","snapshot_id":"S"}`; K/S denote
substitutions, not literal valid ids. The array is these ordered elements joined
by commas inside brackets, without whitespace. A missing optional role removes
its whole element. No same-head freshness publication may change this set.

Each root's content remains its original own-root-signed revocation/1, journaled
as op=add, record_type=revocation/1, with its signature unchanged. Selected
content MUST equal that root's derived latest row at checkpoint.seq. A signed
list, matching freshness list, or witness head alone does not prove latest.
Option I requires protected persistent complete-prefix state plus a bounded
suffix. Option II, trusting the registry-signed list, is rejected: a compromised
registry could otherwise keep selecting older content after a newer revocation
is already in the authenticated journal, renewing the omission indefinitely.
Full-history audit supplements this admission check.

`Context.SnapshotJournal` is immutable Evidence with exactly `{anchor,entries}`.
Entries are raw []byte journal-entry/1 envelopes. Anchor is exactly
`{version,registry_id,owner,registry_seq,registry_head,checkpoint_id,latest}`,
version integer2. Latest contains one ASCII-role-sorted closed row for EVERY
configured D30 role, including roles omitted from the checkpoint:
`{root_role,root_key_id,snapshot_id,record_seq}`. A null snapshot_id paired with
record_seq0 means proven absence over the complete prefix, never an uninspected
role; otherwise id is a content id and 1<=record_seq<=registry_seq. Pins are
protected, pairwise distinct and exact. Changing configured roles/pins requires
requalification of the complete prefix. In particular, a /1 checkpoint's
registry-only coverage cannot seed missing grant/operator rows as absent.

Positive anchors bind the exact retained authenticated checkpoint/head. Only
explicit owner-qualified complete-prefix genesis uses integer registry_seq0,
JSON null registry_head/checkpoint_id and all latest rows null/zero. There is no
seq0 witness projection or automatic cold-store bootstrap. The exported
SnapshotJournalState has Version2 and positive endpoint strings; its JSON fields
are version,registry_id,owner,registry_seq,registry_head,checkpoint_id,latest,
matching positive anchor Evidence. Exported SnapshotJournalEntry.SnapshotID is
*string (nil encodes null); RecordSeq is int64. Genesis is constructed explicitly
as the Evidence map above, not by converting empty endpoint strings to null.

Resolve original signed bytes for every scanned add/revocation reference and
every non-null anchor row from protected IDJournal; missing originals refuse.
Verify id, issuer, signature, closed revocation/1 schema and entries. Non-role
issuers gain no authority or index row. Process EVERY gap-free journal position
through the exact target seq/head; originals in historical proof acquire no
current effect authority. At a positive advancing anchor the first envelope is
the already retained anchor entry and consumes one of64 positions, so normally
63 new entries fit. The exact prior checkpoint (including a qualified archival
checkpoint/1 during upgrade) authenticates its own time separately from the
anchor entry. Empty same-head proof requires an already qualified exact index.

D43: changed snapshots require strictly increasing issued_at and must extend
section2.6: every old (kind,id) remains with a from no later than its old value,
including future-effective entries. Both signed endpoint originals are required
to evaluate this relation. An add of the CURRENT id is a no-op retaining its
first record_seq. Re-adding an earlier id after newer content cannot pass the
strict issuance/cumulative relation. A revoke operation never exposes an earlier
row. Journal order alone and complete=true never prove cumulative continuity.
Selected snapshots still require independently qualified rollback-safe premises.

D44: longer catch-up uses batches satisfying all declared gates or external
complete-history provisioning qualified by the consumer's owner and bound to
the final independently authenticated checkpoint/head. No historical proof-only
batch API is defined. Ordinary VerifyJournal retains checkpoint age checks and
cannot qualify arbitrary stale intermediate checkpoints. No fabricated Now,
lowered witness, truncated suffix, partially staged authority or journal skip is
permitted; otherwise admission remains unavailable. Re-anchor skips only
freshness-publication continuity. Public VerifyJournal uses its entries argument
as the authoritative suffix; SnapshotJournal.entries is the F input, structurally
bounded on J but not a substitute for that argument.

D45 aggregate preflight: in addition to existing per-record8192/depth16,
journal64 and publication64 limits, a /2 call has a 2,097,152-byte charge cap.
Charge every raw argument occurrence, plus immutable Evidence costs for
SnapshotJournal, SignedSnapshots, IDJournal, FreshnessAnchor, JournalWitness,
AgentRevocationRoot, RegistryOwner, GrantRoot, OperatorRoot, ServiceRoot and
WitnessReadAt. Evidence costs are Present's deterministic accounting:16 per
value, UTF-8 bytes for strings/member names and raw length for byte slices,
recursively; duplicated copies are charged separately. Reserve65,536 additional
bytes inside the cap for endpoint/pin/index/audit/output inventory. Each Evidence
still has its own1,048,576 accounting cap/depth32. Every raw record in the three
snapshot/proof/original Evidence values is <=8192 bytes, including unused
retained originals. At J1/F1, complete every input size bound, including this
full charge and the embedded raw limits, before any current-candidate version
preflight or closed-body parsing. Use raw argument lengths and retained immutable
Evidence costs plus the reserve; do not build combined raw slices or parse
record bodies to calculate the charge. Every component is knowable up front;
there is no deferred residual charge. Over-capacity refuses freshness_malformed
for freshness/re-anchor or journal_malformed for journal, even with an
opposite-profile candidate. Over-capacity or truncated proof refuses before any
state advancement; individually maximal inputs need not fit together.
For storage sizing, canonical JSON/base64 representation has a separate
16,777,216-byte ceiling, and one staging plus one committed copy a33,554,432-byte
ceiling; these conservative ceilings include JSON escaping/base64 expansion,
not unbounded retained history. Consumers MUST preflight actual serialization,
metadata, staging/recovery copies, history retention and their smaller native
carrier/store quotas before signing or committing. The pure library enforces
raw/Evidence bounds; it does not allocate or qualify a durable store. History
retention cannot silently evict required proof to fit these per-call bounds.

Accepted /2 Plan.SnapshotJournal is a detached candidate state with version2;
all nested row pointers are copied. On /1 and every refusal it is nil/omitted.
Plan.IDs is a first-occurrence-deduplicated inventory: supplied publications in
order (F only), target checkpoint, selected snapshots in set order (F only),
index-anchor checkpoint when positive, anchor-row original ids in role order,
then suffix entry id and its add/revocation original id in journal order. J uses
its argument entries for this inventory. Unresolved non-revocation references
convey no record authority and are excluded; unrelated IDJournal originals are
charged but excluded. Retained publication endpoints not consumed as wire proof
remain independently required persistence/history dependencies, including the
old re-anchor endpoint. This inventory grants no admission or persistence right.

### 2.8 Snapshot capacity decision

The current domain still requires ONE complete cumulative signed snapshot,
at most64 entries AND at most8,192 bytes including signatures, whichever binds
first. For example65 entries already violate the common array cap; even64 may
exceed the wire limit depending on key/id lengths. There is no count-only
promise that64 entries fit. A producer MUST refuse an over-capacity publication
and retain the last durable complete state; never truncate, clear entries,
reset issuance/continuity, silently split a domain or publish partial success.
Consumers refuse oversized/count-overflow evidence at bounded parse: existing
`key_binding_invalid` at K1, `checkpoint_snapshot_invalid` at checkpoint intake, `revocation_invalid` at
G7, and no accepted plan. Stale last-good state becomes unavailable normally.
A small signed snapshot omitting retained entries is not made complete by its
flag: qualified caller continuity must reject it. Offline parsing alone cannot
establish cumulative retention.

Options: (a) pages under one signed head bound to every page digest, count,
completeness and issuance; (b) a Merkle root and inclusion/exclusion proofs;
(c) narrower independently pinned domains. Default (a) preserves cumulative
enumeration and can be audited without a new exclusion-proof algorithm. (b)
adds proof/canonical-tree and exclusion completeness rules; (c) changes authority
scope and risks gaps or silently discarded history. This slice adopts ONLY
the format direction and over-capacity refusal: no page/head wire profile,
tag or partial-page acceptance is implemented. A later reviewed profile must
bind the full page set, monotonic issued_at, cumulative/future-effective
entries, current max-age and rollback witness to ONE atomic complete head;
missing/mixed pages fail closed. Existing domains that fit are byte-unchanged.

### 2.9 Signed snapshot freshness (D38 B)

Owner decision, 2026-10-24: unchanged revocation/1 bytes remain outside the
journal. A separate registry-owner-signed freshness/1 names that unchanged
snapshot and the current witnessed checkpoint. Only this D30 role may sign it;
service, grant-owner, operator, purpose-5, offline publisher and commit keys
cannot supply freshness. A changed cumulative snapshot still needs a new
journal entry/checkpoint before a freshness record may extend it. No optional
member is added to the closed revocation/1 body.

The four-member envelope uses `swarm-envelope/2`, exact tag
`swarma-registry freshness/1`, normal content-id/signing construction and exactly
one registry `author` signature. Its closed body is:

| Member | Rule |
| --- | --- |
| `type` | Exactly `freshness/1` |
| `registry`, `owner` | Exact protected registry-owner root key id and §2.6 owner |
| `publication_seq` | Positive safe integer, exactly previous+1 |
| `prev` | Mandatory predecessor: previous freshness id for the SAME checkpoint head; null only for the first publication after that head (and publication_seq=1). Global publication_seq and issued_at still strictly increase across head changes |
| `issued_at` | Exact §2.1 timestamp, strictly increasing across publications |
| `snapshot` | Exact unchanged signed revocation/1 content id, equal to checkpoint.snapshot |
| `registry_seq`, `checkpoint_id` | Positive safe registry seq and content id of the exact current checkpoint |

A revocation consumer supplies a bounded oldest-first publication proof, current
signed checkpoint and signed snapshot, the already verified six-field witness
projection (§2.7), protected authenticated head-read time and retained publication
anchor. Verify every publication's exact root, signature, id and body, every
global sequence position and same-head predecessor link, strict issued_at
increase and monotonic registry reference. After a head advance prev MUST be
null; the global sequence still increments exactly+1, so a head change cannot
hide a missing publication. Within the same head, a missing predecessor is a gap.
At equal registry seq a different checkpoint id is a fork; at equal checkpoint
reference a different snapshot is invalid binding. A changed registry seq
requires a different checkpoint id. Same publication seq with a different
content id/binding is a fork, lower seq is rollback, missing intervening
positions or a wrong predecessor is a gap. Exact identical retransmission is
permitted, never an absence default. Full first-failure order is F1–F9 (§6).

Current tip.snapshot MUST equal the verified snapshot id AND checkpoint.snapshot;
its registry_seq/checkpoint_id MUST equal checkpoint.seq/id. Checkpoint root
signature and snapshot signature/schema/completeness are still mandatory.
Snapshot.issued_at<=checkpoint.at<=tip.issued_at. The current checkpoint may be
older than max_age only in this full freshness pipeline, provided a fresh
authenticated witness head read exactly matches its seq/head/id. A witness
behind the named checkpoint is unavailable; a candidate behind the current
witness is rollback; equal seq with another head/id is fork. No witness format
is parsed here and no freshness statement alone proves the current head.

§2.6's age rule is restated **only for this complete profile** as
`tip.issued_at <= min(now,W)` and `max(now,W)-tip.issued_at <= max_age`, with the
same protected positive integer max_age<=60s. The snapshot's own issued_at may
then be older than max_age; it MUST still be no later than the admitted
checkpoint and tip. A protected authenticated head-read timestamp MUST be
>=tip.issued_at and <=min(now,W), and its age at max(now,W) MUST be <=max_age. This protected timestamp MUST
belong to that exact authenticated registry/head/checkpoint projection read,
not an unrelated clock sample or a self-declared received value.
Missing, stale or future freshness/read evidence refuses unavailable. Provider
trust/freshness, durable watermark, complete cumulative snapshots, structural
validation before matching, future-effective entries, increasing unique
snapshot issuance and rollback-safe continuity all remain mandatory. A fresh
signature cannot clear cumulative entries or renew a changed snapshot that
fails the head binding. The §2.6 S+A bound concerns publication of changed
revocation state, not the age of an unchanged base renewed by this profile;
withholding before publication remains unbounded and D29 completion still
requires its durable barriers/acknowledgements or proven expiry.

The retained protected anchor is exactly
`{registry_id,owner,publication_seq,freshness_id,issued_at,snapshot,registry_seq,checkpoint_id}`.
It derives from the last accepted durable publication and its exact scoped
references. Missing anchor refuses; malformed anchor refuses invalid. Explicit
externally authorized publication-genesis provisioning alone may use
publication_seq0, freshness_id null and issued_at null, while still pinning an
authenticated positive registry_seq/checkpoint_id and snapshot. This is not a
seq0 witness projection or automatic cold-store bootstrap. Other anchor seqs
are positive safe integers with content ids and exact timestamp. Publication
genesis has no predecessor timestamp: the §2.1 minimum timestamp is valid for
its first publication. Strict time increase applies only against an actual
predecessor, including a predecessor at that minimum; exact retransmission
still preserves the accepted timestamp. The caller
qualifies anchor authenticity/continuity outside the registry failure domain.

At most64 publication records plus one checkpoint, each <=8192 received bytes,
depth16, <=532480 received bytes total, and at most64 queried ids/keys each.
Verify the entire bounded proof before any revocation match. Intermediate
records may be old: they prove complete signed hash-linked publication positions,
not historical authority; only the current tip supplies age. Historical
checkpoint/snapshot bodies are not re-admitted by proof references alone.
Current head ancestry/validity must already be established by the external
witness verifier, and changed snapshots must obey cumulative publication rules.
Missing history or an over-bound proof refuses on the normal chained path.
Publication continuity may be explicitly waived only by the recovery path below;
snapshot cumulative continuity and witness availability are never waived.

**Explicit re-anchor recovery (D41).** The default remains `VerifyFreshness`:
no failure automatically falls back to recovery. A consumer may automatically
invoke the separate `VerifyFreshnessReanchor(tip,checkpoint,ids,keys)` after
an outage exceeds its bounded chain, or explicitly choose recovery. This API
accepts exactly one signed tip and one checkpoint, using the same received-byte,
depth and query bounds. Its explicit invocation is the trigger, not an inferred
missing predecessor. It never treats a malformed or invalid supplied normal
proof as a successful chained proof. Publication genesis uses the normal path;
recovery requires a retained positive publication with a real timestamp and id.

F1–F7 and tip/read currency at F8 are unchanged: root signatures, current tip,
fresh authenticated witness read, complete cumulative snapshot, and exact
snapshot=checkpoint.snapshot=tip.snapshot bindings are mandatory. At F8R,
validate the retained scoped anchor, then compare the current witnessed registry
sequence with its registry_seq: lower refuses `freshness_rollback`; equal
requires the same checkpoint_id (otherwise `freshness_fork`) and snapshot
(otherwise `freshness_binding_mismatch`). The verified checkpoint content id
commits its registry head: equality with the retained id also requires the same
head; F7 separately compares the verified head/id to the fresh witness.
A higher registry_seq requires a different checkpoint_id. Next require
`T.publication_seq > A.publication_seq`, then `T.issued_at > A.issued_at`;
either failure refuses `freshness_rollback`. F9 query and effective revocation
matching still follow all these gates. No skipped predecessor/link or historical
signature is claimed verified. Normal F8 checks remain unchanged.

The candidate plan additionally carries `reanchor` with the exact members
`{reanchored,skipped_publications,old_freshness_id,new_freshness_id,old_checkpoint_id,new_checkpoint_id}`.
`reanchored` is explicitly true. `skipped_publications` is the integer
`T.publication_seq - A.publication_seq - 1`, counting positions strictly
between the two endpoints, not received records or registry journal positions.
It is emitted even when zero; explicit recovery may choose an adjacent tip.
The four ids name A and T and their checkpoint-bound heads. Normal plans omit
`reanchor` entirely. The consumer atomically persists the admitted tip as its
new anchor and the watermark, and durably logs this skip and both endpoint
heads via their freshness/checkpoint ids in the same acceptance transaction,
so later audit can cross-check the complete retained publication history.
Refusal, including revoked, returns a zero plan and changes no state.

Revocations are carried by the snapshot equal to checkpoint.snapshot, which
remains cumulative under §2.6; skipping freshness positions therefore cannot
hide a revocation. For a single head the snapshot and all authority-bearing
bindings remain identical: publications only advance publication_seq and
issued_at, with prev mechanically naming the preceding same-head publication.
The fresh witness attests the current head; rollback and fork against the stored
anchor still refuse. The publication-completeness cost and compensating issuer
and audit obligations are stated in §7. Recovery never extends authority or
cancels a revocation.

Successful `VerifyFreshness` returns a candidate plan naming every supplied
publication, then checkpoint and snapshot ids, with the monotonic watermark.
Caller atomically persists exact bytes, final anchor and watermark before using
not-revoked evidence and serializes authority currency with its effect gate.
A revocation match returns revoked with zero plan. No entry point commits or
performs effects. Consumers explicitly adopting B use this full subpipeline;
legacy snapshot APIs keep their own-issued_at age rule and cannot consume a
partial success or fabricated refreshed snapshot. Registry publication must
make all qualified publication positions available; signed hash continuity
proves completeness only from the supplied retained anchor through the tip,
not non-withholding before publication or a malicious issuer's unpublished tail.
It also cannot certify that a still-current supplied tip is the latest published
position: a newer published but withheld tail is undetected until the consumer
retains it. The bound supplied is tip age<=protected max_age, not proof of the
latest publication position. Retaining a newer position makes an older tip
rollback on subsequent admission. No additional tail-discovery mechanism is
defined here.
Live publication/effect integration and witness authentication remain separate.

#### Freshness/2 and one-way transition

`freshness/2` uses tag `swarma-registry freshness/2`, the unchanged normal
swarm-envelope/2 signing construction, one registry-owner author, and exactly
`{type,registry,owner,publication_seq,prev,issued_at,snapshots,registry_seq,checkpoint_id}`.
All scalar/publication rules are inherited. Snapshots has the checkpoint/2
ordered-set grammar and MUST equal the checkpoint list in length and EVERY
(role,key,id) element. All selected root originals pass signature/schema,
complete and independent cumulative/rollback-safe qualification, with
snapshot.issued_at<=checkpoint.at. They acquire only currency, never rewritten
content. A=min(max_age of INCLUDED roots), each integer0<max_age<=60; omitted
roots do not determine A. The current tip and authenticated witness read meet
the existing F age/ordering rules using A. F9 ids/keys still query only the
registry-owner snapshot; actual consumer grant/operator checks remain mandatory.
Before current-head comparison derive the full index and reject every non-latest
selected id, even when checkpoint and freshness agree on it.

Protected Context.RegistryCurrencyVersion is int:0/1 selects unchanged legacy /1;
2 selects /2 CURRENT CANDIDATE currency exclusively; other integers refuse at
J2/F2. A supported wrong-profile candidate refuses
registry_currency_version_mismatch at J1/F1 after bounded parsing. Preflight
checks every received current publication and both current checkpoint arguments
(primary and conflict) before closed-body validation. Dispatch uses the protected
pin; no candidate position chooses the profile. There is no
negotiation, fallback or current /1 receipt under pin2. The exact qualified /1
predecessor checkpoint and archived /1 publication bytes remain admissible only
as retained transition/history evidence. Retry never relabels or re-signs a /1
record. Producers construct new /2 records from the journal without editing
closed /1 records, labels or vectors. The upgrade does not authorize synthetic
journal changes or idle content reissue.

Explicitly setting pin2 permits a qualified /1 FreshnessAnchor as the one-way
upgrade predecessor. Singleton normalization describes its OLD registry coverage
only; all configured index rows must already be qualified from the complete
prefix. First checkpoint/2 advances registry_seq; another checkpoint at the same
position is not a migration. On the normal path the first /2 publication is
exactly old publication_seq+1, has later issued_at and prev=null on the advanced
head. If missing positions include /1 publications, normal chaining refuses;
explicit re-anchor may skip them with the existing positive-anchor/audit rules,
but cannot skip journal positions. Persist /2 anchor state thereafter, replacing
its old snapshot field by snapshots; other fields/genesis rules remain unchanged.
Protecting the version floor and fencing old instances is a consumer duty (§7).

Re-anchor /2 retains every F gate including the latest-prefix proof. At equal
registry_seq, checkpoint id and whole set are identical; at a higher sequence
the checkpoint changes and the qualified latest index covers that entire head.
If a grant/operator snapshot changed inside the skipped publication segment,
select its new latest id when included. Omission grants no waiver and cannot
remove its persistent index row. Candidate Reanchor additionally has detached
old_snapshots,new_snapshots,old_registry_currency_version and
new_registry_currency_version (2); old version may be1 on explicit upgrade.
These fields are omitted on /1. The original count and endpoint-id fields remain.
The consumer retains exact endpoint originals/heads and complete history for
later cross-check; skipped freshness forks are not proved absent.

### 2.10 Process-local freshness receipts (D41 composition)

Successful `VerifyFreshness` and `VerifyFreshnessReanchor` return an opaque
`*FreshnessReceipt` alongside the unchanged candidate Plan, only after every
F gate including effective revocation passes. Refusals have a zero Plan and
nil receipt. Only these producers mint receipts. The receipt is immutable,
process-local, has no constructor or accepted decoding/persistence format,
and cannot be supplied through `Present`. Result JSON omits it; direct receipt
JSON encoding and decoding refuse. Zero values, reflection allocations and
concrete struct copies lack provenance and refuse. Sharing the original pointer
is supported concurrently. Unsafe process memory modification is outside this
protected-process contract.

After accepting the producer transaction, the consumer atomically persists the
admitted tip anchor, watermark and any re-anchor audit, then supplies the pointer
as `Context.FreshnessReceipt`, the **admitted** anchor (not the old mint anchor),
the same immutable `SignedSnapshots` Evidence, and current protected facts.
Consumers MUST retain one immutable SignedSnapshots Evidence for the receipt's
lifetime. Rebuilding it, even byte-identically, invalidates the receipt. Rebuild
it whenever snapshot content or cumulative/rollback-safe qualification changes,
including a change later returning to the same ids or booleans. Re-run F after a
snapshot change, premise change, re-anchor or process restart. `complete=true`
is never proof of cumulative publication. The whole snapshot Evidence identity
is conservatively bound, not just a snapshot id or a caller generation counter.

Verification signatures do not change. Receipt handling is classified by entry
point, and a registry-root age waiver applies only when that path actually
admits the bound registry snapshot:

| Class | Entry points | Receipt behavior |
| --- | --- | --- |
| Consumers that may replace registry-root own-age | `VerifyAttestation` (agent), `VerifyMessage`, `Authorize`, `CheckRevocation`, `VerifyEnvelope` where applicable | Run R1–R3; only the bound registry snapshot can gain an age waiver |
| Validate-only | `VerifyAttestation(device=true)`, `VerifyOperator`, `VerifyServiceAttestation` | Run R1–R3; operator-root and grant-root own-age remain mandatory |
| Outside receipt mode | `VerifyJournal`, `VerifyFreshness`, `VerifyFreshnessReanchor` | Ignore Context receipt-consumption fields by design; independently run their complete verification contract |

For consumers and validate-only entry points, nil receipt with
`RequireFreshnessReceipt=false` retains legacy behavior and own-age refusal
ordering. Required absence refuses. Any supplied receipt selects receipt mode
and must validate even when own-age would pass: no failure falls back to legacy
admission. R runs after the entry point's existing trusted-time gate and before
validity continuation, including service identity admission. `CheckRevocation`
additionally requires its explicit root to equal the receipt root.

On outside-mode calls, `FreshnessReceipt`, `RequireFreshnessReceipt` and
`FreshnessMarginSeconds` are ignored, even if supplied or invalid. `VerifyJournal`
authenticates journal/checkpoint continuity and retains its snapshot own-age
checks; a receipt cannot substitute full F admission into that API. The two F
producers independently authenticate the complete normal/recovery proof, so a
prior receipt is neither a prerequisite nor evidence for issuing a new one.
They mint a new receipt only on full success. `New` only stores Context; the
subsequent verification method determines receipt handling. Context-free
`Present`, `Evidence.IsAvailable`, `OperatorRecordCode` and receipt
Audit/JSON methods perform no receipt-consuming admission: Present and receipt
JSON methods retain their receipt rejection rules, and Audit reports origin
only, never current validity or an age waiver.

R validates the protected registry root and owner; exact snapshot bytes/id and
immutable Evidence premise; current witness registry/owner/checkpoint id,
sequence and head; and the admitted anchor's tip id/time/publication sequence,
snapshot, checkpoint and registry sequence. Current `WitnessReadAt` must be
well-formed, no later than min(now,W), and no earlier than its issuing read.
Required missing current facts refuse; malformed facts and foreign bindings
remain distinct. Normal snapshot signature, typed schema, completeness,
rollback-safe qualification, all entry validation and effective matching stay
mandatory. Only the bound **registry-root snapshot's own-age** test is replaced.
These /1 grant-root and operator-root own-age tests remain unchanged.
The separate /2 composition below implements D42(a).

Let A be the protected max_age at issuance, at most60 seconds. Store fixed
`E=min(tip.issued_at+A, issuing WitnessReadAt+A)`. Receipt use requires
`max(now,W) < E - delta`, where Context.FreshnessMarginSeconds is an integer
0..60 (default0); a margin only tightens admission. Newer witness reads never
extend E. All existing trusted clock/watermark and non-future checks apply;
there is no ambient clock. F's inherited inclusive age boundary is unchanged:
a receipt minted at exactly E is already unusable by a consumer.

`receipt.Audit() (FreshnessAudit,bool)` returns detached registry/owner,
snapshot/checkpoint/freshness ids, re-anchored status and old freshness/checkpoint
ids when applicable. Current ids name the new endpoint; checkpoint ids commit
both heads. The bool reports authentic origin only, never currency or authority.
Changing the audit value cannot change admission. No receipt grants Commit or
an effect permit; repeat current checks at the serialized effect boundary.
Offline vectors contain actual signed F inputs plus mint/use contexts and a
consumer operation. Both implementations run F and derive a receipt internally;
serialized private receipt fields or a verified=true assertion confer nothing.

#### Root-specific /2 composition

The /1 classification and JSON bytes above stay unchanged. Under pin2 the
receipt binds version, protected pins/policies, the whole sorted set, exact
selected bytes, the derived complete-prefix state, and BOTH original immutable
Evidence identities (SignedSnapshots and SnapshotJournal), in addition to the
existing witness/read and admitted-anchor bindings. Persist the derived index
separately; advancing it never replaces the receipt's original proof premise.
Rebuilding either Evidence, even to equal-looking values, invalidates that
receipt. Reconstruct inputs and run full F to remint after restart or premise,
head, version or pin changes. A returned candidate is not durable acknowledgment.

| /2 consumer | Own-age slots eligible for exact covered-root waiver |
| --- | --- |
| VerifyAttestation, agent | Registry-owner |
| VerifyAttestation, device | Operator |
| VerifyMessage | Registry-owner and reached operator-device approvers |
| Authorize | Grant and reached operator/registry-owner signer checks |
| VerifyOperator | Operator |
| VerifyServiceAttestation | Grant; direct consumerFacts route retained |
| CheckRevocation | The explicit protected root |
| VerifyEnvelope | Only its typed record's existing checks |
| VerifyJournal, VerifyFreshness, VerifyFreshnessReanchor | Independent proof/producer paths; ignore receipt options |
| New, Present, IsAvailable, Audit, serialization, OperatorRecordCode | No admission/waiver |

A supplied receipt is globally validated through R before any own-age waiver,
even when optional. At the checked root's own-age slot waive ONLY the exact
covered root/id. A valid receipt missing that root refuses
freshness_receipt_unavailable when required; if optional, that invocation's
ordinary own-age check stays active. This is never a retry with the receipt
removed. Invalid, expired, foreign or rebuilt-premise supplied receipts always
refuse globally. All other authority, signature, cumulative, effective-revocation,
generation and replay checks remain. Future-effective entries can become active
while a receipt is still live. Fixed E=min(tip.issued_at+A,mint_read+A), exclusive
max(now,W)<E-margin and no extension by later reads remain unchanged.

Existing method signatures are unchanged. New Context members are
RegistryCurrencyVersion int and SnapshotJournal Evidence; Plan adds
SnapshotJournal *SnapshotJournalState. SnapshotBinding has RootRole,RootKeyID,
SnapshotID strings. FreshnessAudit adds RegistryCurrencyVersion int and a detached
Snapshots []SnapshotBinding; legacy SnapshotID continues to mean registry-owner
only. Audit() (FreshnessAudit,bool) still reports origin, not authority. /2 audit
JSON adds registry_currency_version:2 and snapshots; these members are omitted
on /1, preserving its original eight members and serialization. /2 plan state
uses its explicit version2 serialization; /1 plans and local /1 state-digest
encoding MUST remain unchanged. Consumer state migration uses a versioned codec.

## 3. General grant/1

### 3.1 Closed v0 body

Agent keys MUST NOT be issuers in v0 (§2.4); they remain admissible as subjects
and leaves. Parent delegation does not widen a key's signing profile. A
non-root issuing device requires its operator attestation and current authority;
a grant-service issuer requires its explicit service attestation and a covering
parent grant under §2.6. Neither class is a root by attestation alone.

In addition to common members a grant has exactly:

| Member | Constraint |
| --- | --- |
| `issuer`, `subject` | Key ids from §2.3. No role, UID, label, group or generation subject in this slice. |
| `actions` | Nonempty, sorted unique array of registered exact action strings. No wildcard actions. |
| `targets` | Nonempty array of distinct typed targets, each independently meaningful; no Cartesian-product inference. |
| `not_before`, `expires` | Valid timestamps, `not_before < expires`; MUST equal `iat`, `exp` respectively. |
| `depth` | Integer 0–3: number of further delegations permitted. |
| `parent` | Parent envelope id, or null only at root. |
| `min_assurance` | Exactly `{level:"A1"|"A2"|"A3",presence:boolean}`; required, no default on the wire. |
| `caveats` | null, or exactly `{lang:"caveats/v1",not_before:time,expires:time}`. |

Grant targets and message targets admit only `credential` and `station`.
Operator targets (`registration` with a positive integer id, and `account`)
are a separate domain. An operator-only or unknown target kind inside a grant
or message MUST refuse `envelope_malformed` at E2, before crypto, chain edges
or containment. `grant_target_invalid` at G5 instead means a structurally valid
grant target kind is incompatible with its action (for example, station with
credential.lease). No integer operator id reaches grant prefix containment.

The initial closed action vocabulary and target types are:

| Action | Target |
| --- | --- |
| `credential.lease` | `{kind:"credential",id:account-id,harness:identifier,profile:identifier}` |
| `agent.spawn` | `{kind:"station",id:station-id}` |
| `message.deliver` | `{kind:"station",id:station-id}` |

The latter action authorizes delivery only, never execution of free text. New
actions require a reviewed vocabulary version; no dynamic registry or
`action-namespace/1` is published. A grant MUST have an applicable target for
each action and no target kind outside its actions' kinds. Operator acts are
separate pinned-owner authority and do not acquire authority from this table.

Identifiers use nonempty slash-separated segments `[a-z0-9-]+`, at most 255
ASCII bytes. Harness/profile are single segments. Only grant target `id` may
end in `/*`: it matches descendants with at least one nonempty segment, never
the prefix itself. No other glob, regex, escaping or normalization exists.
A concrete request MUST name exactly one target and contain no wildcard.
Targets of different kinds never contain each other; credential containment
also requires equal harness and profile. A child exact id is contained by an
equal exact parent or a matching parent prefix. A child prefix is contained
only by an equal or ancestor parent prefix. Every child target MUST be
contained by one parent target; splitting coverage across tuples is forbidden.

`caveats/v1` supports only a time interval inside the grant lifetime. Counters,
other presence caveats, rule languages, roles, nondelegable flags and Biscuit
are deferred and MUST refuse. Effective start is max(not_before,caveat start),
end is min(expires,caveat end); null uses the grant window.

### 3.2 Chain and request verification

The closed concrete request is exactly `{key,action,target}`. G1 requires a
canonical key id, a string action and a target object with string kind/id and,
for credential, string harness/profile; target member names are closed by kind.
Wrong field types or member sets return `grant_chain_malformed` at G1. Concrete
identifier syntax, wildcard exclusion and supported target kind are checked at
G8 (`request_target_invalid`), followed by registered action and coverage. This
keeps an invalid request type out of every hash/membership operation.

Chains are leaf first, 1–4 signed envelopes, with no repeated ids or unrelated
records. Every envelope, including the leaf, MUST pass §2 and the checks below.
For every child/parent pair: child.parent MUST equal parent.id; child.issuer
MUST equal parent.subject; actions MUST be a subset; every target MUST be
contained; raw AND effective lifetimes MUST be subsets; audience MUST equal;
child.depth MUST be strictly less than parent.depth. Its `min_assurance.level`
MUST stay equal or increase under A1 < A2 < A3; a true parent presence flag
MUST remain true. A child lowering either requirement is not narrowing. A depth-zero parent cannot
have a child. The last record MUST have parent null and issuer equal to a
protected pinned owner root. A self-signed key without that pin is not a root.

Every link's issuer, subject and envelope id MUST be checked for revocation.
The leaf subject MUST equal the authenticated requesting key. The concrete
request action MUST be registered and allowed by the leaf and its target MUST
be contained by a leaf target. Both the dispatcher/caller chains remain
separate when a consumer requires their intersection; never concatenate them
or let a service signature erase the original caller's authority.

After concrete request coverage, G9 MUST compare established request assurance
against the leaf minimum in its own step. The caller supplies a protected
`{level,presence}` result, independently established for this exact request;
request text, grant fields and unsigned assertions cannot establish it. Missing
or wrongly typed evidence refuses `grant_assurance_unavailable`; lower level
or absent required presence refuses `grant_assurance_insufficient`. A higher
established level meets a lower minimum; a higher child minimum tightens rights.
A1 agent origin alone meets no A2/A3 minimum. A3 minima are representable dormant
constraints, but no v0 provider establishes A3: an asserted A3 result MUST return
`grant_assurance_unavailable`. The interface accepts no provider
qualification boolean to bypass §4's activation gate. Synthetic A2/presence
controls test comparison only, not live provider qualification.

### 3.3 Time, revocation and rollback

Time MUST come from the caller's shared platform time-policy provider, using
[the pinned policy proposal](https://github.com/relux-works/swarma-credential-broker/blob/95d21093dd4265d54cb13c8a4770229b2b6b3835/docs/time-policy.md).
This is a proposal dependency, not a shipped API. The caller supplies a fresh
`Sample`/`StartSample` decision: Now, AuthorityUntil, Uncertainty, Boot, Trusted,
Fresh, and continuity evidence. Untrusted, stale, held, unavailable or expired
samples MUST refuse. The provider owns source selection, stricter-only policy,
NTS evidence, hold recovery and process continuity; waggle MUST NOT pick a
clock source or clear a hold. Re-check provider authority at effect admission.

Let now be the sample time and W the durable watermark. Expiry is exclusive
and evaluated at max(now,W); starts inclusive at min(now,W). Thus rollback
cannot resurrect an expired grant, and forward movement cannot bypass a start.
Apply this to every raw/effective grant window, and act/message iat/exp.
A missing/unreadable/rolled-back watermark MUST refuse; bootstrap is an
explicit protected operator procedure. A result carries candidate watermark
max(now,W); the caller MUST durably advance it before an effect. Watermark
persistence failure refuses, never falls back to wall time. Uncertainty and
cross-process continuity remain the provider's requirements, not inferred from W.

Revocation has exactly `not_revoked`, `revoked`, `unavailable`. Only the first
permits progress. The caller supplies cryptographically verified §2.6 signed current snapshots for the
owner domain, their completeness, freshness and rollback witness; no network or
owner registry exists in this slice. A protected maximum age is REQUIRED and
MUST be at most 60 seconds; older or unavailable evidence is `unavailable`.
Snapshot issuance MUST NOT be in the future relative to min(now,W); its age is
measured at max(now,W). A readable old snapshot is not freshness proof.
Final checks MUST be serialized with the caller's revocation publication and
effect boundary. Restore fencing MUST survive outside the restored failure
domain; missing history keeps authority unavailable. No default empty set.
Revocation cannot erase an already delivered vendor credential.

### 3.4 Broker differences and adapter

This general `grant/1` is NOT the closed broker envelope with signing domain
`swarma-credential-broker grant/1`. Broker v0 R1 remains static UID admission;
no grant is admitted to that implementation by this document.

| Area | Broker §§6–8 proposal | This slice / required adapter treatment |
| --- | --- | --- |
| Canonicalization, id | CCJ-1, domain + LF + body, sha256 id | Same byte algorithm; new domain `swarma-waggle grant/1` produces new ids. |
| Container/signature | `{body,id,sig}`; issuer Ed25519 over id preimage | Adds version, signatures array and signed record binding role/key/version/body (§2.2); re-sign, never relabel. Adds P-256 low-S for authority keys; agent keys remain Ed25519. |
| Common fields | type in body; no aud/nonce/iat/exp | Adds all four; iat/exp equal grant interval. Adapter MUST supply explicit bounded values. |
| Subject | key or generation-bound `agent:` leaf | Keys only; agent keys need root-signed attestation/1 and current generation (§2.6). No silent UID/generation conversion. Generation binding in broker records still needs a separately versioned consumer adapter. |
| Actions | `credential.lease`, `agent.spawn` | Adds `message.deliver`; broker adapter MUST refuse it. |
| Targets | Separate exact accounts/harnesses/profiles lists | Typed correlated tuples; prefix ids allowed here, refused by broker. Enumerate exact Cartesian tuples only when source rights actually permit that product. |
| Harness/profile spelling | Broker includes the harness name `claude_code` | Single-segment grammar here excludes underscore. This is a representation narrowing, not an exact-string adapter. Never silently normalize to `claude-code`: a future versioned consumer adapter needs an explicit approved one-to-one name map, collision/unknown-name refusal and reissued signed grants; until then refuse the unsupported source name. |
| Interval | not_before, expires_at | not_before, expires; exact UTC seconds, equal common iat/exp. No lossy rounding. |
| Depth/parent | Remaining depth, leaf-first, at most four | Same chain structure; depth explicitly 0–3. Every leaf edge remains checked. |
| Conditions | Time only, no role/wildcard/presence | Time-only caveats/v1 plus required min_assurance level/presence. Adapter MUST preserve equal/tighter minima; unrepresentable presence/assurance refuses, never silently drops them. |
| Root/revocation | Configured broker root; local grant/key revocations | Pinned roots, root-issued attestation/1 and signed shared revocation/1 (new exact domains); operator devices attested by the operator root. Retain old revocation authority and old-id/new-id mapping, including effective-from times. No historical bypass. |
| Bindings | Generation leaf plus separate caller chain/intersection | Adapter MUST preserve both dependencies and generation checks; key grant alone cannot replace them. |
| Renewal/release | Repeat chains, ledger, account/profile, freeze and restore gates | All remain consumer gates; a generic accept is insufficient for material release. |

A future migration MUST be one versioned adapter with explicit start/end times,
old/new root pins and id mapping: validate source rights and revocations, obtain
fresh signatures under the new domain, durably revoke/map old records and
replace bindings without lease carry-over. Both roots MAY be accepted only
inside a bounded transition, with both revocation histories checked and no
union that widens rights. At its end old roots MUST refuse. Unrepresentable
predicates or generation subjects MUST refuse until the consumer adapter is
published; a format rewrite cannot authorize them. This slice publishes no
broker migration executable or new binding wire fields.

## 4. operator-act/1

The device signer provider MUST sign the exact raw S0 preimage using P-256
low-S (§2.4), not a FIDO/WebAuthn assertion construction. Assertion wrappers
and signatures over authenticatorData || SHA-256(clientDataJSON) refuse even
when their challenge contains this preimage or its content id. A raw-preimage
signature by the same device key remains the positive control.

### 4.1 Body and authority

In addition to common members, exactly:

| Member | Constraint |
| --- | --- |
| `operation` | Exact consumer-registered operation. |
| `target` | One concrete typed target, no pattern. Registration uses `{kind:"registration",id:registration-number}`, where the id is a positive safe JSON integer, never a string. |
| `owner` | Exact protected configured owner identifier, nonempty UTF-8, at most 255 bytes; no normalization. |
| `epoch` | Exact protected epoch identifier, 1–255 printable ASCII bytes without whitespace. |
| `action_id` | Canonical base64url 16 random bytes; single use per consuming service. |
| `arguments_digest` | `sha256:` + lowercase hex SHA-256(CCJ-1(canonical operation arguments)); no domain or trailing LF. |
| `confirmed` | Boolean signed assertion that exact-content confirmation occurred. |

Only P-256 device keys attested by the pinned operator root may sign this type (§§2.4, 2.6).
Only protected consumer operation policy classifies widening versus narrowing;
the sender MUST NOT select that class. v0 profiles here are Keymaker `revoke`
(narrowing) and illustrative `grant.issue` on an account (widening, no broker
activation). Other operations require a published consumer profile and arguments
schema before admission. Unknown operations MUST refuse. An attested device key
MUST be authorized for this owner, current and not revoked. Neither login to an
operator account nor an arbitrary key in a chain makes an act valid.

Key currency and presence-enrollment currency are separate caller facts.
`SignerFacts.current` means the attested key remains currently authorized for the
owner; false MUST refuse `key_binding_invalid` for every act, including narrowing
(and any message approval). Missing key currency MUST refuse
`key_binding_unavailable`. Revocation remains a separate mandatory check.
`SignerFacts.presence_current` means the provider's presence-enrollment evidence
is current. Its absence/false requires `act_presence_required` for widening;
narrowing may proceed with a current key without this evidence and claims no A3.

Widening MUST require `confirmed=true` AND current trusted signer-provider
enrollment evidence that the attested key requires user presence for each use and
renders/binds the exact operation, target, owner, epoch, audience, action id,
arguments and time bounds before signing. A self-asserted boolean alone is
insufficient. This slice specifies that provider obligation; it does not invent
an attestation, phone app, biometric transport or platform mechanism. If the
provider cannot establish it, widening MUST refuse. Narrowing MAY set confirmed
false, but still requires the attested key signature and current authority.
**v0 activation ruling:** no signer provider is qualified for A3. Every
otherwise valid widening act MUST refuse `act_a3_inactive`, after existing
confirmation, presence and replay checks, with no persistence/effect plan.
Neither `confirmed=true` nor supplied presence/current facts can open this gate.
Narrowing remains usable and claims no A3. Future qualification is a separately
reviewed version/activation change: the provider interface must bind the exact
content and current owner/device, enforce presence per use, render the exact
operation/target/arguments/audience/time, and supply auditable enrollment,
revocation and replay evidence. S0 defines this obligation only.

An unsigned terminal fallback yields no operator-act/1. A consumer may define a
separate authenticated unsigned narrowing path; Keymaker persistent revoke has
none. Widening MUST NOT use an unsigned fallback or an agent session.

### 4.2 Keymaker operator_record, exact mapping

The whole envelope object is Keymaker's opaque `operator_record` parameter on
native surface B. No wrapper, base64 string or extra request parameter is added.
`register` requires operator-principal intake, no signed act in v0. Only
`revoke {registration_number,mode:"operator",operator_record}` consumes this
profile, including persistent revoke; `mode:"ephemeral"` requires null and
retains its own registrant/retirement checks. This profile consumes no widening.

| Verified field / input | Exact binding |
| --- | --- |
| expected type / role | operator-act/1 / approver |
| operation | `revoke` |
| target | `{kind:"registration",id:registration_number}` from request; preserve its positive safe integer type |
| owner | Owner in protected registration binding, never caller override |
| epoch | Binding `master_epoch` returned by pubkey/register (the semantic epoch) |
| action_id | New single-use id, journal namespace of the Keymaker installation |
| arguments_digest | SHA-256(CCJ-1({registration_number: request.registration_number, mode: "operator"})) |
| aud | Exact protected consuming Keymaker installation identifier |
| nonce | New 16-byte value signed with all other fields; not a replacement for action_id |
| iat / exp | Not future, not expired, at most 120 seconds under §3.3 |
| signing key / revocation | Pinned operator root, verified P-256 operator-device attestation for that owner, current signed issuer snapshot and current owner authority |
| confirmed | May be false: persistent revoke is narrowing |

The caller supplies trusted time, protected operator root, device attestation, owner and binding epoch,
revocation evidence, id bytes journal and durable used-action journal. Missing
verifier/evidence, unavailable revocation/time/watermark/key policy/journal or failed state
commit maps to `operator_record_unavailable` (including `key_binding_unavailable` if required
by an adapter). Malformation, bad signature,
foreign key/root, wrong binding/audience/epoch/arguments, expiry/future time,
replay, invalid delegation/attenuation or any other definite invalidity maps to
`operator_record_invalid`. Fine reasons MUST stay in local audit. No new
Keymaker wire refusal codes are introduced. This section supplies the format
part of Q7; the future verifier and durable caller integration remain activation
gates. It MUST NOT be cited as evidence that Q7's runtime gate is already green.

The act including signatures MUST be <= 8,192 received bytes and depth <=16.
For the Keymaker profile the producer MUST publish a CCJ-1 canonical envelope
initially: native surface B requires the complete request to be canonical,
unlike a generic envelope receiver. Embedding that already canonical object
MUST preserve its exact bytes. Whitespace-tolerant standalone vectors are not
permission to send a noncanonical native frame.

With `method:"revoke"`, mode `operator`, a positive safe integer registration
number (at most 16 decimal digits), 32 lowercase hexadecimal request-id digits
and timeout_ms <=2000, the closed native request adds at most 172 bytes around
the object. Therefore payload <=8,364 bytes (8,368 with its 4-byte frame header),
well below the 65,536-byte payload limit. The act's closed schema has at most
three container levels; embedding under params adds two, at most five total.
The adapter MUST still enforce the complete request's 65,536-byte/depth-16 caps,
and MUST NOT add fields, pretty-print or add signatures after publication.

### 4.3 Replay and effect boundary

The journal key is `(protected consumer installation id, action_id)` across all
operator keys, owners, epochs and operations of that consumer. A second use
MUST refuse `act_replay`, including the identical act. It MUST NOT execute a
second effect. Different audience consumers cannot accept the same act because
audience equality is mandatory. Nonce equality does not make two acts equivalent.

The pure validator returns a plan; it never reserves or writes. The caller MUST
atomically reserve the action id, retain the complete act/binding digest and
advance the watermark before the effect. Concurrent attempts MUST yield at
most one reservation. Lost replies/partial effects MUST be reconciled from the
consumer's durable operation journal, never by allocating a fresh act and
blindly retrying. Reservation is not effect completion. Failed/unavailable
reservation refuses before effect; a consumed id MUST NOT be released for reuse.
Retain action ids through the admissible window and rollback/restore horizon;
missing history MUST fence, not report unused. Keymaker's existing outer
request-id retry returns its durable original outcome; it is not a new act
admission and MUST NOT re-run the effect or bypass conflicting-argument checks.

## 5. Human assurance and transport

A1 means authenticated origin: an `author` signature from a currently attested
agent key establishes A1 provenance. Its content remains peer data; this MUST
NOT approve a session, create authority or permit a critical action. Carrier
E2EE is another possible A1 mechanism and remains outside this slice.
A2 means a person's authenticated key signs exact content and the consumer
verifies its current authorization for the concrete action and target. It does
not prove a person saw or wrote the content. Agent authors do not become A2
merely because their signatures or grant chains verify.
A3 additionally requires a qualified exact-content, presence-enforcing provider
and the operator act path. No provider is qualified in v0; §4's widening gate
is closed. Narrowing persistent revoke remains supported without claiming A3.
Software signatures or a claimed confirmation/presence flag do not prove A3.
Owner decision, 2026-10-24: A3 qualification requires a qualified signer app
and platform provider with a written threat model, plus hardware/provider
attestation where the platform provides it. The first profile to qualify is
one phone secure-enclave P-256 key using iOS Secure Enclave. This is the selected
qualification target, not a qualified provider. Until that review is satisfied,
widening remains closed under §4; no supplied boolean or software signature
activates it. S0 defines no enrollment or platform-attestation mechanism.

This document provides no confidentiality or device/app enrollment protocol.

A Matrix adapter MUST carry the completed envelope under the exact event-content
key `works.relux.swarm.envelope`, as unchanged bytes or a reversible byte encoding.
It MUST bind `room` to the actual room id, `to` to the full verified recipient,
and hash the actual human-readable event text bytes. It MUST NOT reconstruct
JSON, substitute display names or derive authority from the event sender.
Consumers enforce §2's envelope limit independently of Matrix limits. The
transport owner must publish the event byte budget and, if needed, an
authenticated content-addressed pointer form with bounded retrieval, exact hash
verification, audience and retention rules. Until then oversized events refuse;
no truncation or untrusted-URL fetch. The content key is fixed here; event budget
and pointer grammar remain transport-owned.

## 6. Future verifier contract and refusal order

The next slice MUST expose pure functions for parsing/canonicalization,
envelope verification, chain authorization and operator validation. No I/O,
network, global mutable state, private keys, ambient clock or automatic fetching.
Inputs are exact bytes and immutable caller-owned snapshots. Caller-supplied
clock, watermark store, revocation source, id journal, replay journal and
signer-assurance interfaces are resolved by the application; the pure core
receives their explicit values and returns a decision plus persistence plan.
Mutable store methods belong to the application adapter, not hidden calls from
a supposedly pure verifier. This follows the registrar public-package boundary.

Required abstract contracts (API names in the next slice may differ):

```text
TimePolicy.Sample / StartSample -> sample | unavailable
Watermark.Load -> value + continuity | unavailable
Revocations.Verify(signed_snapshot,pinned_issuer,ids,keys,sample,continuity)
  -> not_revoked | revoked | unavailable (invalid bytes/signature refuse)
IdJournal.Lookup(id) -> absent | exact_bytes | unavailable
Replay.Lookup(consumer,action_id) -> unused | used | unavailable
SignerFacts.Lookup(owner,key) -> current + presence_current + presence_policy | unavailable
Attestations.Lookup(content_id) -> exact signed agent attestation/1 bytes | unavailable
DeviceAttestations.Lookup(key_id) -> exact signed device attestation/1 bytes | unavailable
CurrentGeneration.Lookup(key_id) -> typed active binding + current_attestation_id | unavailable
RootPolicy.Lookup(purpose,owner) -> protected attestation/operator/grant root pin | unavailable
RootPolicy.CheckDistinctRoles -> distinct | key_binding_invalid
  (all four present role pins; before any signed evidence intake)
RootPolicy.AgentRevoker(attestation_root) -> registry-owner key + purpose registry-revocation
  + exact attestation_root scope | unavailable
SignedSnapshots.Lookup(issuer) -> exact signed revocation/1 + continuity + max_age | unavailable
EstablishedAssurance.Lookup(exact_request) -> level + presence | unavailable
DeliveryContext.Lookup -> actual room + full recipient + exact text bytes | unavailable
Commit(plan) -> atomic reserve + durable watermark + id binding | conflict | unavailable
OnlineAuthority.Check(exact_request) -> current | revoked | unavailable
  (application adapter contacts the authority owner immediately before a critical effect)
```

The separate registry is an application-side source of the signed records
and continuity evidence above, not an authority override or a network dependency
inside the pure core. If the registry or a required snapshot is unavailable,
its adapter MUST report `unavailable`; the existing fail-closed rules below
apply with no new refusal code. Valid caller-supplied snapshots in the current
mode remain subject to the same protected freshness and continuity checks.

All errors and absent required evidence MUST become explicit decisions; absence
is not false or an empty set. These are interface requirements, not storage or
network implementations. An accept from the pure core MUST NOT be exposed as
an effect permit until Commit succeeds and current time/revocation/binding
checks are repeated at the consumer's serialized effect boundary.

Owner decision, 2026-10-24: for effects selected as critical by protected
consumer policy, the application adapter MUST perform `OnlineAuthority.Check`
with the authority owner for the exact request immediately before the effect,
at its serialized effect boundary. Only `current` may proceed; `revoked` or
`unavailable` MUST refuse. Consumer policy selects critical effects; the sender
cannot select the class. This is an abstract interface and consumer obligation,
not network I/O inside the pure verifier or an implemented protocol. §7 lists
its activation gates; offline candidate plans cannot qualify this boundary.

The first failing row wins. Within a row evaluate envelopes leaf first and
fields in the order stated. Envelope structure precedes semantic crypto; nested
evidence follows the exact subpipeline in §2.6. Signature
entries are checked in array order. Codes are distinct per listed substep:

Receipt mode inserts R1–R3 immediately after the consuming path's existing
trusted-time/watermark gate and before validity/admission continuation, including
direct attestation/revocation APIs and operator-only paths. Earlier envelope or
signed-evidence failures retain precedence. Snapshot crypto/schema/entry slots
remain in place; exact snapshot id is rechecked at the replaced own-age slot.
Receipt codes pass through K1/G7/O2 unchanged. VerifyAttestation returns zero
identity plus the exact record.Error; CheckRevocation returns Unavailable plus
that error. No-receipt legacy paths insert no R refusal.

| Step | Check | Refusal |
| --- | --- | --- |
| E1 | Received size / depth and CCJ-1 lexical parsing | `envelope_too_large` / `envelope_malformed` |
| E2 | Closed envelope/body/nested schema and encoding/interval shape | `envelope_malformed` |
| E3 | Fixed version, then expected type | `envelope_version_unsupported` / `envelope_type_mismatch` |
| E4 | Available required-role policy, then reserved/missing required role, duplicate pair, or grant/act role cardinality | `signer_unavailable` / `envelope_role_invalid` |
| E5 | Recomputed id | `envelope_id_mismatch` |
| E6 | Available agent-admission policy, issuer/author match, then allowed profile, message preimage size/depth, then strict crypto | `signer_unavailable` / `signer_unknown` / `signature_profile_invalid` / `signature_preimage_too_large` / `signature_preimage_invalid` / `signature_high_s` / `envelope_signature_invalid` |
| E7 | Exact protected audience | `audience_mismatch` |
| E7a | Required delivery room/recipient context, exact room, exact recipient | `message_context_unavailable` / `message_room_mismatch` / `message_recipient_mismatch` |
| E7b | Delivered text present, valid UTF-8 bytes, exact digest | `message_text_unavailable` / `message_text_invalid` / `message_text_mismatch` |
| T1 | Trusted/fresh provider authority, watermark availability | `time_unavailable` / `watermark_unavailable` |
| R1 (receipt mode only, after T1) | Required presence, authentic original pointer, margin0..60 | `freshness_receipt_unavailable` / `freshness_receipt_invalid` |
| R2 | Required current binding/read presence, then syntax, then exact premise/root/snapshot/witness/admitted-anchor/read consistency | missing: `freshness_receipt_unavailable`; malformed/future read: `freshness_receipt_invalid`; foreign binding, earlier read or rebuilt Evidence: `freshness_receipt_binding_mismatch` |
| R3 | Exclusive fixed expiry max(now,W)<E-margin | `freshness_receipt_expired` |
| T2 | Each expiry at max, then start at min | `expired` / `not_yet_valid` |
| K1 | Before required signed evidence intake: distinct protected root roles; then required outer evidence/header and root, strict root signature, purpose-specific typed fields/current binding, profile/derivation, validity and scoped signed revocation; finally message author/reference equality after ALL author/approver evidence, or grant agent-issuer profile (§2.6) | `key_binding_unavailable` / `key_binding_invalid` / `revoked` / `author_attestation_mismatch` / `signature_profile_invalid` |
| E8 | Id journal availability, then same id other bytes | `id_journal_unavailable` / `envelope_conflict` |
| G1 | Chain length 1–4, unique ids, closed request/schema | `grant_chain_malformed` |
| G2 | E1–E8 for every link (before remaining G rows) | envelope/time code above |
| G3 | Every parent ref and issuer/subject edge, then root pin/null parent | `grant_chain_broken` / `grant_root_unknown` |
| G4 | Depth, actions, targets, raw/effective lifetime, audience and minimum-assurance attenuation | `grant_not_narrowing` |
| G5 | Registered actions and applicable target kinds on every link | `action_unregistered` / `grant_target_invalid` |
| G6 | Every link raw and caveat window (T2 already checks raw) | `expired` / `not_yet_valid` |
| G7 | Distinct protected root roles if not checked earlier, then fresh complete revocation for every id/issuer/subject | `revocation_unavailable` / `revocation_invalid` / `revoked` |
| G8 | Concrete target before membership; requesting key/action/target coverage | `request_target_invalid` / `grant_not_authorized` |
| G9 | Established request assurance/presence available and satisfies leaf minimum | `grant_assurance_unavailable` / `grant_assurance_insufficient` |
| O1 | Operation profile, exact target/owner/epoch/argument digest | `act_operation_unknown` / `act_binding_mismatch` |
| O2 | Distinct protected root roles, then current owner authority, root-signed device attestation and act/device owner equality, then operator-root snapshot for signer/attestation/act revocation | `key_binding_unavailable` / `key_binding_invalid` / `revocation_unavailable` / `revocation_invalid` / `revoked` |
| O3 | Widening confirmed flag then qualified presence facts | `act_confirmation_required` / `act_presence_required` |
| O4 | Available durable replay journal, unused action id | `replay_unavailable` / `act_replay` |
| O5 | Widening activation; unconditionally closed in v0 | `act_a3_inactive` |
| C1 | Adapter Commit conflict/unavailability | `act_replay` / `state_unavailable` |

Journal intake has its own ordered table:

| Step | Check | Refusal |
| --- | --- | --- |
| J1 | Journal input count/total/record byte bounds, duplicate-free depth16 parse, closed entry/checkpoint shapes and encoding | `journal_malformed` |
| J2 | Protected registry owner/pin purpose/scope, D30 and commit/publisher roles | `journal_unavailable` / `journal_invalid` |
| J3 | Candidate then optional checkpoint: exact pin/id/author signature; complete typed body, time; full current snapshot admission, exact snapshot id and stricter snapshot/checkpoint time relation | `checkpoint_invalid` / `time_unavailable` / `watermark_unavailable` / `journal_unavailable` / `checkpoint_snapshot_invalid` |
| J4 | Protected witness availability, exact six-field typed/scope-bound projection | `journal_unavailable` / `journal_witness_invalid` |
| J5 | Same-seq different-head/checkpoint-id fork, then candidate seq rollback | `journal_fork` / `journal_rollback` |
| J5a | Advancing only: protected id-journal prior checkpoint available; authenticate exact id/root/scope/owner/seq/head without age; candidate.at>=prior.at | `journal_unavailable` / `checkpoint_invalid` / `journal_rollback` |
| J6 | Advancing only: first entry is witnessed seq/id anchor; then every entry id/scope, seq/prev/non-decreasing time, final checkpoint head/seq | `journal_anchor_required` / `journal_entry_invalid` / `journal_chain_broken` |

Freshness revocation intake (§2.9) is a separate ordered pipeline:

| Step | Check | Refusal |
| --- | --- | --- |
| F1 | Absent chain, then count/bytes/depth and complete closed wire parsing (publications oldest first, then checkpoint) | `freshness_unavailable`; `freshness_malformed` |
| F2 | Protected registry owner, root purpose/scope and D30 role separation | `freshness_unavailable` / `freshness_invalid` |
| F3 | Each publication's exact pin/version/type/id/one-author signature and crypto; then checkpoint signature admission | `freshness_signature_invalid`; existing `checkpoint_invalid` |
| F4 | Signed complete cumulative snapshot and protected age policy without base-age admission; all entry structures before matching; snapshot.issued_at<=checkpoint.at<=min(now,W) | `time_unavailable` / `watermark_unavailable` / `freshness_unavailable` / `freshness_snapshot_invalid` |
| F5 | Exact authenticated witness projection, then protected read timestamp presence and syntax; currency follows at F8 | `freshness_unavailable` / `freshness_witness_invalid` |
| F6 | Exact tip.snapshot=verified snapshot id=checkpoint.snapshot; tip.registry_seq/checkpoint_id equal checkpoint seq/id | `freshness_binding_mismatch` |
| F7 | Tip registry seq above witness (older evidence), below witness (rollback), then equal seq different checkpoint id/head | `freshness_unavailable` / `freshness_rollback` / `freshness_fork` |
| F8 | Current tip/read currency (including checkpoint.at<=tip.issued_at), then retained publication anchor available/typed/scoped; each publication: lower seq, same-seq different id, exact retransmission fields, global gap, registry rollback/equal-seq checkpoint fork, checkpoint transition, same-head prev or null-on-advance, strictly increasing issued_at, snapshot binding | `freshness_unavailable` / `freshness_state_invalid`; `freshness_rollback` / `freshness_fork` / `freshness_state_invalid` / `freshness_gap` / `freshness_rollback` / `freshness_fork` / `freshness_binding_mismatch` / `freshness_gap` / `freshness_time_invalid` / `freshness_binding_mismatch` |
| F8R (explicit recovery only, replaces publication loop at F8) | After unchanged tip/read currency and anchor validation: require positive stored publication; current registry seq lower/equal checkpoint fork, same-head snapshot binding or changed checkpoint on advance; strictly greater publication_seq, then strictly greater issued_at | `freshness_state_invalid`; `freshness_rollback` / `freshness_fork` / `freshness_binding_mismatch`; `freshness_rollback`; `freshness_rollback` |
| F9 | Bounded valid content-id/key queries, then effective snapshot matches after ALL proof checks | `freshness_request_invalid`; existing `revoked` |

The /1 table retains its steps. The shared current-candidate version preflight
applies at J1/F1 for either protected profile. /2 adds:

| Step | /2 check | Refusal |
| --- | --- | --- |
| J1/F1 | All input size bounds, including full D45 aggregate charge and embedded raw limits; bounded version preflight for every current publication and both checkpoint arguments; closed ordered-set wire shape | journal_malformed / freshness_malformed; registry_currency_version_mismatch |
| J2/F2 | Supported configured version; exact protected role/key mapping | journal_invalid / freshness_invalid (missing registry facts retain unavailable) |
| J3/F4 | Every selected original and independent cumulative premise, without own-age | checkpoint_snapshot_invalid / freshness_snapshot_invalid; existing unavailable/time codes |
| F6 | Full ordered set equality, target seq/checkpoint bindings | freshness_binding_mismatch |
| J7, after J6 | Complete-prefix anchor, authoritative suffix, originals, no-regression derivation and latest selection | Missing originals/proof journal_unavailable; invalid index/regression journal_invalid; existing journal chain/anchor/rollback/fork and checkpoint-invalid codes; non-latest checkpoint_snapshot_invalid |
| F6L, before F7 | Same derivation against the current target head | Missing proof/original freshness_unavailable; invalid or discontinuous proof freshness_state_invalid; non-latest freshness_binding_mismatch |
| F8/F8R | Included-root minimum A, whole-set anchors/re-anchor and one-way upgrade | Existing F8/F8R codes |
| R2 | All required presence before syntax, then exact version/pin/set/byte/two-Evidence/anchor/witness binding | freshness_receipt_unavailable / invalid / binding_mismatch |
| Root own-age slot after global R | Required missing coverage, or optional ordinary own-age | freshness_receipt_unavailable; otherwise existing own-age refusal |

The J1/F1-to-J2/F2 preflight order is:

1. Dispatch uses only the protected currency pin, never a candidate record.
2. Required input presence, then count bounds (an absent freshness chain is
   freshness_unavailable; the re-anchor API supplies one publication).
3. Every current raw record's8192-byte bound, including primary and supplied
   conflict checkpoints, then total raw argument bytes (freshness532480;
   journal540672).
4. For /2, full D45 raw/Evidence charge plus65,536-byte reserve, then embedded
   raw bounds, without current-body parsing or combining raw slices.
5. Bounded current-candidate version probes: publications oldest-first then
   checkpoint for F; primary then supplied nonempty conflict checkpoint for J.
6. Closed wire parsing with existing duplicate/depth16 bounds: publications or
   journal entries oldest-first, then primary and supplied conflict checkpoint.
7. J2/F2 supported protected profile and role/pin policy; later signature,
   proof, index, currency and receipt stages retain their stated order.

Steps1–3 and5–7 retain the /1 behavior. Step4 applies to /2 only. Version probes
are bounded record parses; an unparseable discriminator does not bypass the
closed-wire refusal at step6. Archival predecessors remain later proof inputs,
not current-candidate profile selectors.

R1 remains immediately after the first T1; R3 keeps fixed exclusive expiry.
Malformed/invalid supplied receipts never trigger retry without the receipt.
The only new refusal code is registry_currency_version_mismatch. All /2
refusals have zero plans and nil receipts; direct identity/tri-state APIs retain
their existing zero/unavailable error projections.

All F refusals have a zero plan, including revoked. F rows do not alter legacy
E/G/O/J ordering or own-snapshot freshness. Named N-ORD-FR compounds extend the
U precedence coverage without changing inherited mechanical sweep bytes.

Journal J rows are a separate entry point; they do not precede E/G/O rows on
message/grant/act intake. Within J3 authenticate candidate before optional
fork evidence, each fully before witness comparison; J5a authenticates prior
checkpoint evidence before comparing checkpoint times; J6 entries are oldest
first. All refusals have an empty plan. K1's new service profile follows the
same evidence-signature-before-typed-body order as existing attestations.


For message/act intake, absent/null required-role policy is `signer_unavailable`
at E4; malformed role policy is `envelope_role_invalid`. It MUST NOT default
to an empty role set. Grant intake has its fixed single-author policy.
At E6, absent/null agent-admission key lists are `signer_unavailable`; malformed lists are
`signer_unknown`, before signer membership comparison.

For grant intake G1 precedes G2; G2 performs E/T/K1 checks per link, then G3–G9.
K1 runs after T2 and before E8. Message approvers additionally require current
operator-root-attested devices and fresh signed issuer revocation evidence; unavailable current key
facts return `key_binding_unavailable`, false key currency returns
`key_binding_invalid`; their issuer snapshot uses K1 codes. Operator snapshots
use the G7 revocation codes at O2.
For operator intake E/T checks precede O1–O5. E2 validates type-specific schema
using the expected type, but type string equality is deferred to E3. G4 audience
attenuation is additionally enforced even though G2's configured audience
normally catches a differing link first. Raw start/expiry schema, including
caveat containment, is E2; time authorization is T2/G6. Request argument schema
is a consumer gate, never guessed from signed text. Refusal MUST cause no effect
or authority mutation; refusal audit is permitted. Vectors record an empty
persistence plan on refusal and a candidate plan on accept, never committed I/O.

Message signer admission (§2.5) has its own ordered refusals: size
`signer_preimage_too_large`; tag grammar/delimiter `signer_tag_malformed`;
exact message membership `signer_domain_refused`; CCJ-1 canonicality/depth
`signer_payload_invalid`; when identity narrowing applies, missing/invalid
service-resolved caller key/current-attestation id or identity policy `signer_identity_unavailable`,
then missing/wrongly typed identity paths `signer_identity_malformed`, then
unequal identity values `signer_identity_mismatch`. It performs no effect authorization. In domain-only
conformance probes a malformed tag is `domain_tag_malformed`, an unregistered
configured tag `domain_unknown`, and unequal received/configured bytes
`domain_mismatch`; a correctly retagged foreign signature then fails
`envelope_signature_invalid`. These probes isolate mathematical separation,
including external domains, and do not claim to implement external body schemas
or admission gates.

## 7. Consumer gates and remaining risks

**D42(a), option I obligations.** Grant and operator roots remain offline and
sign snapshot CONTENT only on change. Online per-root freshness signers (b) and
interval content re-signing (c) are rejected because they defeat offline custody.
The root signing application retains its exact submission and independently
checks the published op=add journal-entry/1, its gap-free inclusion chain to the
signed checkpoint/2 seq/head, and an authenticated witness head/checkpoint id.
When its root is selected it checks latest selection too. VerifyJournal /2
supplies bounded journal/checkpoint/index checks; the application matches its
own submission id and obtains witness authentication outside this library. An
intake acknowledgment or a freshness receipt alone is insufficient. Publishers
serve exact anchor entries, predecessor checkpoints, referenced original signed
snapshots and complete retained journal/publication history without truncation.

The currency guarantee is relative to the OBSERVED authenticated witnessed
prefix. Once that prefix contains a newer cumulative root snapshot, a new /2
admission cannot select its older predecessor. This supplies no external-root
revocation deadline measured from snapshot signing/submission: withholding before
journaling, an unpublished/unobserved tail, earlier receipts until fixed expiry,
and immediate global revocation remain unproved. A compromised registry-owner
can delay/withhold newer external content or omit optional coverage, the same
publication cost accepted for its own domain. Used-root required coverage,
root-side intake checks, independently retained witnessed heads and full-history
audit mitigate it without granting registry content-signing authority. Existing
issuance-age bounds apply only to their own-age profiles, not to external roots
whose own-age is waived by /2. Separately qualify any publication latency bound.

Before any receipt use the consumer makes ONE crash-atomic, recovery-qualified
commit binding version and pin identity, the complete index, exact old/new
endpoints and supporting history/originals, time watermarks and re-anchor
sets/versions/audit. Stage dependencies durably before publishing that commitment;
a Plan is only a candidate, never storage acknowledgment or an effect permit.
Partial catch-up grants no authority. Preserve legacy /1 digests; explicitly
version local /2 state. Keep the two original Evidence objects after commit and
remint after restart. Every consumer protects a monotonic version/pin floor and
installation/registry/transition identity outside relevant restore domains;
missing, older or conflicting enrolled state refuses. Fence old serving binaries
and instances that cannot enforce the floor. A normal configuration flag or an
old process that ignores it does not protect against restore.

An unavailable, unauthenticated, stale or conflicting witness refuses current
freshness admission, including re-anchor and re-entry after asynchronous work.
Read/authenticate the witness for EACH admission outside the final serialized
consumer window; inside it compare exact head/state revision and enforce the
qualified read age/deadline. A changed state requires new evidence outside the
window. No network/provider acquisition belongs under final locks, no cached
last-good fallback answers a failed required read, and no old receipt is a
reusable effect/release permit. The pure verifier implements none of this live
storage, witness transport, root application or consumer activation integration.


| Consumer | Contract from this slice | Activation boundary |
| --- | --- | --- |
| Keymaker message signer (first signing consumer) | Exact tag, canonical preimage, size/depth and raw Ed25519 output in §§2.2, 2.4–2.5; root-signed attestation and current binding in §2.6 | Native intake and issuer publication belong to Keymaker; not implemented here |
| Keymaker operator_record verifier | Operator-root-attested P-256 act and exact persistent-revoke mapping in §4.2 | Future verifier and durable caller integration still required |
| Credential broker, later | General grant adapter and repeated binding/lease/renewal gates in §3.4 | Broker v0 R1 unchanged |
| Carrier | Unchanged envelope bytes and bounded event/pointer requirement in §5 | Transport owner publishes wire budget and pointer form |

Keymaker: §4.2 is the exact persistent-revoke mapping. Its kernel caller,
registration, generation, target-retirement and outer mutation journal checks
remain mandatory. `register` gains no signature requirement. No new surface-A
signing domain is implied; Keymaker's SSH signing capability cannot automatically
sign this slice. Its proposed message signer consumes §2.5 rather than
reinterpreting surface A. A current root-attested P-256 device supplies a narrowing act; widening remains inactive in v0.

Broker: the later adapter checks `agent.spawn` and `credential.lease` in the
requester's chain at bind, with the dispatcher chain separately validated. Lease
and every renewal require `credential.lease` for the exact account/harness/profile
and both chains' continued authority. Repeat current ledger/generation, profile,
account, credential binding, freeze, time and revocation checks immediately
before release, including after asynchronous refresh. R1 remains unchanged now.
Dispatcher support and generation-to-key binding are activation dependencies.

The signed author-attestation reference prevents receiver cross-generation or
cross-registration substitution of a stable key. The three-path signer check
prevents a caller from signing for another attestation. Owner decision,
2026-10-24: receiver binding is fixed first; any additional signer-side
generation check is a separate later change. This slice specifies exactly the
three paths in §2.5 and no further signer generation interpretation. Neither
check proves actual creation time beyond the admissible message window; a signed `iat` is still a
claim, and historical verification remains outside v0.

For the ordinary snapshot own-age profile, §2.6's revocation bound is no later than
first-containing-snapshot issued_at + configured maximum age (at most 60 s)
for an effective entry, never before `from`, hence max(issued_at+age,from) for
future entries. It promises nothing before the issuer signs that snapshot.
Owner decision, 2026-10-24: "revocation complete" means completion ONLY after a
defined set of durable barriers and acknowledgements, OR proven expiry of ALL
previously admitted authority. Before completion, only bounded propagation lag
is permitted; in that own-age profile the snapshot admission bound is `S+A`, or `max(S+A,from)`
for future-effective entries, where S is the first-containing signed snapshot
issuance and A its configured maximum age. After completion, NO admission
window for the revoked right may remain. Critical effects additionally require
§6's online check with the authority owner immediately before the effect;
unavailability refuses.

S0 defines the completion requirement and abstract online interface only. The
concrete barrier/acknowledgement set, expiry proof, acknowledgement protocol,
network mechanism, publication/propagation integration and consumer selection
of critical effects MUST be specified and qualified before activation. No
completion latency, acknowledgement set or network protocol is invented here.
The offline checker returns candidate plans before Commit and models neither
these barriers/acknowledgements nor the serialized effect boundary, so it cannot
provide effect-boundary vectors or qualify revocation completion/online checks.

Operator-root recovery also remains an activation gate: separately held,
pre-attested replacement/revocation-only recovery means now, then two-of-three
custodians. A future recovery record's own type/tag, attestation, custody and
threshold policy require separate review and qualification. No v0 record may
perform recovery. The generic signature-list and root-policy contracts must
preserve that extension path; current type-specific cardinalities are not a
single-recovery-signer assumption.

The separate trust node, registry/witness continuity, exclusive administrative
boundary and publication pipeline require qualification before deployment.
The separate signer under its own account in §1 MUST retain custody of the
registry-owner key; the storage and ordering service MUST never hold it.
Compromise of the registry key alone can withhold or delay revocation visibility;
own-age profiles retain their snapshot bound and continuity rules, while /2
supplies only the observed-prefix guarantee above. It cannot mint grants or
attestations, whose original signing roots remain distinct. The own-age bound
starts only with the first-containing signed snapshot (§2.6); nothing here bounds
withholding before publication or proves honest publication by a compromised
registry. The registry and rollback witness on one node are one failure domain.
They MUST use separate processes, accounts and streams; the registry writer
MUST NOT be able to append to witness streams. The trusted witness checkpoint
MUST be held outside that node. Loss of the node MUST cause consumers to fail
closed. These isolation and checkpoint requirements need deployment
qualification. Until deployment, pinned roots and caller-supplied snapshots
remain unchanged; unavailable required evidence refuses under §6.

S0 defines no emergency-stop record. A future emergency stop MUST NOT depend
on a fresh registry snapshot or on registry availability. Restart MUST require
separate current authority; an emergency stop is not a restart authorization.
The mechanism and its reviewed record/profile remain future work.

The identity-journal formats and pure suffix/checkpoint verification are in
§2.7. Registry/witness deployment, witness authentication/update protocol and
explicit bootstrap qualification remain external. Git MAY be storage or
transport; repository commits confer no record authority. No registry service,
witness format, recovery record, contacts or inter-registry exchange is added.

Threats left open: compromised pinned roots/devices/providers, dishonest
confirmation rendering, malicious consumers, stolen live credentials, denial of
service from strict fail-closed time/revocation, rollback beyond external witness
coverage, and metadata exposure. Hashes give integrity, not secrecy. Correct
signatures do not make untrusted prose instructions, guarantee handler safety,
or authorize effects not named in a registered action. Offline vectors qualify
neither durable storage/concurrency nor a presence provider, clock collector,
phone application, Matrix carrier, consumer deployment or live migration.

Historical publication-proof re-verification is outside v0. A stored proof
records "verified at acceptance time"; it is not a permanent current-authority
permit or a historical-verifier API. Any new admission requires a current tip,
fresh authenticated head read, current policy and retained-state continuity.
Old signed intermediates may establish hash-linked completeness for that new
admission; they are not re-admitted as historical effects or authority.

Legacy /1 consumers relying on option B compose F admission through the
process-local receipt contract in §2.10. Its registry-only own-age waiver
preserves every other identity, message, grant and effect check; other root
domains retain own-age checks and VerifyJournal remains an independent proof path.
The /2 covered-root rules are defined separately above. Consumers MUST NOT fake younger Context time or
snapshot bytes or implement a second verifier. Receipts are candidate evidence,
not durable authority or a Commit/effect permit. Live adapter integration and
the D42 /2 live consumer integration still require qualification.

Without re-anchor, the64publication proof bound spans at most64new intervals
when the stored anchor itself need not be resent, about21minutes20seconds at
20seconds per interval (64minutes at60seconds). A head change beyond the first
64positions prevents reaching that head even earlier in recovery: the bounded
prefix cannot satisfy the freshly witnessed current-head binding. A proof
requiring the retained anchor itself consumes one position for that anchor.
The F-proof bound is532480received bytes, independent of any consumer carrier
or intake limit. A consumer with a smaller intake limit must route this proof
separately within independently enforced limits; exceeding either limit
refuses, and splitting does not authorize truncating an authenticated proof.

Explicit re-anchoring (§2.9) does not prove that skipped publication positions
were mutually consistent. Inside the skipped segment the recovering consumer
loses the ability to detect a freshness fork: different publication chains
shown to different consumers (the publication-completeness condition). This
loss has no revocation effect only under the independently qualified cumulative
publication premise: the admitted snapshot equals the witnessed
checkpoint.snapshot and qualified evidence establishes rollback-safe cumulative
publication. Re-anchor comparisons (nondecreasing registry_seq, equal head/id
at equal sequence, strictly increasing publication_seq and issued_at) do not
prove snapshot cumulativity. It MUST NOT be inferred from re-anchor,
`complete=true`, or a higher registry_seq. Under that required premise recovery
never extends authority or cancels revocation. As compensating requirements,
the registry MUST retain the complete freshness history without truncation;
the witness and off-node retained heads MUST permit a later cross-check; and
the consumer MUST retain the audit record carrying both endpoint heads via
freshness and checkpoint ids. These are publisher, deployment and consumer
integration obligations; offline vectors qualify only the pure admission plan.
An unavailable witness means every admission requiring current freshness
refuses. This fail-closed operational consequence applies to both the normal
and re-anchor paths, including during witness outages.
