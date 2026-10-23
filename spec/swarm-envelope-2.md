# Platform signed records, slice v0

Status: proposed normative contract; no production verifier or consumer activation.
MUST, MUST NOT, SHOULD and MAY are requirement words. All byte counts refer to
UTF-8 bytes, not characters. Refusal codes in §6 are stable within this draft.

## 1. Scope, ownership and existing waggle

This slice defines `swarm-envelope/2`, general `grant/1` and `operator-act/1`.
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
main commit and change that pin through their own review. No library API is
published by this slice; §6 is the required behavior for the next slice.

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

There MUST be 1–8 signatures with no duplicate `(role,key)` pair. Other roles
are reserved and MUST refuse. A role never confers authority by itself. Required
roles and admitted keys come from the caller's protected policy. Grants require
exactly one `author` signature by `issuer`; operator acts exactly one `approver`
from the owner's pinned device keys. A message requires `author` by its `author`
key; extra signatures require caller policy, and MUST all verify.

All objects are closed: unknown/missing fields and wrong JSON types MUST refuse,
including nested objects. The JSON reader MUST enforce limits while reading:
65,536 bytes per envelope, 16 container levels (root = 1), 8,192 bytes per string,
64 entries per array except signatures (8) and chain (4). An operator envelope
has a stricter 8,192-byte limit, measured on the whole received object including
signatures. Aggregate chain intake is at most 262,144 bytes. Readers MUST bound
allocated work before parsing. The v0 types are only `grant/1`, `operator-act/1`
and the minimal signed `message/1` below; another type needs a reviewed version.

The common body members are `type`, `aud`, `nonce`, `iat`, `exp`. `aud` is one
exact service identifier, 1–255 printable ASCII bytes without whitespace.
`nonce` is canonical unpadded base64url encoding of 16 independently random
bytes. Production signers MUST use a CSPRNG; fixed vector values are test-only.
Times MUST be exactly `YYYY-MM-DDTHH:MM:SSZ`, real Gregorian dates, years
1970–9999, no offsets, fractions or leap seconds. `iat < exp`. Operator acts
and messages have lifetime at most 120 seconds; grants have no implicit renewal
or maximum lifetime beyond the chain and protected consumer policy.

`message/1` adds exactly `author`, `action`, `target`, `arguments` (an object).
Arguments MUST pass the caller-selected registered action schema. The vector-only
`message.deliver` profile is `{text:string}` or `{text:string,sequence:integer[]}`
for serializer controls; it publishes no general message payload grammar. This minimal
form tests envelope mechanics; it does not publish session commands or board
policy. Authentication alone MUST NOT authorize message delivery or execution.

### 2.2 CCJ-1 and preimages

Body canonicalization MUST use registrar §2 CCJ-1: scalar-sorted object names,
array order preserved, shortest decimal integers, no Unicode normalization,
UTF-8 output, minimal JSON escapes (no escaping slash, angle brackets, ampersand
or non-ASCII scalars). Input MAY have noncanonical whitespace/order/escapes.
Duplicate names at every depth (also escaped aliases), invalid UTF-8/BOM,
lone surrogates, floats/exponents, negative zero, and integers outside
[-9007199254740991, 9007199254740991] MUST refuse. Bodies MUST NOT contain
signature metadata, and canonicalization MUST NOT recursively strip `sig`.

The caller supplies the expected type T from the channel. Domain D is ASCII
`waggle ` followed by T; the body type MUST equal T. Let C = CCJ-1(body).

```text
preimage = ASCII(D) || 0x0a || C
id = "sha256:" || lowercase_hex(SHA-256(preimage))
signature_preimage(role,key) =
  ASCII("waggle swarm-envelope/2 " + T + " " + role) || 0x0a ||
  CCJ-1({body: body, key: key})
```

There is no trailing newline. The envelope id, version and signatures are
outside the body; the mandatory version is fixed in the signing domain. A
signature covers the complete canonical body, the role, key id and expected
type. The hash construction matches the broker's domain/newline/CCJ-1 pattern;
the domain and role-bound signature preimage deliberately differ. Neither an
id nor a signature can be reused across types, versions, keys or roles.

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

## 3. General grant/1

### 3.1 Closed v0 body

In addition to common members a grant has exactly:

| Member | Constraint |
| --- | --- |
| `issuer`, `subject` | Key ids from §2.3. No role, UID, label, group or generation subject in this slice. |
| `actions` | Nonempty, sorted unique array of registered exact action strings. No wildcard actions. |
| `targets` | Nonempty array of distinct typed targets, each independently meaningful; no Cartesian-product inference. |
| `not_before`, `expires` | Valid timestamps, `not_before < expires`; MUST equal `iat`, `exp` respectively. |
| `depth` | Integer 0–3: number of further delegations permitted. |
| `parent` | Parent envelope id, or null only at root. |
| `caveats` | null, or exactly `{lang:"caveats/v1",not_before:time,expires:time}`. |

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
human-presence conditions, rule languages, roles, nondelegable flags and Biscuit
are deferred and MUST refuse. Effective start is max(not_before,caveat start),
end is min(expires,caveat end); null uses the grant window.

### 3.2 Chain and request verification

Chains are leaf first, 1–4 signed envelopes, with no repeated ids or unrelated
records. Every envelope, including the leaf, MUST pass §2 and the checks below.
For every child/parent pair: child.parent MUST equal parent.id; child.issuer
MUST equal parent.subject; actions MUST be a subset; every target MUST be
contained; raw AND effective lifetimes MUST be subsets; audience MUST equal;
child.depth MUST be strictly less than parent.depth. A depth-zero parent cannot
have a child. The last record MUST have parent null and issuer equal to a
protected pinned owner root. A self-signed key without that pin is not a root.

Every link's issuer, subject and envelope id MUST be checked for revocation.
The leaf subject MUST equal the authenticated requesting key. The concrete
request action MUST be registered and allowed by the leaf and its target MUST
be contained by a leaf target. Both the dispatcher/caller chains remain
separate when a consumer requires their intersection; never concatenate them
or let a service signature erase the original caller's authority.

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
permits progress. The caller supplies authenticated current snapshots for the
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
| Canonicalization, id | CCJ-1, domain + LF + body, sha256 id | Same byte algorithm; new domain `waggle grant/1` produces new ids. |
| Container/signature | `{body,id,sig}`; issuer Ed25519 over id preimage | Adds version, signatures array, roles and key binding; re-sign, never relabel. Adds P-256 low-S. |
| Common fields | type in body; no aud/nonce/iat/exp | Adds all four; iat/exp equal grant interval. Adapter MUST supply explicit bounded values. |
| Subject | key or generation-bound `agent:` leaf | Keys only; no silent UID/generation conversion. Generation binding needs a separately versioned consumer adapter. |
| Actions | `credential.lease`, `agent.spawn` | Adds `message.deliver`; broker adapter MUST refuse it. |
| Targets | Separate exact accounts/harnesses/profiles lists | Typed correlated tuples; prefix ids allowed here, refused by broker. Enumerate exact Cartesian tuples only when source rights actually permit that product. |
| Interval | not_before, expires_at | not_before, expires; exact UTC seconds, equal common iat/exp. No lossy rounding. |
| Depth/parent | Remaining depth, leaf-first, at most four | Same chain structure; depth explicitly 0–3. Every leaf edge remains checked. |
| Conditions | Time only, no role/wildcard/presence | Time-only caveats/v1; project into effective interval or refuse. No weakening. |
| Root/revocation | Configured broker root; local grant/key revocations | Pinned owner root + caller snapshot; retain old revocation authority and old-id/new-id mapping. |
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

Only protected consumer operation policy classifies widening versus narrowing;
the sender MUST NOT select that class. v0 profiles here are Keymaker `revoke`
(narrowing) and illustrative `grant.issue` on an account (widening, no broker
activation). Other operations require a published consumer profile and arguments
schema before admission. Unknown operations MUST refuse. A pinned device key
MUST be authorized for this owner, current and not revoked. Neither login to an
operator account nor an arbitrary key in a chain makes an act valid.

Widening MUST require `confirmed=true` AND current trusted signer-provider
enrollment evidence that the pinned key requires user presence for each use and
renders/binds the exact operation, target, owner, epoch, audience, action id,
arguments and time bounds before signing. A self-asserted boolean alone is
insufficient. This slice specifies that provider obligation; it does not invent
an attestation, phone app, biometric transport or platform mechanism. If the
provider cannot establish it, widening MUST refuse. Narrowing MAY set confirmed
false, but still requires the pinned key signature and current authority.
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
| signing key / revocation | Protected operator device pin for that owner, current snapshot |
| confirmed | May be false: persistent revoke is narrowing |

The caller supplies trusted time, protected owner/key pin and binding epoch,
revocation evidence, id bytes journal and durable used-action journal. Missing
verifier/evidence, unavailable revocation/time/watermark/key policy/journal or failed state
commit maps to `operator_record_unavailable`. Malformation, bad signature,
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

A2 here means a person's pinned key signs the exact canonical envelope content,
and the receiver verifies its current grant for the concrete action and target.
It proves key-authenticated, authorized content, not that a person saw or wrote
it. A3 adds the operator act and exact-content confirmation requirement on a
qualified presence-enforcing signer provider. A narrowing signature without
that confirmation does not by itself claim A3. Software signatures or a claimed
confirmed flag alone do not prove presence. Carrier E2EE (A1) is out of scope;
this document promises neither confidentiality nor device/app enrollment.

A Matrix carrier MUST carry the completed envelope bytes unchanged, perhaps as
a reversible byte encoding, and MUST NOT sign reconstructed JSON or use event
sender/display name as the authority. Consumers enforce §2's envelope limit
independently of Matrix limits. The transport owner must publish an event byte
budget and, if needed, an authenticated content-addressed pointer form with
bounded retrieval, exact hash verification, audience and retention rules.
Until that interface exists, oversized carrier events MUST refuse, not truncate
or fetch an untrusted URL. This slice defines no Matrix event extension.

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
Revocations.Check(owner, ids, keys, sample) -> not_revoked | revoked | unavailable
IdJournal.Lookup(id) -> absent | exact_bytes | unavailable
Replay.Lookup(consumer,action_id) -> unused | used | unavailable
SignerFacts.Lookup(owner,key) -> pinned + current + presence_policy | unavailable
Commit(plan) -> atomic reserve + durable watermark + id binding | conflict | unavailable
```

All errors and absent required evidence MUST become explicit decisions; absence
is not false or an empty set. These are interface requirements, not storage or
network implementations. An accept from the pure core MUST NOT be exposed as
an effect permit until Commit succeeds and current time/revocation/binding
checks are repeated at the consumer's serialized effect boundary.

The first failing row wins. Within a row evaluate envelopes leaf first and
fields in the order stated. Structure precedes semantic crypto; signature
entries are checked in array order. Codes are distinct per listed substep:

| Step | Check | Refusal |
| --- | --- | --- |
| E1 | Received size / depth and CCJ-1 lexical parsing | `envelope_too_large` / `envelope_malformed` |
| E2 | Closed envelope/body/nested schema and encoding/interval shape | `envelope_malformed` |
| E3 | Fixed version, then expected type | `envelope_version_unsupported` / `envelope_type_mismatch` |
| E4 | Reserved/missing required role, duplicate pair, or grant/act role cardinality | `envelope_role_invalid` |
| E5 | Recomputed id | `envelope_id_mismatch` |
| E6 | Available key policy, key pin/issuer/author match, then strict crypto (high-S distinguished) | `signer_unavailable` / `signer_unknown` / `signature_high_s` / `envelope_signature_invalid` |
| E7 | Exact protected audience | `audience_mismatch` |
| T1 | Trusted/fresh provider authority, watermark availability | `time_unavailable` / `watermark_unavailable` |
| T2 | Each expiry at max, then start at min | `expired` / `not_yet_valid` |
| E8 | Id journal availability, then same id other bytes | `id_journal_unavailable` / `envelope_conflict` |
| G1 | Chain length 1–4, unique ids, closed request/schema | `grant_chain_malformed` |
| G2 | E1–E8 for every link (before remaining G rows) | envelope/time code above |
| G3 | Every parent ref and issuer/subject edge, then root pin/null parent | `grant_chain_broken` / `grant_root_unknown` |
| G4 | Depth, actions, targets, raw/effective lifetime, audience attenuation | `grant_not_narrowing` |
| G5 | Registered actions and applicable target kinds on every link | `action_unregistered` / `grant_target_invalid` |
| G6 | Every link raw and caveat window (T2 already checks raw) | `expired` / `not_yet_valid` |
| G7 | Fresh complete revocation for every id/issuer/subject | `revocation_unavailable` / `revoked` |
| G8 | Concrete target before membership; requesting key/action/target coverage | `request_target_invalid` / `grant_not_authorized` |
| O1 | Operation profile, exact target/owner/epoch/argument digest | `act_operation_unknown` / `act_binding_mismatch` |
| O2 | Current signer revocation evidence | `revocation_unavailable` / `revoked` |
| O3 | Widening confirmed flag then qualified presence facts | `act_confirmation_required` / `act_presence_required` |
| O4 | Available durable replay journal, unused action id | `replay_unavailable` / `act_replay` |
| C1 | Adapter Commit conflict/unavailability | `act_replay` / `state_unavailable` |

For grant intake G1 precedes G2; G2 performs E/T checks per link, then G3–G8.
For operator intake E/T checks precede O1–O4. E2 validates type-specific schema
using the expected type, but type string equality is deferred to E3. G4 audience
attenuation is additionally enforced even though G2's configured audience
normally catches a differing link first. Raw start/expiry schema, including
caveat containment, is E2; time authorization is T2/G6. Request argument schema
is a consumer gate, never guessed from signed text. Refusal MUST cause no effect
or authority mutation; refusal audit is permitted. Vectors record an empty
persistence plan on refusal and a candidate plan on accept, never committed I/O.

## 7. Consumer gates and remaining risks

Keymaker: §4.2 is the exact persistent-revoke mapping. Its kernel caller,
registration, generation, target-retirement and outer mutation journal checks
remain mandatory. `register` gains no signature requirement. No new surface-A
signing domain is implied; Keymaker's SSH signing capability cannot automatically
sign this slice. A qualified operator device signer supplies the act.

Broker: the later adapter checks `agent.spawn` and `credential.lease` in the
requester's chain at bind, with the dispatcher chain separately validated. Lease
and every renewal require `credential.lease` for the exact account/harness/profile
and both chains' continued authority. Repeat current ledger/generation, profile,
account, credential binding, freeze, time and revocation checks immediately
before release, including after asynchronous refresh. R1 remains unchanged now.
Dispatcher support and generation-to-key binding are activation dependencies.

Threats left open: compromised pinned roots/devices/providers, dishonest
confirmation rendering, malicious consumers, stolen live credentials, denial of
service from strict fail-closed time/revocation, rollback beyond external witness
coverage, and metadata exposure. Hashes give integrity, not secrecy. Correct
signatures do not make untrusted prose instructions, guarantee handler safety,
or authorize effects not named in a registered action. Offline vectors qualify
neither durable storage/concurrency nor a presence provider, clock collector,
phone application, Matrix carrier, consumer deployment or live migration.
