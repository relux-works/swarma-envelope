# External-agent landing card proposal

Status: **PROPOSAL — NOT ADMITTED FOR EXECUTION.** This document proposes a
sealed, finite external-enrollment card inside `swarm-envelope/2`. Publishing
this text grants no security permission and implements no signer, verifier,
transport, registration or onboarding operation. No real card, code, key,
ciphertext, signature or secret-bearing fixture is included.

## 1. Purpose and existing boundary

An external participant generates a separate encryption keypair locally and
provides only its public key through authenticated intake. Its actual direct
manager, using a future explicitly qualified issuance profile and covering
authority, signs the complete cleartext header and code-only ciphertext. The
recipient verifies the full authority chain and all protected context before
opening the code. The redeeming service independently checks current authority
and atomically enforces the finite allowance before any enrollment effect.

The owner decision of 2026-11-17 21:51 UTC selects direct-manager issuance:
each non-root manager receives bounded authority from above and signs only for
its own directly managed subordinate. A project manager signs its own workers;
a product manager may sign a directly staffed worker when no intervening
project manager exists. An explicitly combined role uses its authenticated
actual relation. This chooses the authority topology; it creates no key,
attestation, grant, provider, presence exemption or permission to issue a card.
There is no unresolved choice between root-only and delegated issuance.

The current [Envelope specification](swarm-envelope-2.md), inspected at main
`065e25f69da8b28cdf3ea35d9fcd7fc4aacc4d5e`, has SHA-256
`d67467011753cef7e84643b2321e1106623d962988d700e237353486ff7c2617`.
Its closed tables remain authoritative and unchanged. It contains neither
proposed `sealed-payload/1` nor `external-agent-landing/1`. The current
grant-service profile is Ed25519, `service/grant-service`, `author/grant.sign`:
its attestation supplies identity evidence, and it may sign **only `grant/1`**
with a covering delegable parent grant. Agent keys cannot issue `grant/1`, even
with a parent grant. Existing signatures, grants and service attestations do
not admit the proposed sealed language. A public BIP-340 agent-author profile
does not admit a grant-root or sealed-card signer.

Reuse the existing CCJ-1 codec, content IDs, role/key/version-bearing signature
records, type domains and protected-evidence model. Do not add arbitrary card
fields to closed `grant/1` bodies or unregistered `message/1` arguments. The
existing specification supplies neither confidentiality nor device/app
enrollment. A signature does not encrypt its body. No third signed-record
format or generic arbitrary-byte signing API is proposed.

Link Spec v0.1.60 is adjacent child-grant design evidence only. It is not an
implementation, admission or installed-version receipt for this proposal.
Docking must use the exact accepted and actually implemented child-grant
contract; unavailable functionality cannot be replaced with a local grant
format or assumed caveats. Source revision equality does not prove consumer
dependency equality or installed adoption.

## 2. Authenticated intake and custody

The participant creates a separate X25519 encryption keypair using the agreed
supported implementation and OS CSPRNG. Never reuse or convert a signing key
for decryption. The private key stays under the recipient's native custody;
no seed, password, recovery material or private-key export is requested.

Intake independently confirms the complete encryption key's origin and binds
it to the intended participant, host and enrollment request. If the participant
already has an independently admitted author key, that author additionally
signs the exact encryption-key binding and is checked against independently
known identity and current authority. Without an admitted author, use an
explicit source-agreed no-author case and the independently confirmed separate
encryption pair; do not invent a trusted self-attestation or require another
author pair. Possession is a separate bounded, request-bound proof, whose
protocol remains open; it never substitutes for origin confirmation or uses
an encryption key in an unsupported signing role.

The recipient independently receives and retains BOTH complete canonical
signing keys: the admitted owner grant root as trust anchor and the intended
actual direct-manager issuer key and generation. Neither is obtained,
completed, replaced or discovered from the card or its carried chain.
Confirmation is bilateral: confirming the recipient to the issuer does not
confirm the issuer or root to the recipient.

A confirmation fingerprint is `sha256:` followed by all 64 lowercase hex
digits of SHA-256 over the exact ASCII canonical key identifier. It confirms
an already delivered complete key only. Compare the full digest and the full
key; truncated digests, display grouping, abbreviated keys, forwarded labels
and unknown self-signatures cannot establish origin. Apply strict algorithm
and point validation. A fingerprint is never a substitute for key material.

Protected intake fixes all of the following independently of the card:

- Expected type/profile, source policy/version, singleton HPKE suite and the
  complete recipient key, owner root, issuer key/generation and issuer role.
- Authenticated actual management relation, exact intended participant, host
  and enrollment request, finite issuance purpose and subordinate scope.
- Exact `aud` service identifier and separately confirmed HTTPS server origin;
  neither value is derived from the other or from the card.
- Required rooms and result route, immutable source/revision/digest pins for
  every required profile and dependency, finite restrictions and use limits.
- Explicit intake start/end and pin-validity windows; issue ID, nonce and card
  times are request-bound per-issuance values within that protected scope.

Missing complete keys, ambiguous origin, substituted keys, incomplete scope,
suite mismatch or missing finite validity stops issuance before code creation
or signing, and stops receipt before decryption or field use. Changing either
pinned signing key, recipient key, management relation, rooms, result route or
profile pins requires an admitted authenticated transition/re-intake. Recipient
key replacement cancels the earlier outstanding code and creates a distinct
issue record; no in-place edit or silent issuer-generation rotation is allowed.

The transfer uses only an already admitted authenticated channel under its
existing custody policy, for example an authenticated direct exchange, SSH or
a protected file. A DM label or mode 0600 alone proves neither identity,
encryption nor recipient binding. The complete card must not enter shared
rooms, tracked files or generic review/board attachments. An external
participant's not-yet-created account cannot be used to bootstrap trust.
There is no a2a v1 transport or implementation part in this proposal.

## 3. Direct-manager authority and required source extension

The following are proposed future admission requirements, not existing API
capabilities:

1. `issuer` is the complete canonical public signing-key ID of the actual direct
   manager's qualified grant-domain issuer. It equals the sole author
   signature's key and the issuer admitted at intake. A messaging account,
   display name, ordinary agent/message key or borrowed root is not this issuer.
2. Signed `authority` names the exact ordered `grant/1` chain by immutable
   content IDs through to the independently admitted owner root. It also binds
   the selected management relation, subordinate/request and finite issuance
   scope. Exact chain/reference grammar and the management-relation binding
   remain closed source-agreement items; unsigned labels and arbitrary JSON
   provide no authority.
3. Full exact grants and required subject/issuer attestations must exist in
   protected local inputs or a separately admitted bounded public-evidence
   bundle and match the signed IDs. A URL or hash without records is not
   verification. The card selects no network fetch, replacement root or code
   handler. Carried records cannot install a trust anchor.
4. The root authorizes the first link; every parent's subject matches the next
   issuer. Every parent must authorize delegation and cover the child's action,
   target, purpose, audience/server, subordinate/request policy, interval and
   use limits. Check depth and narrowing at every link. A valid signature or
   leaf grant does not authorize child issuance. Missing vocabulary is an open
   source extension, never a wildcard or implicit caveat.
5. Check the root, every issuer/subject/key generation and grant ID against
   current admitted authority, attestations, revocation and qualified time.
   Historical `iat` cannot rescue a revoked or expired ancestor, a stale
   snapshot or a mismatched generation. A current leaf cannot repair its parent.
6. The recipient and redeeming service independently check the actual direct
   management relation against authenticated protected configuration. A valid
   chain to the correct root alone does not prove that relation. An unrelated
   manager, sibling or product manager bypassing an existing project manager
   refuses. The signer can act only within its covered subtree and issuance
   purpose; it cannot reparent a participant or grant account/room powers.

Preserve current source maxima: chain depth 4 and aggregate chain intake
262144 bytes. The complete card remains at most 16384 bytes. Signed references
permit bounded separate evidence, not an unbounded embedded chain, truncation
or implicit increase in any limit. Missing evidence, unsupported child issuance
or unavailable providers refuse/unavailable under the agreed source contract;
there is no fallback to flat service permission or root impersonation.

Source must explicitly admit the selected **per-manager qualified issuance
profile** for exactly proposed `sealed-payload/1`, profile
`external-agent-landing/1`, bind it to the authenticated direct-manager
relation and covering chain, and explicitly admit the owner root's authority
for this new profile. If extending grant-service, amend its closed record
language, D30 subject role/provenance and grant-domain signing checks. If
selecting a distinct profile, agree its exact key class, purpose, roles,
actions, algorithms, protected source and revocation domain. No algorithm,
key conversion or existing service-key use is selected by implication.

The proposed source change must agree all affected boundaries together:
section 1 scope; section 2.1 type/body schema and type-keyed bound; section 2.4
domain, profile, literal count and key/role/type matrix; section 2.6 D30 and
grant-domain admission; sections 3.1/3.5 issuance vocabulary and narrowing;
and section 6 verifier ordering and full-authority result/API. A candidate
domain is exact ASCII `swarma-envelope sealed-payload/1` with the ordinary LF
delimiter and existing signing construction; it is **unregistered** here.
Any future literal-count assertion must match the actual accepted table.
No domain registry, table, action, target or refusal name is changed by this
document. Exact new spellings and first-failure subordering are source-owned
open items, not caller-selected extensions.

Existing provider presence rules apply to the exact typed operation. Neither
mandatory owner Touch ID per card nor an automatic presence exemption follows
from the hierarchy. Preparation, provider qualification, signing sitting,
verification, redemption and live onboarding remain separate gates. A required
presence or qualified-display check must refuse without a released signature
or usable partial artifact when absent.

## 4. Closed proposed card and encryption context

Keep exactly the existing four outer members `version`, `body`, `id`,
`signatures`. The proposed body is a closed, source-agreed schema with one
author signature and no duplicate, extra or other-role signatures. The v1
profile set is exactly `{external-agent-landing/1}`. A generic type name does
not admit another payload, wildcard, supplied decoder or negotiated profile.
Each additional profile requires separate schema, purpose, signer provenance,
limits, parser, refusal order, conformance and consumer adoption.

| Logical signed body content | Proposed binding and placement |
| --- | --- |
| `type`, `profile`, `aud`, `nonce`, `iat`, `exp` | Exact expected proposed type/profile, independently fixed audience, fresh random 16-byte nonce, explicit UTC integer seconds and `0 < exp - iat <= 3600`. |
| `recipient`, `participant`, `request`, `issue_id` | Complete confirmed encryption key, exact host/participant/request binding and unique durable server-side issue identity. Nonce is not a replacement operation ID. |
| `issuer`, `authority`, management binding | Exact intake issuer/generation, ordered grant IDs to the independent root and finite direct-manager relation/scope; all enter the signed context. |
| `suite` | Closed integer object: mode 0, kem 32, kdf 1, aead 3, no other member; independently selected and compared to intake. |
| `server_origin`, `rooms`, `result_route` | Exact intake HTTPS origin, required room IDs and result recipient/route. No redirect, discovery or locator fetch. |
| `profile_pins`, `restrictions` | Complete immutable source/revision/digest dependencies and finite enrollment/use scope, equal to intake. A branch or moving label is insufficient. |
| `owner_public_keys`, if carried | Closed non-secret public-key declarations only, bound to context. No trust installation or replacement; exact grammar remains open. |
| `enc` | Canonical unpadded base64url of exactly 32 bytes, exactly 43 encoded characters. |
| `ciphertext` | Canonical unpadded base64url of 16–4112 bytes, at most 5483 encoded characters; exact inline AEAD output, never plaintext or a locator. |

All non-secret fields remain in signed cleartext, including scope, relation,
authority references, server, rooms, pins and restrictions. Only the one-use
code object is encrypted. A qualified display must project the exact checked
signed cleartext; unsigned replacements cannot change approval. The signer
checks canonicality, closed schema, profile/suite, scope/time, key equality and
ciphertext framing, but does not receive or claim to validate the plaintext
code. Code creation/sealing/redemption needs its own reviewed secret-safe
native component. A wrong body, tag, role, key, scope, time or display binding
refuses before releasing a signature. Message signing remains unchanged and
must reject this tag.

The complete received envelope is bounded at 16384 bytes **while reading**,
under the protected expected type, before unbounded parsing/allocation. Keep
all shared CCJ-1 depth, string, array and duplicate limits; strings are at most
8192 bytes. Check encoded `enc` length 43 and ciphertext length at most 5483
before bounded canonical decoding, then prove decoded 32 and 16–4112 lengths
before HPKE. Never truncate. Exact nested field grammar, array/member caps and
typed refusal names remain open source items.

The proposed encryption key namespace is `x25519-hpke:` plus canonical
unpadded base64url of exactly 32 public-key bytes; it is disjoint from signing
IDs and supplies no signing role. Source must accept its spelling or one
compatible replacement before implementation. Validate X25519 input at intake
and seal time, reject low-order inputs producing an all-zero DH result and
abort either KEM operation on an all-zero shared secret.

The singleton suite is RFC 9180 HPKE Base mode 0,
DHKEM(X25519, HKDF-SHA256) KEM 32, HKDF-SHA256 KDF 1,
ChaCha20Poly1305 AEAD 3. Use one fresh encapsulation and one single-shot
message at sequence 0 per issuance; no context, encapsulation or nonce reuse.
No suite negotiation, downgrade or failed-signature fallback is allowed. Base
mode does not authenticate the sender: anyone with a recipient public key can
seal a ciphertext. Full outer signature AND authority verification precede
decryption. A successful AEAD result grants no issuance authority.

Separate P-256 HPKE, HPKE Auth and NIP-44 are comparison alternatives only,
outside v1. Auth would require a separately authenticated sender KEM binding;
NIP-44 requires its own sender ECDH/NIP-01 signature context and cannot be
silently substituted for this envelope. No third event container is added.
The selected suite hides no metadata and is not claimed to protect past cards
after compromise of a retained recipient private key. The primitive contract
is [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html); application framing,
replay handling and platform adoption are separate obligations.

### Context structure — exact revised bytes OPEN

The context must commit to all signed non-secret fields, including the new
issuer/authority/management bindings. Preserve the reviewed structural order:

1. `H0` is the closed body object with `enc` and `ciphertext` **absent**, not
   null/empty, and without envelope ID or signatures.
2. A domain-separated commitment over CCJ-1(H0) feeds HPKE `info`; the
   source-agreed complete `info` must be **at most 64 bytes**.
3. HPKE setup produces `enc`. `H` is H0 plus canonical `enc`; the
   source-agreed domain-separated CCJ-1(H) bytes form AAD.
4. Seal once, add exact ciphertext, then compute the existing content ID and
   sign the complete body through the existing role/key/version/type-bearing
   record construction. No cyclic dependency on the ID/signature is introduced.

Exact domain/label bytes, LF delimiters, raw versus textual digest encoding,
info/AAD derivation and revised valid/invalid known-answer vectors remain
**OPEN** for source agreement. The earlier long info-label construction is
superseded and must not be used; this proposal invents no replacement bytes.
Owner-root, issuer or management/chain changes require newly sealed and signed
bytes. Detached evidence must match exact signed IDs and protected context;
unsigned or ciphertext-external authority cannot override H0. Old vectors do
not transfer merely because the HPKE suite is unchanged.

The decrypted plaintext is exactly one CCJ-1 object whose sole member is
`code`, a nonempty opaque UTF-8 string. Maximum canonical plaintext is 4096
bytes and depth 2; code UTF-8 length is at most 4085 bytes, with escaping still
fitting the 4096-byte bound. Controls, duplicates, arrays, nested objects,
additional context or alternate code fields refuse. Check opened byte length
before parsing and the closed grammar before code submission. The 4112-byte
ciphertext maximum includes the fixed 16-byte tag. Service-owned code syntax
is not interpreted as commands or a URL. Decrypted fields cannot override
signed scope.

No plaintext code, decryption key, sensitive preimage or secret-bearing card
may enter model prompts, argv, history, diagnostics, rooms or generic artifacts.
Evidence carries non-secret issue IDs/digests/status only. Temporary secret
storage requires a separately admitted retention/deletion/recovery contract;
none is supplied here.

## 5. Receive, redeem and recover

A qualified receiver starts from protected expected type/profile, complete
authenticated intake, qualified chain verifier and current protected authority,
attestation, revocation and time inputs. Pin-only admission is excluded. An
uninitialized recipient lacking these inputs is not ready to consume the
card; an operator-assisted code-only route does not implement this contract.

The proposed first-failure pipeline preserves these stages; exact E6 internal
subordering and new result/refusal spellings must be agreed before implementation:

| Stage | Mandatory gate before continuing |
| --- | --- |
| E1 | Protected-type 16384-byte streaming bound before unbounded allocation. |
| E2 | Strict canonical parse, closed outer/body/profile schema, shared limits, singleton suite and bounded enc/ciphertext framing. No field is yet a destination or action. |
| E3 | Exact version and protected expected type/profile; unknown values refuse without fallback. |
| E4 | Exactly one author signature, with no other, extra or duplicate role/signature. |
| E5 | Recompute the existing content ID from the exact complete body. |
| E6 | Verify exact outer signature, key = issuer = intake issuer, admitted issuance profile and complete valid ordered chain to the independently pinned owner root. Check every current authority, attestation, generation, revocation, depth/narrowing and actual management relation. Missing parent/evidence/snapshot/root or unqualified time refuses before opening. |
| E7 | Compare audience and origin independently; then complete recipient, suite, host/participant/request, rooms/route, pins and restrictions to intake. Validate request-bound issue ID and nonce. No profile fetch or other field use. |
| T1/T2 | Validate card/code/intake windows plus the chain's independently admitted current-time/currency rules. The strictest deadline wins; no renewal. |
| E8 | Durably reserve the winning content ID, issue ID and nonce/context under complete issuer key plus enrollment request, before opening or releasing code. Missing/unreadable journal or failed durable write refuses. |
| Open | HPKE open using protected key and agreed exact info/AAD; bound and validate the closed code object before any submission. No plaintext output on failure. |
| Redeem | Submit only to the exact intake origin for the same issue/recipient/request; the service independently rechecks current covering hierarchy and scope and serializes currency/revocation with reservation before effect. |

The card interval is `0 < exp - iat <= 3600` seconds and contained in the
explicit intake/pin windows; code lifetime is at most one hour and cannot
outlast stricter issuance or authority policy. Existing `message/1` and
`operator-act/1` retain `0 < exp - iat <= 120` seconds. Grant windows remain
bounded by their chain and protected consumer policy; the card extends none.

Retain local UTC integer seconds with zero additional skew and a durable
nondecreasing wall-clock watermark as an additional conservative gate. Refuse
unavailable time/watermark, observed rollback, future `iat`, expired or invalid
intervals and out-of-window cards. This detects only observed rollback and
does not qualify trusted current grant time. A local watermark alone never
establishes current authority; server expiry/currentness remains independent.

First accepted content ID wins for the issuer/request. Identical bytes/ID may
reconcile that same operation; a different ID refuses until a new authenticated
intake/request. Durable phases distinguish accepted, opened, redemption pending,
confirmed and refused without storing secrets. After interruption, reconcile
the same winning operation; no replacement ID or allowance is created because
an effect is uncertain.

After opening, the only allowed action is code presentation through the agreed
onboarding UI/API to the exact intake-confirmed origin for the same issue,
recipient and request. Before confirmed redemption there is no redirect,
profile fetch/install/activation, room invitation/JOIN/power change,
result-route traffic or other card-selected effect. Refusal, timeout or a lost
or ambiguous response preserves the pending/unknown fence. A confirmed
response permits only separately admitted subsequent onboarding steps; it
never automatically launches arbitrary instructions or proves complete
onboarding, assignment or idle-wake readiness.

The service atomically reserves the issue/code allowance and writes a durable
enrollment operation identity before effect. Concurrent attempts allow at most
one enrollment effect. A valid idempotent retry returns the existing outcome;
changed recipient/server/arguments refuse. Lost responses or partial effects
reconcile the same operation, retaining uncertainty until resolved. Never
release a consumed code, reset a reservation or duplicate an effect merely
because its response was lost. Revoked/expired/unknown codes and missing replay
history refuse; a parent revoked between receive and redeem must be caught by
the independent current server gate.

The full-authority observation needs a distinct truthful source-agreed result
and observation time. Earlier `ISSUER_PINNED_UNVERIFIED_CHAIN` records remain
historically limited observations. Later current verification records a new
observation over original exact bytes and current context; it never upgrades
historical authority/presence, repeats enrollment or refreshes an allowance.

## 6. Paired acceptance and forbidden cases

These are semantic requirements for future implementation and independent
review, **not executed cryptographic or runtime tests**. Each negative has a
nearby valid future-admitted control; rejecting everything is not success.
All intake/admission/context failures forbid decryption, obtaining or submitting
a code and external effects. Post-open plaintext failures forbid submission;
redemption failures fence subsequent onboarding effects.

| Valid control / changed forbidden case | Required observation |
| --- | --- |
| Future-qualified actual project-manager chain for its worker / unrelated or sibling manager with otherwise valid signature and root chain | Only the authenticated actual manager in the covered subtree passes E6; no sibling authority. |
| Authenticated directly staffed product-manager worker / product manager bypassing an existing project manager | Direct staffing passes after future admission; bypass refuses, with no invented management tier. |
| Independently admitted root and issuer / attacker root, self-pinned carried root or issuer replacement | Root/key mismatch refuses before opening; carried records install no trust. |
| Complete matched delegable parent links / missing link, mismatched subject/next issuer, exhausted depth or wider action/target/purpose/server/recipient/interval/use | Narrow chain can proceed; the specific chain/narrowing failure refuses without partial signature or usable effect. Missing vocabulary is unavailable, not a wildcard. |
| Current valid parents, generations and attestations / revoked or expired ancestor, mismatched generation, missing/stale snapshot or unqualified current time | E6 current authority gate refuses; historical iat or a valid leaf does not rescue it. |
| Future-qualified issuance key/profile and covering grant / ordinary agent key, wrong service purpose, operator-device, commit/publisher key or today's grant-service used for sealed-payload | Intended profile refusal before opening; parent grants/signatures never widen closed source tables. |
| Signed ordered chain IDs with exact protected evidence / changed ID/order, substituted record, missing evidence, URL-only record or card-selected fetch | Closed/binding refusal; no unauthenticated retrieval or external fetch. |
| Qualified complete-chain receiver / correct issuer pin, signature and HPKE keys but no current chain view | Complete authority can reach scope/time/replay gates; pin-only receiver refuses. |
| Complete intake keys and full digest / matching abbreviation but different complete key, card-completed key or ambiguous origin | Exact complete-key/origin check refuses before code creation or opening. Possession alone is insufficient. |
| Admitted author with valid binding / no admitted author with independently confirmed encryption pair / unknown self-signed author | First two use their explicit closed cases; unknown self-signature grants no origin authority. |
| Exact singleton type/profile/suite / unknown version, alternate/misspelled/wildcard profile, suite or extra schema field | Bounded refusal without decoder dispatch, downgrade, crash or raw payload logging. |
| Signature key = issuer = intake issuer over complete body / different body issuer, retagged grant signature, modified ciphertext or header | ID/signature/profile gate refuses before HPKE; valid AEAD alone is insufficient. |
| Signed context equals protected intake / changed audience, origin, recipient, host/request, room/route, pin, restriction or management relation | Specific context mismatch refuses before opening or fetch/effect; no implicit widening of use or origin. |
| Exact display projects checked non-secret fields / hidden unsigned replacement, modified signed field or missing required provider presence | Qualified binding/presence refusal, no released signature or usable partial artifact; code never enters signer/display. |
| Enc32, ciphertext16–4112, canonical base64url and upper valid bounds / enc31 or33, ciphertext15 or4113, noncanonical encoding or >5483 encoded ciphertext characters | Intended bounded pre-HPKE refusal, no truncation or blanket rejection. |
| Envelope16384 bytes and chain within depth4/aggregate262144 / envelope16385, chain depth/aggregate overflow or attacker-selected type | Enforce protected bounds before unbounded allocation; no raised caps. |
| Independently agreed revised info/AAD vectors / changed label, LF, absent-to-null, digest encoding, enc, suite, unsigned authority or manager replacement | Context/signature failure, no opening/effect; exact independent known-answer vectors remain required. |
| Valid X25519 input / low-order recipient or all-zero shared secret | Reject at intake/seal/open as applicable; no unsafe sealed code. |
| Code-only closed canonical object within4096 / extra context, duplicate code, array, nested object, controls or oversize | Refuse after bounded open but before submission, with no leaked or usable partial plaintext. |
| Valid card <=3600, message/act <=120 and qualified current windows / greater interval, expired pin/code, rollback, missing watermark, future iat or wider child interval | Intended time gate refuses; code, local clock and card never extend authority or another type's lifetime. |
| First winning ID and identical retry / different ID for same issuer/request, unreadable journal or failed durable reservation | First ID persists before opening; identical retry reconciles once, others refuse without replacement allowance. |
| Confirmed same-issue redemption / revoked or unknown code, parent revoked after receipt, timeout or lost response | Independent server current gate and durable fence prevent forbidden follow-on effects; uncertainty stays pending/unknown. |
| One successful operation with concurrent identical retry / duplicate race, partial effect/lost response or changed retry arguments | At most one effect, same durable result or intended conflict; preserve reserved/consumed state. |
| Historical pin-only observation plus a new valid current-chain observation / historical relabeling, effect replay or renewed allowance | Only an explicit new observation; no authority upgrade of the past. |
| Dedicated future sealed verifier / same bytes sent to existing message-only consumer or Matrix envelope message path | Message consumer refuses without wake, forward, re-emission or raw payload log. |
| Clean isolated release fixture / inert planted prohibited code/preimage/key sentinel | Release checker must detect the intended violation and refuse; skip, unapplied plant, crash or unrelated setup failure is not passing evidence. |

Ciphertext authenticity and authority need separate independent expectations;
two implementations agreeing is not an oracle. Destructive controls must use
isolated fixtures, never live accounts, real codes, root keys or native secret
stores. This document alone proves none of these executable properties.

## 7. Open agreement and implementation gates

The following remain **OPEN**, and prevent execution:

1. Source admission of the sealed type/profile/domain, closed schemas and
   nested grammar, lifetime/type-keyed bounds, per-manager issuer profile and
   owner-root language, D30/provenance and grant-domain signing rules. Existing
   tables and current `grant/1`-only service rule remain untouched.
2. Exact grant action/target/purpose/subordinate-use vocabulary, ordered chain
   and management-relation grammar, protected evidence/currentness inputs and
   revocation domain. Dock to exact implemented child-grant/provider contracts
   in both directions; Link Spec v0.1.60 alone supplies no readiness.
3. Bounded HPKE `info` (at most64 bytes), exact revised context bytes and
   independent valid/invalid known-answer vectors committing all authority and
   management fields. No adoption of the superseded long label or old vectors.
4. Recipient key namespace/validation, explicit author/no-author binding and
   request-bound possession protocol; closed declaration/array limits; secret-
   safe preparation/sealing API and storage/recovery contract.
5. Full-authority verifier API/result, exact first-failure subordering and new
   refusal spellings; separately implemented qualified authority/time/replay
   inputs, durable receiver/server operation state and serialized revocation
   checks. Pin-only verification is not a fallback.
6. Provider/native custody, qualified display/presence and issuance readiness;
   independent whole-solution review and conformance, required checks,
   signatures, source acceptance and separately admitted consumer adoption.
   Text publication or a passing codec is not whole-path readiness.

Existing message verification remains unchanged. Use a separate sealed-profile
entry point whose expected type/profile comes from protected configuration.
In v1 do not carry this object under Matrix content key
`works.relux.swarm.envelope`; no transport/message-verifier reinterpretation
is admitted. Any later transport adoption must independently prove these
rejections against actual consumer code.

This proposal authorizes no real card issuance, registration, key or native
secret-store operation, provider change, service launch or runtime activation.
Signing a document and publishing a proposal remain separate from implementing,
qualifying and using the proposed enrollment protocol.
