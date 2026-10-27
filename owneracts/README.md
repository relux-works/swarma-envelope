# Owner-act arguments, unsigned bodies and byte mapping

`Parse(operation, raw)` accepts only the closed `owner-acts/1` canonical
argument object for an explicitly selected operation. This is grammar intake,
not authorization, a protected-state assertion, a signature plan or an operator
verification verdict. Callers must select the profile from their own reviewed
configuration; an input cannot select a policy or handler.

The exact active selectors are `owner-dm.bind`, `owner-dm.unbind` and
`owner-dm.mirror-enable`. `launch.approve`, `host.change`, aliases and unknown
selectors refuse. There are no reserved-operation schemas or handlers here.

## Accepted fields

Every operation requires exactly these common fields:

| Field | Grammar |
| --- | --- |
| `profile` | Literal `owner-acts/1` |
| `source_room`, `source_recipient` | Opaque printable ASCII bytes 0x21–0x7e, length 1–255 each |
| `text_sha256` | Exactly 64 lowercase hexadecimal digits, without prefix |
| `authority_revision` | Integer 1–9007199254740990 |

The only additional fields are:

| Operation | Required fields |
| --- | --- |
| `owner-dm.bind` | `identity_generation`, `binding_revision`, `owner_recipient`, `mirror` literal false |
| `owner-dm.unbind` | `identity_generation`, `binding_revision`, `owner_recipient`, `bound_room` |
| `owner-dm.mirror-enable` | `identity_generation`, `binding_revision`, `owner_recipient`, `bound_room`, `mirror` literal true, `audience_revision`, `audience_digest` |

`identity_generation` and `audience_revision` are integers
1–9007199254740990; `binding_revision` is an integer 0–9007199254740990.
`owner_recipient` and `bound_room` use the same ASCII and length bounds as
`source_room`. `audience_digest` is the literal prefix `sha256:` followed by
exactly 64 lowercase hexadecimal digits.

The received object must be canonical CCJ-1, at most 2048 bytes, with a depth
ceiling of 4. These schemas are flat: every member has its specified scalar
type. Duplicate, unknown, missing, null, nested and array-valued members refuse.
The existing codec rejects invalid UTF-8, malformed escapes, unsafe integers,
floats and numeric spelling variations. Canonical comparison rejects whitespace,
key-order and escape variations rather than silently rewriting received bytes.
Non-ASCII identifiers refuse without Unicode normalization. Canonical escaping
of quote and backslash bytes is allowed within printable ASCII identifiers;
escaping counts toward the received-byte ceiling.

## Results and failures

`Arguments` contains independent scalar values with owned string storage and no
retained input buffer, map or slice. Absent operation-specific fields are zero:
`BoundRoom` is empty for bind; audience fields are zero/empty except for enable;
`Mirror` is false for bind and unbind. Callers can construct or modify this value,
so it is never durable validation evidence. Every error returns `Arguments{}`
and leaves the caller buffer unchanged. Concurrent mutation of the input while
parsing is outside the API contract.

`Error.Code` is parser-local and contains no received bytes. Checks run in this
order; these codes are not the operator verifier's wire refusal vocabulary:

| Code | Meaning |
| --- | --- |
| `arguments_operation_unsupported` | Selector is reserved or unknown; checked before touching the input |
| `arguments_too_large` | Received bytes exceed 2048; checked before parsing or copying |
| `arguments_invalid` | CCJ syntax/value/depth failure; or, after canonical comparison, a closed-schema/type/value violation |
| `arguments_noncanonical` | Valid bounded CCJ whose canonical bytes differ from the received bytes |

## Canonical unsigned body intake

`ParseBody(raw)` accepts exactly the canonical CCJ-1 **body**, with the twelve
members `type`, `aud`, `nonce`, `iat`, `exp`, `operation`, `target`, `owner`,
`epoch`, `action_id`, `arguments_digest`, `confirmed`. Type is `operator-act/1`;
operations are exactly the three owner-DM operations above. Target is exactly
`{kind:"owner-dm",id:NAME}`, where NAME matches `[a-z0-9][a-z0-9-]{0,62}`.
No envelope, key, signature, arguments, profile/class, handler or preimage member
is accepted. Legacy `revoke`/`grant.issue`, reserved operations and aliases refuse.

Body input is 1–8192 bytes, depth at most 16, arrays at most 64 and strings at
most 8192, subject to stricter fields: owner is nonempty UTF-8 at most 255 raw
bytes; audience is `owner-acts:` plus 32 lowercase hexadecimal digits; epoch is
`epoch:` plus 32 lowercase hexadecimal digits; nonce/action ID are independently
canonical unpadded base64url encodings of 16 bytes. Times retain their original
`YYYY-MM-DDTHH:MM:SSZ` strings, valid years 1970–9999, with positive lifetime at
most 120 seconds. Arguments digest is a full lowercase `sha256:` content ID.
Confirmed accepts both booleans. No random generation, uniqueness, current time
or confirmation is established. Owner spaces, escaped controls and Unicode are
retained exactly, without normalization; other field constraints still apply.
Arrays cannot satisfy any closed body field. The strict fields bound every
valid serialized body to 2043 bytes even with maximal owner escape expansion;
the outer limit still rejects oversized input before parsing/copying.

The returned `Body` includes every scalar and both target components as owned
strings/boolean. No input buffer, map or slice is retained. Assigning a result
or its struct copy cannot modify another result or the input. The caller must
keep input stable during the synchronous call. Ordinary returned data is mutable
and forgeable by the caller; it is not an immutable signing plan or authority.

`*BodyError` contains a fixed local code and no received bytes. Every error
returns `Body{}` and leaves input unchanged. Checks are ordered as follows:

| Code | Meaning |
| --- | --- |
| `body_too_large` | More than 8192 received bytes, before parsing or copying |
| `body_invalid` | Bounded CCJ syntax/value/depth failure (including empty input); or, after canonical equality, wrong closed members/types/field values |
| `body_noncanonical` | Bounded CCJ parses but re-encoding differs from exact input |
| `body_operation_unsupported` | After canonical/closed-member checks, string operation is outside the three-operation registry; before remaining field validation |

This local admission is intentionally strict about whitespace, order and escape
spelling. Existing received-envelope parsing remains permissive about valid JSON
transport variants. No existing parser or verifier refusal order is changed.

Full separately received canonical arguments, their actual digest and exact Map
equality remain later composition obligations; a syntactically valid digest is
not validated arguments. Protected enrollment/device/owner/installation/epoch,
complete root catalogs and pins, immutable full display/preimage preparation,
explicit native owner confirmation and independent native signature verification
are separate requirements. `confirmed=true` is data, never proof of confirmation
or presence. No signing, current rights, native provider or effect follows.

## Typed byte mapping

`Map(MappingInput)` accepts proposed metadata and `ArgumentInput`, the operation's
A0 without `text_sha256`. It does not accept arbitrary maps, raw A0 JSON, a class,
a target kind or a prevalidated `Arguments` value. Profile `owner-acts/1` and
kind `owner-dm` are fixed. Bind and mirror-enable derive class `widening`; unbind
derives `narrowing`. Irrelevant fields must be zero: `BoundRoom` for bind,
audience fields except for mirror-enable, and `Mirror` for bind/unbind.
Relevant argument fields follow the grammar above.

`MappingInput` supplies `Operation`, target `Identity`, `Owner`, `Epoch`,
`Audience`, `ActionID`, `Nonce`, `IssuedAt`, `ExpiresAt`, `Confirmed`, full public
`Key`, and `Arguments`. All strings are bounded before decoding/serialization:

| Input | Static constraint |
| --- | --- |
| Identity | `[a-z0-9][a-z0-9-]{0,62}` |
| Owner | Nonempty valid UTF-8, at most 255 bytes; exact spaces, controls and Unicode forms retained |
| Audience / Epoch | `owner-acts:` / `epoch:` followed by 32 lowercase hexadecimal digits |
| Key | Canonical valid compressed P-256 public key ID, checked by `record.KeyBytes` and `record.ValidateKey` |
| ActionID / Nonce | Independently canonical unpadded base64url encodings of 16 bytes; representation only, no random-generation or uniqueness claim |
| IssuedAt / ExpiresAt | Original UTC-second strings `YYYY-MM-DDTHH:MM:SSZ`, years 1970–9999; positive interval at most 120 seconds |
| Confirmed | Either boolean retained as signed data; never presence evidence |

The mapper constructs D with exactly `profile`, derived `class`, `operation`,
`target`, `owner`, `epoch`, `aud`, `action_id`, `nonce`, `iat`, `exp`, `confirmed`,
`key`, and `arguments` (A0). Using the pinned CCJ-1 codec:

```text
Render = UTF8("owner-acts/1\n") || CCJ-1(D)       (no trailing newline)
A = A0 plus text_sha256 = lowercase hex SHA256(Render)
Arguments = CCJ-1(A)
ArgumentsDigest = "sha256:" plus lowercase hex SHA256(Arguments)
```

Complete A must fit 2048 bytes and Render must fit 4096 bytes; there is no
truncation. The actually computed A passes the existing `Parse` contract.
D contains no text hash, arguments digest, envelope ID or signatures.

`Body` is canonical bytes of exactly the existing `operator-act/1` body:
`type`, `aud`, `nonce`, `iat`, `exp`, `operation`, `target`, `owner`, `epoch`,
`action_id`, `arguments_digest`, `confirmed`. Arguments remain separate.
`ContentID` and `SigningPreimage` use `record.ContentID("operator-act/1", body)`
and `record.SigningPreimage("operator-act/1", key, "approver", body)`.
The latter is the full raw domain-tagged preimage containing body, key, role and
version; neither Render nor its hash is the signature preimage.

`Mapping` returns independent owned byte buffers for Render, Arguments, Body
and SigningPreimage, plus digest strings. Modifying one output cannot change
another or an independent invocation. Ordinary Go struct copies share slices;
returned data is mutable and is not durable validation evidence or a trusted
immutable signing plan. Typed input strings are ordinary Go values; concurrent
unsafe mutation of their backing memory is outside this contract.

Every failure returns `Mapping{}` and `*MappingError` with a local code and no
received values. Unsupported operations return `mapping_operation_unsupported`;
invalid typed metadata or A0 returns `mapping_invalid`; complete A/Render cap
violations return `mapping_too_large`. These are not wire verifier verdicts.
Individual string-cap violations are invalid input. No usable partial output is
returned, including for failures found after rendering.

These APIs do not sign, read a clock/RNG, observe delivery context or audience,
compare protected state, verify signatures, establish current rights,
currency or replay safety, write journals, enable effects or integrate a
native/provider consumer. The mapper checks the supplied audience digest's
format and binds its bytes; it does not establish equality to an observed
roster. No signed-envelope size is checked because no envelope is input.
The envelope verifier recognizes the `owner-dm` target grammar, but its
operations still refuse as `act_operation_unknown` in `VerifyOperator`.
Mapping success does not admit an act or open widening/native activation gates.
The mapper does not change record algorithms or verifier refusal order.

## Narrow validation

From the repository root:

```sh
GOMAXPROCS=2 "$CURATOR_GO" test ./owneracts -p 1 -count=1
GOMAXPROCS=2 "$CURATOR_GO" build ./owneracts
GOMAXPROCS=2 "$CURATOR_GO" vet ./owneracts
"${CURATOR_GO%/go}/gofmt" -l owneracts
```

Tests include literal positive fixtures, unsigned-body ten-family grammar sweep,
separate body free hunt, schema/type and encoding refusals,
field/integer bounds, byte-cap neighbors, exact mapping goldens, field binding,
raw-byte identity and input/output ownership. Mapping goldens fix complete byte
outputs and hashes independently from the mapper and codec under test. Expected
grammar comes from the field contract above; the codec is used to construct additional
wire fixtures, not as an independent oracle of accepted schemas. The API-name
inventory checks only this package's exported names. Commands report to
stdout/stderr; keep captured logs in an ignored task-scoped temporary directory.
These checks do not qualify a full owner-act verifier, native hardware, policy,
carrier behavior or eventual effect safety.
