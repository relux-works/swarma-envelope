# Owner-act argument grammar

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

This package does not hash or match actual delivered text, compute an audience
digest, derive rendering/A0/preimages, compare any field to protected state,
verify signatures, establish current rights/currency, read clocks or journals,
produce effect plans, or implement consumer/native/provider integration. Bind
and mirror grammar success does not open any widening or native activation gate.
The existing record/verifier APIs, schemas and refusal order are unchanged.

## Narrow validation

From the repository root:

```sh
GOMAXPROCS=2 "$CURATOR_GO" test ./owneracts -p 1 -count=1
GOMAXPROCS=2 "$CURATOR_GO" build ./owneracts
GOMAXPROCS=2 "$CURATOR_GO" vet ./owneracts
"${CURATOR_GO%/go}/gofmt" -l owneracts
```

Tests include literal positive fixtures, schema/type and encoding refusals,
field/integer bounds, byte-cap neighbors and input ownership. Expected grammar
comes from the field contract above; the codec is used to construct additional
wire fixtures, not as an independent oracle of accepted schemas. The API-name
inventory checks only this package's exported names. Commands report to
stdout/stderr; keep captured logs in an ignored task-scoped temporary directory.
These checks do not qualify a full owner-act verifier, native hardware, policy,
carrier behavior or eventual effect safety.
