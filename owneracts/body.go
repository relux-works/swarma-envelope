package owneracts

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
)

// Body is ordinary grammar-only data for an unsigned owner-acts/1 body. Type
// and TargetKind are always operator-act/1 and owner-dm. Identity is target.id.
// All strings own their storage; copies contain no shared mutable buffers.
// Callers can construct or change Body: it is not an immutable signing plan,
// protected selection, authorization, confirmation evidence or signed act.
type Body struct {
	Type            string
	Audience        string
	Nonce           string
	IssuedAt        string
	ExpiresAt       string
	Operation       string
	TargetKind      string
	Identity        string
	Owner           string
	Epoch           string
	ActionID        string
	ArgumentsDigest string
	Confirmed       bool
}

// BodyError contains only a fixed local code, never received values or a wire
// verifier verdict: body_too_large, body_invalid, body_noncanonical, or
// body_operation_unsupported. Every failure returns Body{}.
type BodyError struct{ Code string }

func (e *BodyError) Error() string { return e.Code }

// ParseBody accepts only the closed canonical unsigned operator-act/1 body for
// owner-dm.bind, owner-dm.unbind and owner-dm.mirror-enable. It checks size before
// decoding/copying, bounded CCJ, canonical equality, exact members, operation,
// then all field values. It never changes or retains raw; raw must remain stable
// during the call. Empty input is invalid. No key, signature, arguments or
// caller-provided preimage is accepted as a member.
//
// ArgumentsDigest is syntax only: full separate arguments and Map equality,
// protected enrollment/selection, immutable display/preimage preparation and
// native confirmation/signature verification remain separate obligations.
// Confirmed is signed data only; timestamps establish no trusted current time.
func ParseBody(raw []byte) (Body, error) {
	fail := func(code string) (Body, error) { return Body{}, &BodyError{Code: code} }
	if len(raw) > 8192 {
		return fail("body_too_large")
	}
	v, err := record.Parse(raw, 8192, 16)
	if err != nil {
		return fail("body_invalid")
	}
	canonical, err := record.Canonical(v)
	if err != nil {
		return fail("body_invalid")
	}
	if !bytes.Equal(raw, canonical) {
		return fail("body_noncanonical")
	}
	m, ok := v.(map[string]any)
	if !ok || !members(m, []string{"type", "aud", "nonce", "iat", "exp", "operation", "target", "owner", "epoch", "action_id", "arguments_digest", "confirmed"}) {
		return fail("body_invalid")
	}
	op, ok := m["operation"].(string)
	if !ok {
		return fail("body_invalid")
	}
	switch op {
	case "owner-dm.bind", "owner-dm.unbind", "owner-dm.mirror-enable":
	default:
		return fail("body_operation_unsupported")
	}
	target, ok := m["target"].(map[string]any)
	if !ok || !members(target, []string{"kind", "id"}) {
		return fail("body_invalid")
	}
	// Bound each string before field decoding or creating returned copies.
	for _, field := range []struct {
		value any
		max   int
	}{
		{m["type"], 14}, {m["aud"], 43}, {m["nonce"], 22},
		{m["iat"], 20}, {m["exp"], 20}, {target["kind"], 8},
		{target["id"], 63}, {m["owner"], 255}, {m["epoch"], 38},
		{m["action_id"], 22}, {m["arguments_digest"], 71},
	} {
		s, ok := field.value.(string)
		if !ok || len(s) > field.max {
			return fail("body_invalid")
		}
	}
	kind, identity := target["kind"].(string), target["id"].(string)
	owner, audience, epoch := m["owner"].(string), m["aud"].(string), m["epoch"].(string)
	confirmed, ok := m["confirmed"].(bool)
	if !ok || m["type"] != "operator-act/1" || kind != "owner-dm" || !identityName(identity) ||
		len(owner) == 0 || !utf8.ValidString(owner) || !namespace(audience, "owner-acts:") || !namespace(epoch, "epoch:") ||
		!record.IsContentID(m["arguments_digest"].(string)) {
		return fail("body_invalid")
	}
	if _, err := record.DecodeBase64(m["nonce"].(string), 16); err != nil {
		return fail("body_invalid")
	}
	if _, err := record.DecodeBase64(m["action_id"].(string), 16); err != nil {
		return fail("body_invalid")
	}
	start, startOK := mappingTime(m["iat"].(string))
	end, endOK := mappingTime(m["exp"].(string))
	if !startOK || !endOK || end <= start || end-start > 120 {
		return fail("body_invalid")
	}
	return Body{
		Type: strings.Clone(m["type"].(string)), Audience: strings.Clone(audience),
		Nonce: strings.Clone(m["nonce"].(string)), IssuedAt: strings.Clone(m["iat"].(string)),
		ExpiresAt: strings.Clone(m["exp"].(string)), Operation: strings.Clone(op),
		TargetKind: strings.Clone(kind), Identity: strings.Clone(identity), Owner: strings.Clone(owner),
		Epoch: strings.Clone(epoch), ActionID: strings.Clone(m["action_id"].(string)),
		ArgumentsDigest: strings.Clone(m["arguments_digest"].(string)), Confirmed: confirmed,
	}, nil
}
