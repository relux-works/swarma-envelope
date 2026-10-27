// Package owneracts parses closed owner-acts/1 arguments and unsigned bodies,
// and maps typed proposals to exact rendering, argument, body and signing-preimage
// bytes. These APIs do not authorize an act, establish protected facts or current
// rights, produce an immutable signing plan, or enable an effect. Consumer
// verification remains a separate obligation in verifier.VerifyOwnerAct.
package owneracts

import (
	"bytes"
	"strings"

	"github.com/relux-works/swarma-envelope/record"
)

// Arguments is a decoded grammar-only value. Its strings own their storage;
// there is no retained caller buffer, map or slice. Callers can construct or
// change this value, so it is never durable validation evidence or authority.
// BoundRoom is empty for bind; AudienceRevision/AudienceDigest are zero/empty
// except for mirror-enable. Mirror is false for bind and unbind, true for enable.
type Arguments struct {
	Operation          string
	Profile            string
	SourceRoom         string
	SourceRecipient    string
	TextSHA256         string
	AuthorityRevision  int64
	IdentityGeneration int64
	BindingRevision    int64
	OwnerRecipient     string
	BoundRoom          string
	Mirror             bool
	AudienceRevision   int64
	AudienceDigest     string
}

// Error is a parser-local failure containing no received bytes. Code is one of:
// arguments_operation_unsupported (unknown or reserved selector),
// arguments_too_large (more than 2048 received bytes),
// arguments_invalid (CCJ syntax/value/depth or closed schema/value failure), or
// arguments_noncanonical (valid CCJ whose canonical bytes differ).
// These are not operator verifier refusal codes or wire verdicts.
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

// Parse accepts exact canonical CCJ-1 object bytes for the explicitly selected
// owner-dm.bind, owner-dm.unbind or owner-dm.mirror-enable operation. It checks the
// selector first, then the 2048-byte ceiling before parsing/copying, depth 4,
// canonical bytes, and the closed flat schema. Arrays and nulls are never fields.
// All failures return Arguments{}; input bytes are never changed or retained.
// No state, delivered text, audience or digest equality is established here.
func Parse(operation string, raw []byte) (Arguments, error) {
	fail := func(code string) (Arguments, error) { return Arguments{}, &Error{Code: code} }
	var additional []string
	switch operation {
	case "owner-dm.bind":
		additional = []string{"identity_generation", "binding_revision", "owner_recipient", "mirror"}
	case "owner-dm.unbind":
		additional = []string{"identity_generation", "binding_revision", "owner_recipient", "bound_room"}
	case "owner-dm.mirror-enable":
		additional = []string{"identity_generation", "binding_revision", "owner_recipient", "bound_room", "mirror", "audience_revision", "audience_digest"}
	default:
		return fail("arguments_operation_unsupported")
	}
	if len(raw) > 2048 {
		return fail("arguments_too_large")
	}
	v, err := record.Parse(raw, 2048, 4)
	if err != nil {
		return fail("arguments_invalid")
	}
	canonical, err := record.Canonical(v)
	if err != nil {
		return fail("arguments_invalid")
	}
	if !bytes.Equal(raw, canonical) {
		return fail("arguments_noncanonical")
	}
	m, ok := v.(map[string]any)
	common := []string{"profile", "source_room", "source_recipient", "text_sha256", "authority_revision"}
	if !ok || !members(m, append(common, additional...)) {
		return fail("arguments_invalid")
	}
	profile, _ := m["profile"].(string)
	sourceRoom, a := identifier(m["source_room"])
	sourceRecipient, b := identifier(m["source_recipient"])
	ownerRecipient, c := identifier(m["owner_recipient"])
	textHash, d := m["text_sha256"].(string)
	authorityRevision, e := revision(m["authority_revision"], 1)
	identityGeneration, f := revision(m["identity_generation"], 1)
	bindingRevision, g := revision(m["binding_revision"], 0)
	if profile != "owner-acts/1" || !a || !b || !c || !d || !hex64(textHash) || !e || !f || !g {
		return fail("arguments_invalid")
	}
	args := Arguments{
		Operation: operation, Profile: profile, SourceRoom: sourceRoom,
		SourceRecipient: sourceRecipient, TextSHA256: textHash,
		AuthorityRevision: authorityRevision, IdentityGeneration: identityGeneration,
		BindingRevision: bindingRevision, OwnerRecipient: ownerRecipient,
	}
	if operation != "owner-dm.bind" {
		args.BoundRoom, ok = identifier(m["bound_room"])
		if !ok {
			return fail("arguments_invalid")
		}
	}
	if operation != "owner-dm.unbind" {
		args.Mirror, ok = m["mirror"].(bool)
		if !ok || args.Mirror != (operation == "owner-dm.mirror-enable") {
			return fail("arguments_invalid")
		}
	}
	if operation == "owner-dm.mirror-enable" {
		args.AudienceRevision, ok = revision(m["audience_revision"], 1)
		digest, isString := m["audience_digest"].(string)
		if !ok || !isString || !strings.HasPrefix(digest, "sha256:") || !hex64(strings.TrimPrefix(digest, "sha256:")) {
			return fail("arguments_invalid")
		}
		args.AudienceDigest = digest
	}
	return args, nil
}

func members(m map[string]any, names []string) bool {
	if len(m) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := m[name]; !ok {
			return false
		}
	}
	return true
}

func identifier(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || len(s) < 1 || len(s) > 255 {
		return "", false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return "", false
		}
	}
	return s, true
}

func revision(v any, min int64) (int64, bool) {
	n, ok := v.(int64)
	return n, ok && n >= min && n <= 9007199254740990
}

func hex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
