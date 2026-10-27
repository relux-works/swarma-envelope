package owneracts

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
)

// ArgumentInput is typed A0: the operation's arguments without text_sha256.
// Profile is fixed internally. Irrelevant operation-specific fields must be zero.
// Values are caller assertions, not protected state or validated evidence.
type ArgumentInput struct {
	SourceRoom         string
	SourceRecipient    string
	AuthorityRevision  int64
	IdentityGeneration int64
	BindingRevision    int64
	OwnerRecipient     string
	BoundRoom          string
	Mirror             bool
	AudienceRevision   int64
	AudienceDigest     string
}

// MappingInput supplies proposed body metadata and typed A0. Identity is the
// exact target name; its kind is fixed to owner-dm. Key is a full public P-256 ID.
// IssuedAt/ExpiresAt are original UTC-second strings. Confirmed is signed data,
// not presence evidence. No field selects a class, policy or verifier handler.
type MappingInput struct {
	Operation string
	Identity  string
	Owner     string
	Epoch     string
	Audience  string
	ActionID  string
	Nonce     string
	IssuedAt  string
	ExpiresAt string
	Confirmed bool
	Key       string
	Arguments ArgumentInput
}

// Mapping contains owned, independent byte buffers and digest strings. Arguments
// is complete canonical A; Body is canonical operator-act/1 body bytes, without
// arguments as a member. SigningPreimage is the existing full raw domain-tagged
// approver preimage, not Render or a digest-only signing input.
// Ordinary returned data is mutable, not durable evidence, an immutable signing
// plan, authorization or an admitted act. Copying this struct shares its slices.
type Mapping struct {
	Render          []byte
	Arguments       []byte
	ArgumentsDigest string
	Body            []byte
	ContentID       string
	SigningPreimage []byte
}

// MappingError contains only a local code, never received values or a wire
// verifier verdict. Codes are mapping_operation_unsupported, mapping_invalid
// (typed metadata/A0 grammar), and mapping_too_large (complete A or Render cap).
type MappingError struct{ Code string }

func (e *MappingError) Error() string { return e.Code }

// Map derives the noncircular owner-acts/1 Render, text hash, canonical arguments,
// arguments digest, complete operator body, content ID and raw signing preimage.
// It validates all typed input before emitting anything. Failure returns Mapping{}.
// It uses no clock, RNG, state, secret or I/O and never signs or authorizes.
// Current rights, actual delivered text/audience equality and full operator
// verification remain separate in verifier.VerifyOwnerAct.
func Map(in MappingInput) (Mapping, error) {
	fail := func(code string) (Mapping, error) { return Mapping{}, &MappingError{Code: code} }
	class := "widening"
	switch in.Operation {
	case "owner-dm.bind", "owner-dm.mirror-enable":
	case "owner-dm.unbind":
		class = "narrowing"
	default:
		return fail("mapping_operation_unsupported")
	}
	// Bound every caller-controlled string before decoding or serialization.
	a := in.Arguments
	for _, s := range []struct {
		value string
		max   int
	}{
		{in.Identity, 63}, {in.Owner, 255}, {in.Epoch, 38}, {in.Audience, 43},
		{in.ActionID, 22}, {in.Nonce, 22}, {in.IssuedAt, 20}, {in.ExpiresAt, 20}, {in.Key, 49},
		{a.SourceRoom, 255}, {a.SourceRecipient, 255}, {a.OwnerRecipient, 255}, {a.BoundRoom, 255}, {a.AudienceDigest, 71},
	} {
		if len(s.value) > s.max {
			return fail("mapping_invalid")
		}
	}
	if !identityName(in.Identity) || len(in.Owner) == 0 || !utf8.ValidString(in.Owner) ||
		!namespace(in.Epoch, "epoch:") || !namespace(in.Audience, "owner-acts:") {
		return fail("mapping_invalid")
	}
	alg, _, err := record.KeyBytes(in.Key)
	if err != nil || alg != "p256" || record.ValidateKey(in.Key) != nil {
		return fail("mapping_invalid")
	}
	if _, err := record.DecodeBase64(in.ActionID, 16); err != nil {
		return fail("mapping_invalid")
	}
	if _, err := record.DecodeBase64(in.Nonce, 16); err != nil {
		return fail("mapping_invalid")
	}
	start, ok := mappingTime(in.IssuedAt)
	end, endOK := mappingTime(in.ExpiresAt)
	if !ok || !endOK || end <= start || end-start > 120 {
		return fail("mapping_invalid")
	}
	a0, ok := argumentObject(in.Operation, a)
	if !ok {
		return fail("mapping_invalid")
	}
	target := map[string]any{"kind": "owner-dm", "id": in.Identity}
	d, err := record.Canonical(map[string]any{
		"profile": "owner-acts/1", "class": class, "operation": in.Operation,
		"target": target, "owner": in.Owner, "epoch": in.Epoch, "aud": in.Audience,
		"action_id": in.ActionID, "nonce": in.Nonce, "iat": in.IssuedAt, "exp": in.ExpiresAt,
		"confirmed": in.Confirmed, "key": in.Key, "arguments": a0,
	})
	if err != nil {
		return fail("mapping_invalid")
	}
	render := append([]byte("owner-acts/1\n"), d...)
	if len(render) > 4096 {
		return fail("mapping_too_large")
	}
	complete := make(map[string]any, len(a0)+1)
	for name, value := range a0 {
		complete[name] = value
	}
	complete["text_sha256"] = strings.TrimPrefix(record.Digest(render), "sha256:")
	arguments, err := record.Canonical(complete)
	if err != nil {
		return fail("mapping_invalid")
	}
	if len(arguments) > 2048 {
		return fail("mapping_too_large")
	}
	// Only the actually derived hash enters the existing parser. No dummy hash.
	if _, err := Parse(in.Operation, arguments); err != nil {
		return fail("mapping_invalid")
	}
	digest := record.Digest(arguments)
	body := map[string]any{
		"type": "operator-act/1", "aud": in.Audience, "nonce": in.Nonce,
		"iat": in.IssuedAt, "exp": in.ExpiresAt, "operation": in.Operation,
		"target": target, "owner": in.Owner, "epoch": in.Epoch,
		"action_id": in.ActionID, "arguments_digest": digest, "confirmed": in.Confirmed,
	}
	bodyBytes, err := record.Canonical(body)
	if err != nil {
		return fail("mapping_invalid")
	}
	id, err := record.ContentID("operator-act/1", body)
	if err != nil {
		return fail("mapping_invalid")
	}
	preimage, err := record.SigningPreimage("operator-act/1", in.Key, "approver", body)
	if err != nil {
		return fail("mapping_invalid")
	}
	return Mapping{Render: render, Arguments: arguments, ArgumentsDigest: digest, Body: bodyBytes, ContentID: id, SigningPreimage: preimage}, nil
}

func identityName(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] >= '0' && s[i] <= '9' || i > 0 && s[i] == '-') {
			return false
		}
	}
	return true
}

func namespace(s, prefix string) bool {
	if len(s) != len(prefix)+32 || !strings.HasPrefix(s, prefix) {
		return false
	}
	for _, c := range s[len(prefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func mappingTime(s string) (int64, bool) {
	if len(s) != 20 {
		return 0, false
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	return t.Unix(), err == nil && t.Year() >= 1970 && t.Year() <= 9999 && t.Format("2006-01-02T15:04:05Z") == s
}

func argumentObject(operation string, a ArgumentInput) (map[string]any, bool) {
	_, roomOK := identifier(a.SourceRoom)
	_, sourceOK := identifier(a.SourceRecipient)
	_, ownerOK := identifier(a.OwnerRecipient)
	_, authorityOK := revision(a.AuthorityRevision, 1)
	_, generationOK := revision(a.IdentityGeneration, 1)
	_, bindingOK := revision(a.BindingRevision, 0)
	if !roomOK || !sourceOK || !ownerOK || !authorityOK || !generationOK || !bindingOK {
		return nil, false
	}
	if operation != "owner-dm.mirror-enable" && (a.AudienceRevision != 0 || a.AudienceDigest != "") {
		return nil, false
	}
	if operation == "owner-dm.bind" && a.BoundRoom != "" || a.Mirror != (operation == "owner-dm.mirror-enable") {
		return nil, false
	}
	if operation != "owner-dm.bind" {
		if _, ok := identifier(a.BoundRoom); !ok {
			return nil, false
		}
	}
	if operation == "owner-dm.mirror-enable" {
		if _, ok := revision(a.AudienceRevision, 1); !ok || !record.IsContentID(a.AudienceDigest) {
			return nil, false
		}
	}
	m := map[string]any{
		"profile": "owner-acts/1", "source_room": a.SourceRoom, "source_recipient": a.SourceRecipient,
		"authority_revision": a.AuthorityRevision, "identity_generation": a.IdentityGeneration,
		"binding_revision": a.BindingRevision, "owner_recipient": a.OwnerRecipient,
	}
	if operation != "owner-dm.bind" {
		m["bound_room"] = a.BoundRoom
	}
	if operation != "owner-dm.unbind" {
		m["mirror"] = a.Mirror
	}
	if operation == "owner-dm.mirror-enable" {
		m["audience_revision"], m["audience_digest"] = a.AudienceRevision, a.AudienceDigest
	}
	return m, true
}
