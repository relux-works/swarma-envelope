package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/swarma-registrar/ccj"
)

// Error is an ordered specification refusal. It contains no received bytes.
type Error struct{ Code string }

func (e *Error) Error() string  { return e.Code }
func refusal(code string) error { return &Error{Code: code} }

// DecodeBase64 accepts only the canonical unpadded URL alphabet. A negative
// length permits any decoded length, within the caller's prior byte bound.
func DecodeBase64(s string, length int) ([]byte, error) {
	if length >= 0 && len(s) != base64.RawURLEncoding.EncodedLen(length) {
		return nil, refusal("envelope_malformed")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s || (length >= 0 && len(b) != length) {
		return nil, refusal("envelope_malformed")
	}
	return b, nil
}

// Digest returns the specification's lowercase content-id representation.
func Digest(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

// Tag returns the closed tag for a platform type, or an empty string.
func Tag(kind string) string {
	switch kind {
	case "message/1":
		return "swarma-msg/2"
	case "grant/1":
		return "swarma-waggle grant/1"
	case "operator-act/1":
		return "swarma-waggle operator-act/1"
	case "attestation/1":
		return "swarma-attestation attestation/1"
	case "revocation/1":
		return "swarma-attestation revocation/1"
	case "journal-entry/1":
		return "swarma-registry journal-entry/1"
	case "checkpoint/1", "checkpoint/2":
		return "swarma-registry " + kind
	case "freshness/1", "freshness/2":
		return "swarma-registry " + kind
	}
	return ""
}

// Registered reports exact membership in the closed platform domain registry.
func Registered(tag string) bool {
	switch tag {
	case "swarma-registry checkpoint/2", "swarma-registry freshness/2", "swarma-registry freshness/1", "swarma-registry journal-entry/1", "swarma-registry checkpoint/1", "swarma-msg/2", "swarma-waggle grant/1", "swarma-waggle operator-act/1", "swarma-attestation attestation/1", "swarma-attestation revocation/1", "swarma-registrar registration/1", "swarma-registrar enrollment/1", "swarma-credential-broker grant/1", "swarma-credential-broker revocation/1":
		return true
	}
	return false
}

// Parse applies size/depth/array/string bounds and the pinned registrar's
// duplicate-free CCJ-1 reader. It accepts noncanonical envelope whitespace.
// Size is checked before parsing or copying the input. Numbers are int64.
func Parse(raw []byte, maxBytes, maxDepth int) (any, error) {
	if maxBytes < 0 || len(raw) > maxBytes {
		return nil, refusal("envelope_too_large")
	}
	if maxDepth < 1 || maxDepth > 16 {
		return nil, refusal("envelope_malformed")
	}
	if !preflight(raw, maxDepth) {
		return nil, refusal("envelope_malformed")
	}
	v, e := ccj.Parse(raw, ccj.RegistrationMalformed)
	if e != nil {
		return nil, refusal("envelope_malformed")
	}
	if !bounded(v, 0, maxDepth) {
		return nil, refusal("envelope_malformed")
	}
	return v, nil
}

// preflight bounds containers before the registrar allocates them. Lexical
// validity and duplicate names are decided exclusively by registrar CCJ-1.
func preflight(raw []byte, limit int) bool {
	type frame struct {
		array  bool
		count  int
		expect bool
	}
	stack := make([]frame, 0, 16)
	quoted, escaped := false, false
	for _, c := range raw {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if len(stack) > 0 {
			f := &stack[len(stack)-1]
			if f.array && f.expect && c != ']' {
				f.count++
				f.expect = false
				if f.count > 64 {
					return false
				}
			}
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			stack = append(stack, frame{array: c == '[', expect: true})
			if len(stack) > limit {
				return false
			}
		case '}', ']':
			if len(stack) == 0 {
				return false
			}
			stack = stack[:len(stack)-1]
		case ',':
			if len(stack) > 0 {
				stack[len(stack)-1].expect = true
			}
		}
	}
	return len(stack) == 0 && !quoted
}
func bounded(v any, d, limit int) bool {
	switch x := v.(type) {
	case map[string]any:
		if d >= limit {
			return false
		}
		for k, v := range x {
			if !bounded(k, d+1, limit) || !bounded(v, d+1, limit) {
				return false
			}
		}
	case []any:
		if d >= limit || len(x) > 64 {
			return false
		}
		for _, v := range x {
			if !bounded(v, d+1, limit) {
				return false
			}
		}
	case string:
		return utf8.ValidString(x) && len(x) <= 8192
	}
	return true
}

// Canonical uses only the pinned registrar CCJ-1 implementation.
func Canonical(v any) ([]byte, error) {
	b, e := ccj.Marshal(v, ccj.RegistrationMalformed)
	if e != nil {
		return nil, refusal("envelope_malformed")
	}
	return b, nil
}

// ContentID binds the complete body to the caller-selected platform type.
func ContentID(kind string, body map[string]any) (string, error) {
	tag := Tag(kind)
	if tag == "" {
		return "", refusal("envelope_type_mismatch")
	}
	b, e := Canonical(body)
	if e != nil {
		return "", e
	}
	return Digest(append([]byte(tag+"\n"), b...)), nil
}

// SigningPreimage reconstructs the complete domain/LF/CCJ-1 signed record.
func SigningPreimage(kind, key, role string, body map[string]any) ([]byte, error) {
	tag := Tag(kind)
	if tag == "" {
		return nil, refusal("envelope_type_mismatch")
	}
	b, e := Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "key": key, "role": role})
	if e != nil {
		return nil, e
	}
	return append([]byte(tag+"\n"), b...), nil
}
func split(raw []byte, code string) (string, []byte, error) {
	i := bytes.IndexByte(raw, '\n')
	if i < 1 || i > 96 {
		return "", nil, refusal(code)
	}
	for _, c := range raw[:i] {
		if c < 32 || c > 126 {
			return "", nil, refusal(code)
		}
	}
	return string(raw[:i]), raw[i+1:], nil
}

// IdentityPolicy is protected provider configuration, not received body data.
// Invalid explicitly represents unavailable/malformed provider configuration.
// MultiAgent always enforces all three paths, regardless of Check.
type IdentityPolicy struct {
	Check               bool
	MultiAgent          bool
	Invalid             bool
	CallerKey           string
	CallerAttestationID string
}

// SignerAdmission contains a digest for audit only, never effect authority.
type SignerAdmission struct {
	Tag            string
	PreimageSHA256 string
}

// AdmitSigner checks length, exact domain, canonical codec/depth and then the
// optional/mandatory three-path caller identity narrowing. It releases no signature.
func AdmitSigner(raw []byte, p IdentityPolicy) (SignerAdmission, error) {
	fail := func(c string) (SignerAdmission, error) { return SignerAdmission{}, refusal(c) }
	if len(raw) > 24576 {
		return fail("signer_preimage_too_large")
	}
	tag, payload, e := split(raw, "signer_tag_malformed")
	if e != nil {
		return SignerAdmission{}, e
	}
	if tag != Tag("message/1") {
		return fail("signer_domain_refused")
	}
	v, e := Parse(payload, 24576, 12)
	if e != nil {
		return fail("signer_payload_invalid")
	}
	b, e := Canonical(v)
	if e != nil || !bytes.Equal(b, payload) {
		return fail("signer_payload_invalid")
	}
	if p.Invalid {
		return fail("signer_identity_unavailable")
	}
	if p.Check || p.MultiAgent {
		alg, _, e := KeyBytes(p.CallerKey)
		if e != nil || alg != "ed25519" || ValidateKey(p.CallerKey) != nil || !IsContentID(p.CallerAttestationID) {
			return fail("signer_identity_unavailable")
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return fail("signer_identity_malformed")
		}
		body, ok := obj["body"].(map[string]any)
		if !ok {
			return fail("signer_identity_malformed")
		}
		key, a := obj["key"].(string)
		author, b := body["author"].(string)
		id, c := body["author_attestation"].(string)
		if !a || !b || !c {
			return fail("signer_identity_malformed")
		}
		if key != p.CallerKey || author != p.CallerKey || id != p.CallerAttestationID {
			return fail("signer_identity_mismatch")
		}
	}
	return SignerAdmission{Tag: tag, PreimageSHA256: Digest(raw)}, nil
}

// IsContentID checks the exact lowercase SHA-256 content-id alphabet.
func IsContentID(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// CheckDomain verifies exact registered-tag separation and raw signature math.
// It does not implement external domains' body schemas or authority policies.
func CheckDomain(raw []byte, expected, key string, sig []byte) error {
	if !Registered(expected) {
		return refusal("domain_unknown")
	}
	if len(raw) > 65536 {
		return refusal("envelope_too_large")
	}
	tag, payload, e := split(raw, "domain_tag_malformed")
	if e != nil {
		return e
	}
	if tag != expected {
		return refusal("domain_mismatch")
	}
	v, e := Parse(payload, 65536, 16)
	if e != nil {
		return e
	}
	b, e := Canonical(v)
	if e != nil || !bytes.Equal(b, payload) {
		return refusal("envelope_malformed")
	}
	return VerifySignature(key, sig, raw)
}
