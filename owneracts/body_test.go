package owneracts_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
	"github.com/relux-works/swarma-envelope/record"
)

// This literal fixture and expected scalars come from the closed body contract,
// independently of Map, signatures, protected facts and the parser under test.
const bodyLiteral = `{"action_id":"AAECAwQFBgcICQoLDA0ODw","arguments_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","aud":"owner-acts:0123456789abcdef0123456789abcdef","confirmed":false,"epoch":"epoch:fedcba9876543210fedcba9876543210","exp":"2026-01-02T03:06:05Z","iat":"2026-01-02T03:04:05Z","nonce":"EBESExQVFhcYGRobHB0eHw","operation":"owner-dm.bind","owner":"owner","target":{"id":"identity","kind":"owner-dm"},"type":"operator-act/1"}`

func bodyExpected() owneracts.Body {
	return owneracts.Body{
		Type: "operator-act/1", Audience: "owner-acts:0123456789abcdef0123456789abcdef",
		Nonce: "EBESExQVFhcYGRobHB0eHw", IssuedAt: "2026-01-02T03:04:05Z", ExpiresAt: "2026-01-02T03:06:05Z",
		Operation: "owner-dm.bind", TargetKind: "owner-dm", Identity: "identity", Owner: "owner",
		Epoch: "epoch:fedcba9876543210fedcba9876543210", ActionID: "AAECAwQFBgcICQoLDA0ODw",
		ArgumentsDigest: "sha256:" + strings.Repeat("0", 64), Confirmed: false,
	}
}

func bodyAccept(t *testing.T, raw []byte, want owneracts.Body) owneracts.Body {
	t.Helper()
	before := bytes.Clone(raw)
	got, err := owneracts.ParseBody(raw)
	if err != nil || got != want {
		t.Fatalf("exact body: got %+v, error %v; want %+v", got, err, want)
	}
	if !bytes.Equal(before, raw) {
		t.Fatal("input changed on success")
	}
	return got
}

func bodyReject(t *testing.T, raw []byte, code string) {
	t.Helper()
	before := bytes.Clone(raw)
	got, err := owneracts.ParseBody(raw)
	var local *owneracts.BodyError
	if !errors.As(err, &local) || local.Code != code || err.Error() != code || got != (owneracts.Body{}) {
		t.Fatalf("want local %s and zero body; got %+v, %v", code, got, err)
	}
	if !bytes.Equal(before, raw) {
		t.Fatal("input changed on refusal")
	}
	// Every refusal retains an exact positive neighbor; reject-all cannot pass.
	bodyAccept(t, []byte(bodyLiteral), bodyExpected())
}

func bodyReplace(old, next string) []byte {
	if !strings.Contains(bodyLiteral, old) {
		panic("bad test replacement")
	}
	return []byte(strings.Replace(bodyLiteral, old, next, 1))
}

func bodyOwner(token string) []byte { return bodyReplace(`"owner":"owner"`, `"owner":`+token) }

// Canonical constructs additional fixtures only. Expectations remain independently
// specified scalar values; agreement with the codec/mapper is not a schema oracle.
func bodyObject(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"type": "operator-act/1", "aud": "owner-acts:0123456789abcdef0123456789abcdef",
		"nonce": "EBESExQVFhcYGRobHB0eHw", "iat": "2026-01-02T03:04:05Z", "exp": "2026-01-02T03:06:05Z",
		"operation": "owner-dm.bind", "target": map[string]any{"id": "identity", "kind": "owner-dm"},
		"owner": "owner", "epoch": "epoch:fedcba9876543210fedcba9876543210",
		"action_id": "AAECAwQFBgcICQoLDA0ODw", "arguments_digest": "sha256:" + strings.Repeat("0", 64), "confirmed": false,
	}
}

func bodyCanonical(t *testing.T, v any) []byte {
	t.Helper()
	b, err := record.Canonical(v)
	if err != nil {
		t.Fatal("test fixture", err)
	}
	return b
}

// All three operations and both booleans preserve every field. Digest syntax and
// confirmed=true are admitted data, not argument validation or human presence.
func TestBodyExactControls(t *testing.T) {
	for _, op := range []string{"owner-dm.bind", "owner-dm.unbind", "owner-dm.mirror-enable"} {
		for _, confirmed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", op, confirmed), func(t *testing.T) {
				want := bodyExpected()
				want.Operation, want.Confirmed = op, confirmed
				raw := strings.Replace(bodyLiteral, "owner-dm.bind", op, 1)
				if confirmed {
					raw = strings.Replace(raw, `"confirmed":false`, `"confirmed":true`, 1)
				}
				bodyAccept(t, []byte(raw), want)
			})
		}
	}
}

// BOM, non-UTF-8 bytes, overlong sequences, surrogate encodings and UTF-16
// refuse; a canonical non-ASCII owner is preserved byte for byte.
func TestBodyBOMAndEncodings(t *testing.T) {
	for _, prefix := range [][]byte{{0xef, 0xbb, 0xbf}, {0xff, 0xfe}, {0xfe, 0xff}} {
		bodyReject(t, append(bytes.Clone(prefix), []byte(bodyLiteral)...), "body_invalid")
	}
	for _, bad := range []string{"\xff", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82"} {
		bodyReject(t, bodyOwner(`"`+bad+`"`), "body_invalid")
	}
	bodyReject(t, []byte("\x00{\x00}"), "body_invalid")
	want := bodyExpected()
	want.Owner = "é"
	bodyAccept(t, bodyOwner(`"é"`), want)
}

// Legal JSON framing whitespace is noncanonical; NEL/LS/PS are invalid framing.
// Those same exact line characters are legal owner data with canonical escapes.
func TestBodyLineEndings(t *testing.T) {
	for _, s := range []string{"\n", "\r", "\r\n", "\n\r", "\t", " "} {
		bodyReject(t, append([]byte(s), []byte(bodyLiteral)...), "body_noncanonical")
		bodyReject(t, append([]byte(bodyLiteral), []byte(s)...), "body_noncanonical")
		bodyReject(t, bodyReplace(`,"aud"`, ","+s+`"aud"`), "body_noncanonical")
	}
	for _, s := range []string{"\u0085", "\u2028", "\u2029"} {
		bodyReject(t, append([]byte(s), []byte(bodyLiteral)...), "body_invalid")
		bodyReject(t, bodyReplace(`,"aud"`, ","+s+`"aud"`), "body_invalid")
		want := bodyExpected()
		want.Owner = "owner" + s
		bodyAccept(t, bodyOwner(`"owner`+s+`"`), want)
	}
	for _, c := range []struct{ value, token string }{{"\r", `\r`}, {"\n", `\n`}, {"\r\n", `\r\n`}} {
		want := bodyExpected()
		want.Owner += c.value
		bodyAccept(t, bodyOwner(`"owner`+c.token+`"`), want)
	}
}

// Every raw JSON C0 control refuses, while its exact canonical escape is valid
// owner text. DEL is legal owner data under the existing UTF-8 owner contract.
func TestBodyControlCharacters(t *testing.T) {
	for c := byte(0); c < 32; c++ {
		t.Run(fmt.Sprint(c), func(t *testing.T) {
			bodyReject(t, bodyOwner("\"owner"+string(c)+"\""), "body_invalid")
			token := fmt.Sprintf(`\u%04x`, c)
			switch c {
			case '\b':
				token = `\b`
			case '\t':
				token = `\t`
			case '\n':
				token = `\n`
			case '\f':
				token = `\f`
			case '\r':
				token = `\r`
			}
			want := bodyExpected()
			want.Owner += string(c)
			bodyAccept(t, bodyOwner(`"owner`+token+`"`), want)
		})
	}
	want := bodyExpected()
	want.Owner = "\x7f"
	bodyAccept(t, bodyOwner("\"\x7f\""), want)
}

// Unicode blanks/invisibles cannot frame JSON but remain literal owner bytes;
// composed and decomposed forms are distinct, with no normalization or trim.
func TestBodyUnicodeWhitespace(t *testing.T) {
	for _, s := range []string{"\u00a0", "\u1680", "\u2003", "\u200b", "\u202f", "\u205f", "\u3000", "\ufeff", "\u202e"} {
		bodyReject(t, append([]byte(s), []byte(bodyLiteral)...), "body_invalid")
		want := bodyExpected()
		want.Owner = s + "owner" + s
		bodyAccept(t, bodyOwner(`"`+want.Owner+`"`), want)
	}
	for _, s := range []string{" owner ", "é", "e\u0301"} {
		want := bodyExpected()
		want.Owner = s
		bodyAccept(t, bodyOwner(`"`+s+`"`), want)
	}
}

// YAML/JavaScript comments are not CCJ. Quoted comment-looking owner strings
// remain literal data, including punctuation that cannot select a grammar.
func TestBodyComments(t *testing.T) {
	for _, s := range []string{"# comment\n", "// comment\n", "/* comment */"} {
		bodyReject(t, append([]byte(s), []byte(bodyLiteral)...), "body_invalid")
		bodyReject(t, append([]byte(bodyLiteral), []byte(s)...), "body_invalid")
	}
	bodyReject(t, bodyReplace(`,"aud"`, `,/* comment */"aud"`), "body_invalid")
	for _, s := range []string{"# comment", "// comment", "/* comment */"} {
		want := bodyExpected()
		want.Owner = s
		bodyAccept(t, bodyOwner(`"`+s+`"`), want)
	}
}

// Alternate JSON spellings are refused locally even when record.Parse admits
// them. Quotes, backslashes and slash survive canonical spelling exactly.
func TestBodyQuotesAndEscapes(t *testing.T) {
	for _, token := range []string{`"\u006fwner"`, `"own\/er"`, `"\u00e9"`, `"\u000a"`, `"\uD83D\uDE00"`} {
		bodyReject(t, bodyOwner(token), "body_noncanonical")
	}
	for _, token := range []string{`'owner'`, `"\x41"`, `"\v"`, `"\uD800"`, `"\uDC00"`, `"\u000"`, `"unclosed`, `owner`} {
		bodyReject(t, bodyOwner(token), "body_invalid")
	}
	bodyReject(t, bodyReplace(`"owner":`, `"\u006fwner":`), "body_noncanonical")
	bodyReject(t, []byte(`{"type":"operator-act/1",`+strings.TrimPrefix(strings.TrimSuffix(bodyLiteral, `,"type":"operator-act/1"}`), "{")+`}`), "body_noncanonical")
	for _, c := range []struct{ token, value string }{{`"own/er"`, "own/er"}, {`"\"\\"`, "\"\\"}, {`"😀"`, "😀"}} {
		want := bodyExpected()
		want.Owner = c.value
		bodyAccept(t, bodyOwner(c.token), want)
	}
}

// YAML block scalars (including indicators and header comments) are structural
// counterexamples; their nearby quoted spellings are exact ordinary owner text.
func TestBodyBlockScalars(t *testing.T) {
	for _, s := range []string{"|\n  owner", ">\n  owner", "|-\n  owner", "|2 # header\n  owner", ">+\n  owner"} {
		bodyReject(t, bodyOwner(s), "body_invalid")
	}
	for _, s := range []string{"|", ">", "|-", "|2 # header", ">+"} {
		want := bodyExpected()
		want.Owner = s
		bodyAccept(t, bodyOwner(`"`+s+`"`), want)
	}
}

// Numeric/null/object/array-looking quoted owner values are never coerced.
// Non-string owners and illegal CCJ number spellings refuse with zero output.
func TestBodyNumericLookingScalars(t *testing.T) {
	for _, s := range []string{"null", "true", "false", "{}", "[]", "42", "0x2A", "0o52", "1e2", "-0", strings.Repeat("9", 255)} {
		want := bodyExpected()
		want.Owner = s
		bodyAccept(t, bodyOwner(`"`+s+`"`), want)
	}
	for _, token := range []string{"null", "true", "false", "{}", "[]", "42", "0x2A", "0o52", "1e2", "-0", "1.0", "9007199254740992", strings.Repeat("9", 5000)} {
		bodyReject(t, bodyOwner(token), "body_invalid")
	}
}

// Duplicates at both depths, including escaped aliases and conflicting values,
// are refused before any first/last-wins selection or canonical comparison.
func TestBodyDuplicateKeys(t *testing.T) {
	for _, raw := range [][]byte{
		bodyReplace(`"owner":"owner"`, `"owner":"owner","owner":"owner"`),
		bodyReplace(`"owner":"owner"`, `"owner":"foreign","owner":"owner"`),
		bodyReplace(`"owner":"owner"`, `"owner":"owner","\u006fwner":"foreign"`),
		bodyReplace(`"id":"identity"`, `"id":"identity","id":"foreign"`),
		bodyReplace(`"kind":"owner-dm"`, `"kind":"owner-dm","\u006bind":"account"`),
	} {
		bodyReject(t, raw, "body_invalid")
	}
}

// Exact schema rejects every missing/extra member and every wrong field type.
// Signature/envelope/arguments/preimage members cannot turn this into a wrapper.
func TestBodyClosedMembers(t *testing.T) {
	for name := range bodyObject(t) {
		t.Run("missing/"+name, func(t *testing.T) {
			m := bodyObject(t)
			delete(m, name)
			bodyReject(t, bodyCanonical(t, m), "body_invalid")
		})
		for _, value := range []any{nil, int64(1), false, "false", []any{}, map[string]any{}} {
			if name == "confirmed" && value == false {
				continue
			}
			if name != "target" && name != "confirmed" {
				if _, ok := value.(string); ok {
					continue
				}
			}
			m := bodyObject(t)
			m[name] = value
			bodyReject(t, bodyCanonical(t, m), "body_invalid")
		}
	}
	for _, name := range []string{"extra", "key", "sig", "signatures", "arguments", "body", "version", "id", "profile", "class", "preimage", "current", "handler"} {
		m := bodyObject(t)
		m[name] = "untrusted"
		bodyReject(t, bodyCanonical(t, m), "body_invalid")
	}
	for _, name := range []string{"kind", "id"} {
		for _, value := range []any{nil, int64(1), false, []any{}, map[string]any{}} {
			m := bodyObject(t)
			m["target"].(map[string]any)[name] = value
			bodyReject(t, bodyCanonical(t, m), "body_invalid")
		}
		m := bodyObject(t)
		delete(m["target"].(map[string]any), name)
		bodyReject(t, bodyCanonical(t, m), "body_invalid")
	}
	m := bodyObject(t)
	m["target"].(map[string]any)["generation"] = int64(1)
	bodyReject(t, bodyCanonical(t, m), "body_invalid")
	for _, raw := range []string{"null", "true", "[]", "1", `"body"`, bodyLiteral + "{}", `{"body":` + bodyLiteral + `,"id":"untrusted","signatures":[],"version":"swarm-envelope/2"}`} {
		bodyReject(t, []byte(raw), "body_invalid")
	}
}

// Size is decided before parsing even for otherwise malformed/unsupported input.
// Stricter closed fields make a valid 8192-byte body unreachable: maximum owner
// escape expansion is 1530 bytes, identity63, and all other fields fixed/bounded.
func TestBodySizeLimits(t *testing.T) {
	bodyReject(t, nil, "body_invalid")
	bodyReject(t, []byte{}, "body_invalid")
	bodyReject(t, []byte("{"), "body_invalid")
	for _, n := range []int{8191, 8192, 8193} {
		code := "body_noncanonical"
		if n > 8192 {
			code = "body_too_large"
		}
		raw := append([]byte(bodyLiteral), bytes.Repeat([]byte(" "), n-len(bodyLiteral))...)
		bodyReject(t, raw, code)
	}
	bodyReject(t, bytes.Repeat([]byte{0xff}, 8193), "body_too_large")
	for _, n := range []int{254, 255, 256} {
		want := bodyExpected()
		want.Owner = strings.Repeat("x", n)
		if n <= 255 {
			bodyAccept(t, bodyOwner(`"`+want.Owner+`"`), want)
		} else {
			bodyReject(t, bodyOwner(`"`+want.Owner+`"`), "body_invalid")
		}
	}
	for _, s := range []string{strings.Repeat("é", 127) + "x", strings.Repeat("é", 128)} {
		want := bodyExpected()
		want.Owner = s
		if len(s) <= 255 {
			bodyAccept(t, bodyOwner(`"`+s+`"`), want)
		} else {
			bodyReject(t, bodyOwner(`"`+s+`"`), "body_invalid")
		}
	}
	for _, n := range []int{8192, 8193} {
		bodyReject(t, bodyOwner(`"`+strings.Repeat("x", n)+`"`), "body_too_large")
	}
	want := bodyExpected()
	want.Owner, want.Identity, want.Operation = strings.Repeat("\x00", 255), strings.Repeat("a", 63), "owner-dm.mirror-enable"
	m := bodyObject(t)
	m["owner"], m["operation"], m["target"].(map[string]any)["id"] = want.Owner, want.Operation, want.Identity
	raw := bodyCanonical(t, m)
	// 454-byte literal minus old owner5/id8/op13 plus 1530/63/22.
	maximum := len(bodyLiteral) - 5 - 8 - 13 + 1530 + 63 + 22
	if len(bodyLiteral) != 454 || maximum != 2043 {
		t.Fatal("maximum body fixture derivation", maximum)
	}
	if len(raw) != maximum {
		t.Fatal("maximum serialized body derivation", len(raw))
	}
	bodyAccept(t, raw, want)
	// Arrays/deeper containers are invalid closed fields even within codec limits.
	// Beyond codec limits the same input is already refused by record preflight.
	for _, n := range []int{64, 65} {
		token := "[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]"
		bodyReject(t, bodyOwner(token), "body_invalid")
		_, err := record.Parse([]byte(token), 8192, 16)
		if (err == nil) != (n == 64) {
			t.Fatalf("array preflight neighbor %d: %v", n, err)
		}
	}
	for _, n := range []int{15, 16, 17} {
		token := strings.Repeat("[", n) + "0" + strings.Repeat("]", n)
		bodyReject(t, bodyOwner(token), "body_invalid")
		_, err := record.Parse([]byte(token), 8192, 16)
		if (err == nil) != (n <= 16) {
			t.Fatalf("depth preflight neighbor %d: %v", n, err)
		}
	}
}
