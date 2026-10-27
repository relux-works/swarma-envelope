package owneracts_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
)

const reviewHash = "0000000000000000000000000000000000000000000000000000000000000000"

// These independently written wire fixtures and expected values implement only
// the published closed field grammar, not current-state or digest equality.
func reviewControls() []struct {
	op, raw string
	want    owneracts.Arguments
} {
	return []struct {
		op, raw string
		want    owneracts.Arguments
	}{
		{"owner-dm.bind", `{"authority_revision":7,"binding_revision":0,"identity_generation":11,"mirror":false,"owner_recipient":"@o:x","profile":"owner-acts/1","source_recipient":"@s:x","source_room":"!r:x","text_sha256":"` + reviewHash + `"}`, owneracts.Arguments{Operation: "owner-dm.bind", Profile: "owner-acts/1", SourceRoom: "!r:x", SourceRecipient: "@s:x", TextSHA256: reviewHash, AuthorityRevision: 7, IdentityGeneration: 11, OwnerRecipient: "@o:x"}},
		{"owner-dm.unbind", `{"authority_revision":7,"binding_revision":12,"bound_room":"!b:x","identity_generation":11,"owner_recipient":"@o:x","profile":"owner-acts/1","source_recipient":"@s:x","source_room":"!r:x","text_sha256":"` + reviewHash + `"}`, owneracts.Arguments{Operation: "owner-dm.unbind", Profile: "owner-acts/1", SourceRoom: "!r:x", SourceRecipient: "@s:x", TextSHA256: reviewHash, AuthorityRevision: 7, IdentityGeneration: 11, BindingRevision: 12, OwnerRecipient: "@o:x", BoundRoom: "!b:x"}},
		{"owner-dm.mirror-enable", `{"audience_digest":"sha256:` + reviewHash + `","audience_revision":13,"authority_revision":7,"binding_revision":12,"bound_room":"!b:x","identity_generation":11,"mirror":true,"owner_recipient":"@o:x","profile":"owner-acts/1","source_recipient":"@s:x","source_room":"!r:x","text_sha256":"` + reviewHash + `"}`, owneracts.Arguments{Operation: "owner-dm.mirror-enable", Profile: "owner-acts/1", SourceRoom: "!r:x", SourceRecipient: "@s:x", TextSHA256: reviewHash, AuthorityRevision: 7, IdentityGeneration: 11, BindingRevision: 12, OwnerRecipient: "@o:x", BoundRoom: "!b:x", Mirror: true, AudienceRevision: 13, AudienceDigest: "sha256:" + reviewHash}},
	}
}

func reviewReject(t *testing.T, op, raw, code string) {
	t.Helper()
	input := []byte(raw)
	before := bytes.Clone(input)
	got, err := owneracts.Parse(op, input)
	var local *owneracts.Error
	if !errors.As(err, &local) || local.Code != code || err.Error() != code {
		t.Fatalf("intended %s; got=%+v error=%v", code, got, err)
	}
	if got != (owneracts.Arguments{}) {
		t.Fatalf("failed parse retained usable fields: %+v", got)
	}
	if !bytes.Equal(input, before) {
		t.Fatal("failed parse altered input")
	}
}

// Only printable ASCII fixture values use this helper. It escapes two bytes,
// not a second JSON parser/canonicalizer or a schema acceptance oracle.
func reviewQuoted(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Active schemas must retain every specified scalar exactly; zero hashes are
// valid grammar even though this test supplies no text, roster or protected state.
func TestReviewArgumentsExactControls(t *testing.T) {
	for _, c := range reviewControls() {
		t.Run(c.op, func(t *testing.T) {
			input := []byte(c.raw)
			got, err := owneracts.Parse(c.op, input)
			if err != nil || got != c.want || string(input) != c.raw {
				t.Fatalf("exact control got=%+v error=%v want=%+v", got, err, c.want)
			}
		})
	}
}

// The real entry point rejects malformed encodings and noncanonical spelling
// with distinct local codes. This corpus covers every supplied grammar family;
// YAML is tested only for refusal, never as a supported input language.
func TestReviewArgumentsGrammarFamilies(t *testing.T) {
	for _, c := range reviewControls() {
		t.Run(c.op, func(t *testing.T) {
			cases := []struct{ name, raw, code string }{
				{"encoding/utf8-bom", "\xef\xbb\xbf" + c.raw, "arguments_invalid"},
				{"encoding/utf16-be", "\xfe\xff\x00{\x00}", "arguments_invalid"},
				{"encoding/utf16-le", "\xff\xfe{\x00}\x00", "arguments_invalid"},
				{"encoding/utf32-le", "\xff\xfe\x00\x00{\x00\x00\x00", "arguments_invalid"},
				{"encoding/overlong", strings.Replace(c.raw, "!r:x", "\xc0\xaf", 1), "arguments_invalid"},
				{"encoding/surrogate-bytes", strings.Replace(c.raw, "!r:x", "\xed\xa0\x80", 1), "arguments_invalid"},
				{"encoding/truncated", strings.Replace(c.raw, "!r:x", "\xe2\x82", 1), "arguments_invalid"},
				{"line-endings/lone-cr", c.raw + "\r", "arguments_noncanonical"},
				{"line-endings/crlf", c.raw + "\r\n", "arguments_noncanonical"},
				{"line-endings/mixed", "\n\r" + strings.Replace(c.raw, ",", ",\r\n\t", 1) + "\r", "arguments_noncanonical"},
				{"control/raw-null", strings.Replace(c.raw, "!r:x", "a\x00b", 1), "arguments_invalid"},
				{"control/raw-del", strings.Replace(c.raw, "!r:x", "a\x7fb", 1), "arguments_invalid"},
				{"control/escaped-tab", strings.Replace(c.raw, "!r:x", `a\tb`, 1), "arguments_invalid"},
				{"control/escaped-del", strings.Replace(c.raw, "!r:x", `\u007f`, 1), "arguments_noncanonical"},
				{"comments/block", "/*closed*/" + c.raw, "arguments_invalid"},
				{"comments/line", c.raw + "//tail\r", "arguments_invalid"},
				{"comments/hash", c.raw + "#tail", "arguments_invalid"},
				{"quotes/single", strings.ReplaceAll(c.raw, `"`, `'`), "arguments_invalid"},
				{"escapes/printable", strings.Replace(c.raw, "!r:x", `\u0021r:x`, 1), "arguments_noncanonical"},
				{"escapes/bad-hex", strings.Replace(c.raw, "!r:x", `\u00zz`, 1), "arguments_invalid"},
				{"escapes/low-surrogate", strings.Replace(c.raw, "!r:x", `\udfff`, 1), "arguments_invalid"},
				{"escapes/paired-surrogate", strings.Replace(c.raw, "!r:x", `\ud83d\ude00`, 1), "arguments_noncanonical"},
				{"duplicates/escaped-key", `{"\u0061uthority_revision":7,` + c.raw[1:], "arguments_invalid"},
				{"duplicates/last-profile", c.raw[:len(c.raw)-1] + `,"profile":"owner-acts/0"}`, "arguments_invalid"},
				{"out-of-contract/yaml", "profile: owner-acts/1\nsource_room: >\n  !r:x\n", "arguments_invalid"},
			}
			for i, s := range []string{"\u0085", "\u00a0", "\u1680", "\u2007", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000", "\ufeff"} {
				cases = append(cases, struct{ name, raw, code string }{fmt.Sprintf("unicode-space/outside-%d", i), s + c.raw, "arguments_invalid"}, struct{ name, raw, code string }{fmt.Sprintf("unicode-space/inside-%d", i), strings.Replace(c.raw, "!r:x", s, 1), "arguments_invalid"})
			}
			for _, token := range []string{"-0", "00", "7.0", "7e0", "+7", "0x7", "null", "true", "9007199254740991", "9007199254740992", "9223372036854775808"} {
				cases = append(cases, struct{ name, raw, code string }{"numeric/" + token, strings.Replace(c.raw, `"authority_revision":7`, `"authority_revision":`+token, 1), "arguments_invalid"})
			}
			for _, x := range cases {
				t.Run(x.name, func(t *testing.T) { reviewReject(t, c.op, x.raw, x.code) })
			}
		})
	}
}

// Multiple simultaneous violations preserve selector -> byte -> bounded parse
// -> canonical -> schema precedence. Late schema failures also return zero fields.
func TestReviewArgumentsOrderingAndZero(t *testing.T) {
	c := reviewControls()[0]
	for _, op := range []string{"host.change", "launch.approve", "owner-dm.bind\r", "owner-dm.bind\u00a0"} {
		for _, raw := range []string{c.raw, strings.Repeat("\xff", 2049), " "} {
			reviewReject(t, op, raw, "arguments_operation_unsupported")
		}
	}
	reviewReject(t, c.op, strings.Repeat("\xff", 2049), "arguments_too_large")
	reviewReject(t, c.op, " "+strings.Replace(c.raw, "!r:x", "\xff", 1), "arguments_invalid")
	reviewReject(t, c.op, " "+`{"profile":"owner-acts/1",`+c.raw[1:], "arguments_invalid")
	reviewReject(t, c.op, " "+`{"a":{"b":{"c":{"d":{}}}}}`, "arguments_invalid")
	reviewReject(t, c.op, " "+strings.Replace(c.raw, `"profile":"owner-acts/1"`, `"profile":null`, 1), "arguments_noncanonical")
	reviewReject(t, c.op, strings.Replace(c.raw, `"profile":"owner-acts/1"`, `"profile":null`, 1), "arguments_invalid")
	reviewReject(t, c.op, strings.Replace(c.raw, `"mirror":false`, `"mirror":true`, 1), "arguments_invalid")
	u := reviewControls()[1]
	reviewReject(t, u.op, strings.Replace(u.raw, `"bound_room":"!b:x"`, `"bound_room":""`, 1), "arguments_invalid")
	m := reviewControls()[2]
	reviewReject(t, m.op, strings.Replace(m.raw, `"audience_revision":13`, `"audience_revision":0`, 1), "arguments_invalid")
}

func reviewLargeUnbind(values [4]string) string {
	return `{"authority_revision":9007199254740990,"binding_revision":9007199254740990,"bound_room":` + reviewQuoted(values[0]) + `,"identity_generation":9007199254740990,"owner_recipient":` + reviewQuoted(values[1]) + `,"profile":"owner-acts/1","source_recipient":` + reviewQuoted(values[2]) + `,"source_room":` + reviewQuoted(values[3]) + `,"text_sha256":"` + reviewHash + `"}`
}

// Independently assembled canonical objects straddle the raw-byte cap using
// legal quote escapes. No second parser computes the expected grammar or values.
func TestReviewArgumentsByteNeighbors(t *testing.T) {
	baseValues := [4]string{strings.Repeat("x", 255), strings.Repeat("x", 255), strings.Repeat("x", 255), strings.Repeat("x", 255)}
	base := len(reviewLargeUnbind(baseValues))
	for _, size := range []int{2047, 2048, 2049} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			extra := size - base
			if extra < 0 || extra > 1020 {
				t.Fatalf("invalid fixture expansion %d", extra)
			}
			values := baseValues
			for i := range values {
				n := min(extra, 255)
				extra -= n
				values[i] = strings.Repeat(`"`, n) + strings.Repeat("x", 255-n)
			}
			raw := reviewLargeUnbind(values)
			if len(raw) != size {
				t.Fatalf("fixture length %d, expected %d", len(raw), size)
			}
			if size > 2048 {
				reviewReject(t, "owner-dm.unbind", raw, "arguments_too_large")
				return
			}
			got, err := owneracts.Parse("owner-dm.unbind", []byte(raw))
			want := owneracts.Arguments{Operation: "owner-dm.unbind", Profile: "owner-acts/1", SourceRoom: values[3], SourceRecipient: values[2], OwnerRecipient: values[1], BoundRoom: values[0], TextSHA256: reviewHash, AuthorityRevision: 9007199254740990, IdentityGeneration: 9007199254740990, BindingRevision: 9007199254740990}
			if err != nil || got != want {
				t.Fatalf("boundary control got=%+v error=%v want=%+v", got, err, want)
			}
		})
	}
}

// Numeric/comment/structure-looking ASCII stays opaque, including quote/backslash
// parity near apparent container delimiters. Independent values survive buffer
// overwrite and subsequent parsing. This does not promise concurrent input safety.
func TestReviewArgumentsOpaqueValuesAndOwnership(t *testing.T) {
	for _, c := range reviewControls() {
		for _, value := range []string{"null", "true", "0x2A", "0o52", "-0", "9007199254740992", "1e309", "//comment", "/*comment*/", "#comment", "end>", `\"[{]}\\`, strings.Repeat("[{", 100), strings.Repeat("}", 255)} {
			raw := []byte(strings.Replace(c.raw, `"!r:x"`, reviewQuoted(value), 1))
			want := c.want
			want.SourceRoom = value
			got, err := owneracts.Parse(c.op, raw)
			if err != nil || got != want {
				t.Fatalf("opaque %q changed/refused: %+v %v", value, got, err)
			}
			for i := range raw {
				raw[i] = 0xff
			}
			if _, err := owneracts.Parse(c.op, []byte(c.raw)); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("owned values changed after buffer overwrite: %+v", got)
			}
		}
	}
}
