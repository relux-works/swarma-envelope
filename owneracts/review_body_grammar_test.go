package owneracts_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
)

// This separate literal and every expected scalar are fixed from the body
// contract, without Map, record.Canonical, keys, arguments or protected facts.
const reviewBodyLiteral = `{"action_id":"_____________________w","arguments_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","aud":"owner-acts:ffffffffffffffffffffffffffffffff","confirmed":true,"epoch":"epoch:00000000000000000000000000000000","exp":"2000-03-01T00:00:00Z","iat":"2000-02-29T23:59:59Z","nonce":"AAAAAAAAAAAAAAAAAAAAAA","operation":"owner-dm.unbind","owner":"reviewer","target":{"id":"9-review","kind":"owner-dm"},"type":"operator-act/1"}`

func reviewBodyExpected() owneracts.Body {
	return owneracts.Body{Type: "operator-act/1", Audience: "owner-acts:ffffffffffffffffffffffffffffffff", Nonce: "AAAAAAAAAAAAAAAAAAAAAA", IssuedAt: "2000-02-29T23:59:59Z", ExpiresAt: "2000-03-01T00:00:00Z", Operation: "owner-dm.unbind", TargetKind: "owner-dm", Identity: "9-review", Owner: "reviewer", Epoch: "epoch:00000000000000000000000000000000", ActionID: "_____________________w", ArgumentsDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Confirmed: true}
}

func reviewBodyOK(t *testing.T, raw []byte, want owneracts.Body) owneracts.Body {
	t.Helper()
	before := bytes.Clone(raw)
	got, err := owneracts.ParseBody(raw)
	if err != nil || got != want || !bytes.Equal(raw, before) {
		t.Fatalf("exact scalar/input mismatch: got %+v, error %v, want %+v", got, err, want)
	}
	return got
}

func reviewBodyNo(t *testing.T, raw []byte, code string) {
	t.Helper()
	before := bytes.Clone(raw)
	got, err := owneracts.ParseBody(raw)
	var local *owneracts.BodyError
	if !errors.As(err, &local) || local.Code != code || err.Error() != code || got != (owneracts.Body{}) || !bytes.Equal(raw, before) {
		t.Fatalf("want %s/zero/unchanged input, got %+v, error %v", code, got, err)
	}
	reviewBodyOK(t, []byte(reviewBodyLiteral), reviewBodyExpected())
}

// Independent fixture spelling of the specified minimal JSON string escapes.
// This constructs strings only; it is not a parser or schema oracle.
func reviewBodyQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(c)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if c < 32 {
				fmt.Fprintf(&b, `\u%04x`, c)
			} else {
				b.WriteRune(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func reviewBodyOwner(token string) []byte {
	return []byte(strings.Replace(reviewBodyLiteral, `"owner":"reviewer"`, `"owner":`+token, 1))
}

// All ten mandatory grammar families use the public entry point, exact local
// refusals and full-value positive neighbors. The examples are bounded, not an
// exhaustive Unicode/encoding or allocation proof.
func TestReviewBodyGrammarFamilies(t *testing.T) {
	t.Run("BOM-and-encodings", func(t *testing.T) {
		for _, s := range []string{"\ufeff", "\x00\x00\xfe\xff", "\xff\xfe\x00\x00"} {
			reviewBodyNo(t, []byte(reviewBodyLiteral+s), "body_invalid")
			reviewBodyNo(t, []byte("{"+s+reviewBodyLiteral[1:]), "body_invalid")
		}
		for _, s := range []string{"\x80", "\xc1\xbf", "\xf0\x80\x80\xaf", "\xf8\x88\x80\x80\x80", "\xed\xbf\xbf"} {
			reviewBodyNo(t, reviewBodyOwner(`"`+s+`"`), "body_invalid")
		}
		for _, s := range []string{"\ufeff", "\ufffd", "\U00010000", "\U0010ffff"} {
			want := reviewBodyExpected()
			want.Owner = s
			reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(s)), want)
		}
	})
	t.Run("line-endings", func(t *testing.T) {
		for _, s := range []string{"\r", "\n", "\r\n", "\n\r"} {
			for _, raw := range []string{strings.Replace(reviewBodyLiteral, `"owner":`, `"owner"`+s+`:`, 1), strings.Replace(reviewBodyLiteral, `"target":`, `"target":`+s, 1), reviewBodyLiteral[:len(reviewBodyLiteral)-1] + s + "}"} {
				reviewBodyNo(t, []byte(raw), "body_noncanonical")
			}
		}
		for _, s := range []string{"\r\n", "\n\r", "\u0085", "\u2028", "\u2029"} {
			want := reviewBodyExpected()
			want.Owner = s + "x" + s
			reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(want.Owner)), want)
		}
	})
	t.Run("control-characters", func(t *testing.T) {
		for _, c := range []byte{0, 1, 8, 9, 10, 12, 13, 27, 31} {
			// JSON framing controls differ: TAB/LF/CR are legal whitespace.
			code := "body_invalid"
			if c == 9 || c == 10 || c == 13 {
				code = "body_noncanonical"
			}
			reviewBodyNo(t, []byte(reviewBodyLiteral+string(c)), code)
		}
	})
	t.Run("Unicode-whitespace", func(t *testing.T) {
		for _, s := range []string{"\u0085", "\u2000", "\u2007", "\u2028", "\u2029", "\u2060", "\u2066", "\u2069"} {
			reviewBodyNo(t, []byte(reviewBodyLiteral+s), "body_invalid")
			want := reviewBodyExpected()
			want.Owner = s
			reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(s)), want)
		}
		for _, s := range []string{"Å", "A\u030a", "\u212b", "\u00a0\u3000"} {
			want := reviewBodyExpected()
			want.Owner = s
			reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(s)), want)
		}
	})
	t.Run("comments", func(t *testing.T) {
		for _, s := range []string{"//", "/*", "*/", "#", "<!--x-->"} {
			reviewBodyNo(t, reviewBodyOwner(s+`"reviewer"`), "body_invalid")
			want := reviewBodyExpected()
			want.Owner = s
			reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(s)), want)
		}
	})
	t.Run("quotes-and-escapes", func(t *testing.T) {
		for _, s := range []string{`"\u001B"`, `"\u0022"`, `"\u005c"`, `"\u0026\u003c\u003e"`, `"\udbff\udfff"`} {
			reviewBodyNo(t, reviewBodyOwner(s), "body_noncanonical")
		}
		for _, s := range []string{`"\uD800x"`, `"\uDC00\uD800"`, `"\U0001f600"`, `"\0"`, `"\u{41}"`} {
			reviewBodyNo(t, reviewBodyOwner(s), "body_invalid")
		}
		want := reviewBodyExpected()
		want.Owner = "\x1b\"\\&<>/"
		reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(want.Owner)), want)
	})
	t.Run("block-scalars", func(t *testing.T) {
		for _, s := range []string{"|+2 # header\r\n    x\r\n", ">-2\n    x\n", "| # eof", "---\nowner: x\n..."} {
			reviewBodyNo(t, reviewBodyOwner(s), "body_invalid")
			want := reviewBodyExpected()
			want.Owner = s
			reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(s)), want)
		}
	})
	t.Run("numeric-looking-scalars", func(t *testing.T) {
		for _, s := range []string{"00", "+1", "-9007199254740991", "9007199254740991", "9007199254740992", "NaN", "Infinity", ".inf", "1E+10", "٠١"} {
			want := reviewBodyExpected()
			want.Owner = s
			reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(s)), want)
			reviewBodyNo(t, reviewBodyOwner(s), "body_invalid")
		}
	})
	t.Run("duplicate-keys", func(t *testing.T) {
		// All12 normative top-level names, not a list read from the parser.
		for _, name := range []string{"type", "aud", "nonce", "iat", "exp", "operation", "target", "owner", "epoch", "action_id", "arguments_digest", "confirmed"} {
			alias := fmt.Sprintf(`"\u%04x%s":null,`, name[0], name[1:])
			reviewBodyNo(t, []byte("{"+alias+reviewBodyLiteral[1:]), "body_invalid")
		}
		for _, name := range []string{"id", "kind"} {
			alias := fmt.Sprintf(`"\u%04x%s":null,`, name[0], name[1:])
			reviewBodyNo(t, []byte(strings.Replace(reviewBodyLiteral, `"target":{`, `"target":{`+alias, 1)), "body_invalid")
		}
	})
	t.Run("size-limits", func(t *testing.T) {
		for _, n := range []int{8191, 8192, 8193} {
			code := "body_invalid"
			if n == 8193 {
				code = "body_too_large"
			}
			reviewBodyNo(t, bytes.Repeat([]byte{'['}, n), code)
		}
		for _, s := range []string{strings.Repeat("😀", 63) + "éx", strings.Repeat("😀", 64)} {
			want := reviewBodyExpected()
			want.Owner = s
			if len(s) == 255 {
				reviewBodyOK(t, reviewBodyOwner(reviewBodyQuote(s)), want)
			} else {
				reviewBodyNo(t, reviewBodyOwner(reviewBodyQuote(s)), "body_invalid")
			}
		}
	})
}

// Every variable-width field reaches its independent maximum together. The
// exact cap is2043 (false); true and id62 give valid2042 neighbors. The8192
// outer ceiling has no eligible positive under the stricter closed schema.
func TestReviewBodyMaximum(t *testing.T) {
	want := reviewBodyExpected()
	want.Owner, want.Identity, want.Operation, want.Confirmed = strings.Repeat("\x00", 255), strings.Repeat("z", 63), "owner-dm.mirror-enable", false
	raw := string(reviewBodyOwner(reviewBodyQuote(want.Owner)))
	raw = strings.Replace(raw, `"id":"9-review"`, `"id":"`+want.Identity+`"`, 1)
	raw = strings.Replace(raw, `"owner-dm.unbind"`, `"owner-dm.mirror-enable"`, 1)
	raw = strings.Replace(raw, `"confirmed":true`, `"confirmed":false`, 1)
	if len(raw) != 2043 {
		t.Fatal("independent maximum", len(raw))
	}
	reviewBodyOK(t, []byte(raw), want)
	want.Confirmed = true
	reviewBodyOK(t, []byte(strings.Replace(raw, `"confirmed":false`, `"confirmed":true`, 1)), want)
	want.Confirmed, want.Identity = false, strings.Repeat("z", 62)
	reviewBodyOK(t, []byte(strings.Replace(raw, strings.Repeat("z", 63), want.Identity, 1)), want)
	reviewBodyNo(t, []byte(strings.Replace(raw, strings.Repeat("z", 63), strings.Repeat("z", 64), 1)), "body_invalid")
	reviewBodyNo(t, []byte(strings.Replace(raw, `"owner":"`, `"owner":"\u0000`, 1)), "body_invalid")
}
