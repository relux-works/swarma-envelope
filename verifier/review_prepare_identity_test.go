package verifier_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/verifier"
)

// This oracle decodes the documented review language and independently pins
// every heading/order/value. It never calls Map, record or the production quote
// functions. Existing public literal fixtures supply expected body/A/act text.
func reviewPrepareDecode(t *testing.T, text string) string {
	t.Helper()
	if len(text) < 2 || text[0] != '"' || text[len(text)-1] != '"' {
		t.Fatal("review: missing quote")
	}
	text = text[1 : len(text)-1]
	var b strings.Builder
	for len(text) > 0 {
		c := text[0]
		if c == '\\' {
			if len(text) >= 2 && (text[1] == '\\' || text[1] == '"') {
				b.WriteByte(text[1])
				text = text[2:]
				continue
			}
			if len(text) < 10 || text[:3] != `\u{` || text[9] != '}' {
				t.Fatal("review: malformed escape")
			}
			h := text[3:9]
			if strings.ToUpper(h) != h {
				t.Fatal("review: noncanonical hex case")
			}
			n, err := strconv.ParseUint(h, 16, 32)
			if err != nil || !utf8.ValidRune(rune(n)) || n > 0x10ffff || n >= 33 && n < 127 {
				t.Fatal("review: invalid or unnecessary scalar escape")
			}
			b.WriteRune(rune(n))
			text = text[10:]
			continue
		}
		if c <= 32 || c >= 127 || c == '"' {
			t.Fatal("review: unescaped data")
		}
		b.WriteByte(c)
		text = text[1:]
	}
	return b.String()
}
func reviewPrepareHash(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
func reviewPrepareData(t *testing.T, f prepareFixture, d verifier.OwnerActSigningData) {
	t.Helper()
	class := "widening"
	if bytes.Contains(f.body, []byte(`"operation":"owner-dm.unbind"`)) {
		class = "narrowing"
	}
	key := f.enrollment["device"].(string)
	pre := []byte("swarma-waggle operator-act/1\n" + `{"body":` + string(f.body) + `,"key":"` + key + `","role":"approver","version":"swarm-envelope/2"}`)
	id := reviewPrepareHash(append([]byte("swarma-waggle operator-act/1\n"), f.body...))
	ah := reviewPrepareHash(f.args)
	th := strings.TrimPrefix(reviewPrepareHash(f.render), "sha256:")
	if !bytes.Equal(d.Body, f.body) || !bytes.Equal(d.Arguments, f.args) || !bytes.Equal(d.Render, f.render) || !bytes.Equal(d.SigningPreimage, pre) || d.ContentID != id || d.ArgumentsDigest != ah || d.TextSHA256 != th || d.Class != class || d.Key != key || d.ProfilePin != f.enrollment["profile_pin"] || d.ReviewVersion != "owner-act-review/1" || d.PredictedEnvelopeBytes != len(f.body)+305 {
		t.Fatal("review: complete raw identity differs")
	}
	wants := [][2]string{
		{"Profile (trusted code)", "owner-acts/1"}, {"Compiled profile pin (independent installation)", f.enrollment["profile_pin"].(string)}, {"Classification (trusted code)", class},
		{"Installation (local trusted label)", f.enrollment["installation"].(string)}, {"Device key (independent enrollment)", key}, {"Owner (independent enrollment)", f.enrollment["owner"].(string)},
		{"Audience (independent enrollment)", f.enrollment["aud"].(string)}, {"Epoch (independent enrollment)", f.enrollment["epoch"].(string)}, {"Issuer (independent enrollment)", f.enrollment["issuer"].(string)},
		{"Root catalog ID (independent enrollment)", f.enrollment["root_catalog_id"].(string)}, {"Profile catalog ID (independent enrollment)", f.enrollment["profile_catalog_id"].(string)},
		{"Complete canonical body (literal JSON)", string(f.body)}, {"Complete canonical arguments (literal JSON)", string(f.args)}, {"Computed arguments digest", ah}, {"Computed text SHA256", th}, {"Computed content ID", id}, {"Complete profile act text (literal UTF-8)", string(f.render)},
	}
	lines := strings.Split(string(d.Review), "\n")
	if len(lines) != 19 || lines[0] != "owner-act-review/1" || lines[18] != "" {
		t.Fatal("review: complete layout differs")
	}
	for i, w := range wants {
		prefix := w[0] + ": "
		if !strings.HasPrefix(lines[i+1], prefix) {
			t.Fatalf("review: heading/order %d", i)
		}
		if got := reviewPrepareDecode(t, strings.TrimPrefix(lines[i+1], prefix)); got != w[1] {
			t.Fatalf("review: full field %s differs", w[0])
		}
	}
}
func reviewPrepareOK(t *testing.T, f prepareFixture) (*verifier.OwnerActSigningPlan, verifier.OwnerActSigningData) {
	t.Helper()
	b, a := bytes.Clone(f.body), bytes.Clone(f.args)
	p, err := verifier.PrepareOwnerAct(f.body, f.args, f.context(t))
	if err != nil || p == nil {
		t.Fatalf("review: positive refused %v", err)
	}
	d, ok := p.Snapshot()
	if !ok || !bytes.Equal(b, f.body) || !bytes.Equal(a, f.args) {
		t.Fatal("review: missing snapshot or input mutation")
	}
	reviewPrepareData(t, f, d)
	return p, d
}
func reviewPrepareNo(t *testing.T, f prepareFixture, c verifier.OwnerActPreparationContext, code string) {
	t.Helper()
	b, a := bytes.Clone(f.body), bytes.Clone(f.args)
	p, e := verifier.PrepareOwnerAct(f.body, f.args, c)
	var local *verifier.OwnerActPreparationError
	if p != nil || !errors.As(e, &local) || local.Code != code || e.Error() != code || !bytes.Equal(b, f.body) || !bytes.Equal(a, f.args) {
		t.Fatalf("review: want %s/nil/unchanged; got %v %v", code, p, e)
	}
	reviewPrepareOK(t, prepareFixtureFor(t, "unbind"))
}

// Formal identity families: admissible distinct Unicode/line-ending spellings
// retain complete raw identity and every review value; invalid framing of BOTH
// inputs refuses exactly. No exhaustive Unicode or concurrent-mutation claim.
func TestReviewPrepareIdentityFamilies(t *testing.T) {
	t.Run("normalisation", func(t *testing.T) {
		seen := map[string]bool{}
		for _, s := range []string{"Å", "A\u030a", "\u212b", " a ", "a\u2007b", "a\u2060b", "\ufeff", "\ufffd", "\U0010ffff", `\u{00200B}`, "\u200b"} {
			f := prepareFixtureFor(t, "mirror-enable")
			f.owner(s)
			f.enrollment["installation"] = s
			_, d := reviewPrepareOK(t, f)
			if seen[d.ContentID] {
				t.Fatal("review: normalization collapsed identity")
			}
			seen[d.ContentID] = true
		}
		for _, s := range []string{"Room%2F", "room%2f", `r\u{00000A}`, `"quoted"`, "~!#$%&'()*+,-./:;<=>?@[]^_`{|}"} {
			f := prepareFixtureFor(t, "bind")
			f.argument("source_room", "room", s)
			reviewPrepareOK(t, f)
		}
	})
	t.Run("line-endings", func(t *testing.T) {
		seen := map[string]bool{}
		for _, s := range []string{"\r", "\n", "\r\n", "\n\r", "\u0085", "\u2028", "\u2029"} {
			f := prepareFixtureFor(t, "bind")
			f.owner(s + "x" + s)
			f.enrollment["installation"] = "label" + s
			_, d := reviewPrepareOK(t, f)
			if seen[d.ContentID] {
				t.Fatal("review: EOL identity collapsed")
			}
			seen[d.ContentID] = true
			g := prepareFixtureFor(t, "bind")
			g.argument("source_room", "room", "x"+s)
			reviewPrepareNo(t, g, g.context(t), "preparation_invalid")
		}
	})
	t.Run("trailing-bytes", func(t *testing.T) {
		p, before := reviewPrepareOK(t, prepareFixtureFor(t, "unbind"))
		for _, tail := range []string{"\n\r", "\r", "\u0085", "\u2028", "\u2029", "\ufeff", "\v", "\x00", " null", "[]", "\xff"} {
			for _, which := range []string{"body", "A"} {
				f := prepareFixtureFor(t, "unbind")
				if which == "body" {
					f.body = append(f.body, tail...)
				} else {
					f.args = append(f.args, tail...)
				}
				reviewPrepareNo(t, f, f.context(t), "preparation_invalid")
				after, ok := p.Snapshot()
				if !ok || !reflect.DeepEqual(before, after) {
					t.Fatal("review: failure changed prior plan")
				}
			}
		}
		f := prepareFixtureFor(t, "unbind")
		f.owner("\x00\n\r ")
		reviewPrepareOK(t, f)
	})
}
