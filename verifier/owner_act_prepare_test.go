package verifier_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Published synthetic public basepoint and root encodings; no private key,
// enrollment, protected storage, installation or live authority is exercised.
const prepareKey = "p256:A2sX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"
const prepareOtherKey = "p256:AmsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"
const prepareIssuer = "ed25519:HBNOVZnP7h9DWY3ShGX0kQ8NsEwAUjEZP119NF_Z4yo"
const preparePin = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const prepareRootID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
const prepareProfileID = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

type prepareFixture struct {
	body, args, render, preimage           []byte
	enrollment, installed, roots, profiles map[string]any
}

func prepareRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../owneracts/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func prepareFixtureFor(t *testing.T, op string) prepareFixture {
	t.Helper()
	return prepareFixture{
		body: prepareRead(t, op+".body.json"), args: prepareRead(t, op+".arguments.json"), render: prepareRead(t, op+".render"), preimage: prepareRead(t, op+".preimage"),
		enrollment: map[string]any{"device": prepareKey, "owner": "owner", "installation": "Local laptop", "aud": "owner-acts:0123456789abcdef0123456789abcdef", "epoch": "epoch:fedcba9876543210fedcba9876543210", "issuer": prepareIssuer, "root_catalog_id": prepareRootID, "profile_catalog_id": prepareProfileID, "profile": "owner-acts/1", "profile_pin": preparePin},
		installed:  map[string]any{"profile": "owner-acts/1", "pin": preparePin},
		roots:      map[string]any{"id": prepareRootID, "roles": map[string]any{"service_root": nil, "agent_revocation_root": nil, "operator_root": prepareIssuer, "root": nil, "commit_signing_key": nil, "enrollment_publisher": nil, "service_authority": nil, "service_attestations": nil}},
		profiles:   map[string]any{"id": prepareProfileID, "profiles": map[string]any{"owner-acts/1": preparePin}},
	}
}
func (f prepareFixture) context(t *testing.T) verifier.OwnerActPreparationContext {
	t.Helper()
	return verifier.OwnerActPreparationContext{Enrollment: evidence(t, f.enrollment), InstalledProfile: evidence(t, f.installed), RootCatalog: evidence(t, f.roots), ProfileCatalog: evidence(t, f.profiles)}
}
func prepareAccept(t *testing.T, f prepareFixture) (*verifier.OwnerActSigningPlan, verifier.OwnerActSigningData) {
	t.Helper()
	beforeB, beforeA := bytes.Clone(f.body), bytes.Clone(f.args)
	p, err := verifier.PrepareOwnerAct(f.body, f.args, f.context(t))
	if err != nil || p == nil {
		t.Fatalf("valid preparation refused: %v", err)
	}
	d, ok := p.Snapshot()
	if !ok {
		t.Fatal("valid snapshot unavailable")
	}
	if !bytes.Equal(f.body, beforeB) || !bytes.Equal(f.args, beforeA) {
		t.Fatal("caller input changed")
	}
	return p, d
}
func prepareRejectContext(t *testing.T, f prepareFixture, c verifier.OwnerActPreparationContext, code string) {
	t.Helper()
	b, a := bytes.Clone(f.body), bytes.Clone(f.args)
	p, err := verifier.PrepareOwnerAct(f.body, f.args, c)
	var local *verifier.OwnerActPreparationError
	if p != nil || !errors.As(err, &local) || local.Code != code || err.Error() != code {
		t.Fatalf("want exact %s and nil plan; got %v %v", code, p, err)
	}
	if !bytes.Equal(b, f.body) || !bytes.Equal(a, f.args) {
		t.Fatal("refusal changed caller input")
	}
}
func prepareReject(t *testing.T, f prepareFixture, code string) {
	t.Helper()
	prepareRejectContext(t, f, f.context(t), code)
}
func prepareDigest(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

// An independent literal-domain oracle uses the normative exact signed record,
// not Map or record.SigningPreimage. JSON scalar escaping below is fixture-only,
// and uses literal CCJ spellings. Production still has only the existing parser.
func prepareExpectedPreimage(body []byte, key string) []byte {
	return []byte("swarma-waggle operator-act/1\n" + `{"body":` + string(body) + `,"key":"` + key + `","role":"approver","version":"swarm-envelope/2"}`)
}
func prepareJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Rebind literal fixture text/A/body hashes after an independently specified
// valid value replacement, without using the candidate mapper as an oracle.
func (f *prepareFixture) rehash() {
	oldText := string(f.args[bytes.Index(f.args, []byte(`"text_sha256":"`))+15:])
	oldText = oldText[:64]
	text := strings.TrimPrefix(prepareDigest(f.render), "sha256:")
	f.args = bytes.Replace(f.args, []byte(oldText), []byte(text), 1)
	i := bytes.Index(f.body, []byte(`"arguments_digest":"`)) + 20
	old := f.body[i : i+71]
	f.body = bytes.Replace(f.body, old, []byte(prepareDigest(f.args)), 1)
	f.preimage = prepareExpectedPreimage(f.body, f.enrollment["device"].(string))
}
func (f *prepareFixture) owner(s string) {
	f.enrollment["owner"] = s
	f.body = bytes.Replace(f.body, []byte(`"owner":"owner"`), []byte(`"owner":`+prepareJSON(s)), 1)
	f.render = bytes.Replace(f.render, []byte(`"owner":"owner"`), []byte(`"owner":`+prepareJSON(s)), 1)
	f.rehash()
}
func prepareExactData(t *testing.T, f prepareFixture, d verifier.OwnerActSigningData) {
	t.Helper()
	for _, pair := range []struct {
		name      string
		got, want []byte
	}{{"body", d.Body, f.body}, {"arguments", d.Arguments, f.args}, {"render", d.Render, f.render}, {"preimage", d.SigningPreimage, prepareExpectedPreimage(f.body, f.enrollment["device"].(string))}} {
		if !bytes.Equal(pair.got, pair.want) {
			t.Fatalf("exact %s differs", pair.name)
		}
	}
	if d.ArgumentsDigest != prepareDigest(f.args) || d.TextSHA256 != strings.TrimPrefix(prepareDigest(f.render), "sha256:") || d.ContentID != prepareDigest(append([]byte("swarma-waggle operator-act/1\n"), f.body...)) || d.Key != f.enrollment["device"] || d.ProfilePin != preparePin || d.ReviewVersion != "owner-act-review/1" {
		t.Fatal("independent complete identity differs")
	}
	// Shape-only size witness uses86 inert characters, never a signature verifier
	// or emitted production envelope. The constructor only computes this count.
	shape := `{"body":` + string(f.body) + `,"id":"` + d.ContentID + `","signatures":[{"key":"` + d.Key + `","role":"approver","sig":"` + strings.Repeat("x", 86) + `"}],"version":"swarm-envelope/2"}`
	if d.PredictedEnvelopeBytes != len(shape) {
		t.Fatalf("predicted closed shape bytes %d != %d", d.PredictedEnvelopeBytes, len(shape))
	}
}

// All3 static operations have literal original body/A/Render/preimage fixtures
// plus separately authored literal full-review golden files. No signatures or
// native confirmation are claimed. Unbind is narrowing; others stay widening.
func TestPrepareLiteralGoldens(t *testing.T) {
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		t.Run(op, func(t *testing.T) {
			f := prepareFixtureFor(t, op)
			_, d := prepareAccept(t, f)
			prepareExactData(t, f, d)
			if !bytes.Equal(d.SigningPreimage, f.preimage) {
				t.Fatal("existing literal preimage differs")
			}
			want, err := os.ReadFile("testdata/prepare-" + op + ".review")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(d.Review, want) {
				t.Fatalf("full literal review differs:\n%s", d.Review)
			}
			class := "widening"
			if op == "unbind" {
				class = "narrowing"
			}
			if d.Class != class {
				t.Fatal("trusted class differs")
			}
		})
	}
}

// Formal identity/any normalisation: each admissible original owner spelling
// fixes exact independent body/A/Render/digest/preimage bytes. The visible review
// must retain the literal scalar distinction, including controls/invisibles.
func TestPrepareIdentityNormalization(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range []struct{ owner, display string }{
		{"owner", `owner`}, {"OWNER", `OWNER`}, {" owner", `\u{000020}owner`}, {"owner ", `owner\u{000020}`},
		{"é", `\u{0000E9}`}, {"e\u0301", `e\u{000301}`}, {"оwner", `\u{00043E}wner`},
		{"a\u200bb", `a\u{00200B}b`}, {"a\u00a0b", `a\u{0000A0}b`}, {"a\u202eb", `a\u{00202E}b`},
		{"a\x00b", `a\u{000000}b`}, {"a\x7fb", `a\u{00007F}b`},
	} {
		t.Run(fmt.Sprintf("owner-%x", tc.owner), func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			f.owner(tc.owner)
			_, d := prepareAccept(t, f)
			prepareExactData(t, f, d)
			if !bytes.Contains(d.Review, []byte(`Owner (independent enrollment): "`+tc.display+`"`+"\n")) {
				t.Fatal("owner review loses scalar spelling")
			}
			if seen[d.ContentID] {
				t.Fatal("distinct raw owner collapsed")
			}
			seen[d.ContentID] = true
			if bytes.ContainsAny(d.Review, "éо\u200b\u00a0\u202e\x00\x7f") {
				t.Fatal("review contains raw nonASCII/control")
			}
		})
	}
	// Printable opaque A values admit case/percent/quote/backslash, not Unicode.
	for _, s := range []string{"Room", "room%2Fpart", "r\"\\x", "room:part"} {
		t.Run("A-"+s, func(t *testing.T) {
			f := prepareFixtureFor(t, "bind")
			old := []byte(`"source_room":"room"`)
			replacement := []byte(`"source_room":` + prepareJSON(s))
			f.args = bytes.Replace(f.args, old, replacement, 1)
			f.render = bytes.Replace(f.render, old, replacement, 1)
			f.rehash()
			_, d := prepareAccept(t, f)
			prepareExactData(t, f, d)
			if !bytes.Contains(d.Review, []byte(`Complete canonical arguments (literal JSON): "{`)) {
				t.Fatal("full A missing")
			}
		})
	}
}

// Formal identity/line-ending rewrite: all six admitted scalar line endings
// remain exact owner/preimage identities and visibly escaped local labels. Fixed
// review layout uses LF only. No EOL form is converted to another owner's bytes.
func TestPrepareIdentityLineEndings(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range []struct{ line, escaped string }{{"\r", `\u{00000D}`}, {"\n", `\u{00000A}`}, {"\r\n", `\u{00000D}\u{00000A}`}, {"\u0085", `\u{000085}`}, {"\u2028", `\u{002028}`}, {"\u2029", `\u{002029}`}} {
		t.Run(fmt.Sprintf("%x", tc.line), func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			f.owner("a" + tc.line + "b")
			f.enrollment["installation"] = "local" + tc.line + "name"
			_, d := prepareAccept(t, f)
			prepareExactData(t, f, d)
			for _, line := range []string{`Owner (independent enrollment): "a` + tc.escaped + `b"` + "\n", `Installation (local trusted label): "local` + tc.escaped + `name"` + "\n"} {
				if !bytes.Contains(d.Review, []byte(line)) {
					t.Fatal("exact visible EOL lost", line)
				}
			}
			if seen[d.ContentID] {
				t.Fatal("line ending identity collapsed")
			}
			seen[d.ContentID] = true
		})
	}
}

// Formal identity/trailing bytes: body and A each reject LF/NUL/space/second
// value with the exact local error and nil result; original plans stay unchanged.
// Literal escaped control field data remains a valid neighboring input.
func TestPrepareIdentityTrailingBytes(t *testing.T) {
	original := prepareFixtureFor(t, "unbind")
	p, before := prepareAccept(t, original)
	for _, tail := range []string{"\n", "\x00", " ", "{}", "\r\n", "\t"} {
		for _, which := range []string{"body", "arguments"} {
			t.Run(fmt.Sprintf("%s-%x", which, tail), func(t *testing.T) {
				f := prepareFixtureFor(t, "unbind")
				if which == "body" {
					f.body = append(f.body, tail...)
				} else {
					f.args = append(f.args, tail...)
				}
				prepareReject(t, f, "preparation_invalid")
				now, ok := p.Snapshot()
				if !ok || !reflect.DeepEqual(before, now) {
					t.Fatal("failed call changed old plan")
				}
			})
		}
	}
	f := prepareFixtureFor(t, "unbind")
	f.owner("owner\x00\n ")
	_, d := prepareAccept(t, f)
	prepareExactData(t, f, d)
	for _, raw := range [][]byte{nil, {}, []byte("{}"), []byte("null"), []byte("\xff")} {
		for _, which := range []string{"body", "arguments"} {
			f := prepareFixtureFor(t, "unbind")
			if which == "body" {
				f.body = raw
			} else {
				f.args = raw
			}
			prepareReject(t, f, "preparation_invalid")
		}
	}
}

// The full review is reversible visible literal content. This independent
// decoder checks every line value and rejects nonformat text; literal escape
// spellings and controls must not collapse to each other or create headings.
func prepareUnquote(t *testing.T, s string) string {
	t.Helper()
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		t.Fatal("unquoted review value")
	}
	s = s[1 : len(s)-1]
	var out strings.Builder
	for len(s) > 0 {
		c := s[0]
		if c <= 32 || c > 126 || c == '"' {
			t.Fatal("unescaped value")
		}
		if c != '\\' {
			out.WriteByte(c)
			s = s[1:]
			continue
		}
		if len(s) >= 2 && (s[1] == '\\' || s[1] == '"') {
			out.WriteByte(s[1])
			s = s[2:]
			continue
		}
		if len(s) < 10 || s[:3] != `\u{` || s[9] != '}' {
			t.Fatal("invalid scalar escape")
		}
		v, err := strconv.ParseUint(s[3:9], 16, 32)
		if err != nil || v > 0x10ffff || v >= 0xd800 && v <= 0xdfff {
			t.Fatal("invalid code point")
		}
		out.WriteRune(rune(v))
		s = s[10:]
	}
	return out.String()
}
func prepareReviewValues(t *testing.T, b []byte) map[string]string {
	t.Helper()
	lines := strings.Split(string(b), "\n")
	if len(lines) != 19 || lines[0] != "owner-act-review/1" || lines[18] != "" {
		t.Fatal("fixed review layout differs")
	}
	out := map[string]string{}
	for _, line := range lines[1:18] {
		n, v, ok := strings.Cut(line, ": ")
		if !ok || out[n] != "" {
			t.Fatal("invalid fixed review labels")
		}
		out[n] = prepareUnquote(t, v)
	}
	return out
}
