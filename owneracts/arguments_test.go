package owneracts_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/internal/apicheck"
	"github.com/relux-works/swarma-envelope/owneracts"
	"github.com/relux-works/swarma-envelope/record"
)

const textHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Literal, independently ordered fixtures fix the accepted schemas and decoded
// values. Hashes are opaque grammar examples, not claims about actual text/state.
var fixtures = []struct {
	op, raw string
	want    owneracts.Arguments
}{
	{
		"owner-dm.bind",
		`{"authority_revision":1,"binding_revision":0,"identity_generation":1,"mirror":false,"owner_recipient":"owner","profile":"owner-acts/1","source_recipient":"service","source_room":"room","text_sha256":"` + textHash + `"}`,
		owneracts.Arguments{Operation: "owner-dm.bind", Profile: "owner-acts/1", SourceRoom: "room", SourceRecipient: "service", TextSHA256: textHash, AuthorityRevision: 1, IdentityGeneration: 1, BindingRevision: 0, OwnerRecipient: "owner"},
	},
	{
		"owner-dm.unbind",
		`{"authority_revision":2,"binding_revision":3,"bound_room":"bound","identity_generation":4,"owner_recipient":"owner","profile":"owner-acts/1","source_recipient":"service","source_room":"room","text_sha256":"` + textHash + `"}`,
		owneracts.Arguments{Operation: "owner-dm.unbind", Profile: "owner-acts/1", SourceRoom: "room", SourceRecipient: "service", TextSHA256: textHash, AuthorityRevision: 2, IdentityGeneration: 4, BindingRevision: 3, OwnerRecipient: "owner", BoundRoom: "bound"},
	},
	{
		"owner-dm.mirror-enable",
		`{"audience_digest":"sha256:` + textHash + `","audience_revision":5,"authority_revision":2,"binding_revision":3,"bound_room":"bound","identity_generation":4,"mirror":true,"owner_recipient":"owner","profile":"owner-acts/1","source_recipient":"service","source_room":"room","text_sha256":"` + textHash + `"}`,
		owneracts.Arguments{Operation: "owner-dm.mirror-enable", Profile: "owner-acts/1", SourceRoom: "room", SourceRecipient: "service", TextSHA256: textHash, AuthorityRevision: 2, IdentityGeneration: 4, BindingRevision: 3, OwnerRecipient: "owner", BoundRoom: "bound", Mirror: true, AudienceRevision: 5, AudienceDigest: "sha256:" + textHash},
	},
}

func object(t *testing.T, raw string) map[string]any {
	t.Helper()
	v, err := record.Parse([]byte(raw), 2048, 4)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func canonical(t *testing.T, v any) []byte {
	t.Helper()
	b, err := record.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func stringField(a owneracts.Arguments, name string) string {
	switch name {
	case "source_room":
		return a.SourceRoom
	case "source_recipient":
		return a.SourceRecipient
	case "owner_recipient":
		return a.OwnerRecipient
	case "bound_room":
		return a.BoundRoom
	case "text_sha256":
		return a.TextSHA256
	case "audience_digest":
		return a.AudienceDigest
	}
	panic("unexpected test field")
}

func integerField(a owneracts.Arguments, name string) int64 {
	switch name {
	case "authority_revision":
		return a.AuthorityRevision
	case "identity_generation":
		return a.IdentityGeneration
	case "binding_revision":
		return a.BindingRevision
	case "audience_revision":
		return a.AudienceRevision
	}
	panic("unexpected test field")
}

func reject(t *testing.T, op string, raw []byte, code string) {
	t.Helper()
	before := bytes.Clone(raw)
	got, err := owneracts.Parse(op, raw)
	var e *owneracts.Error
	if !errors.As(err, &e) || e.Code != code || err.Error() != code {
		t.Fatalf("expected parser-local %s, got result=%+v error=%v", code, got, err)
	}
	if got != (owneracts.Arguments{}) {
		t.Fatalf("rejection returned partial arguments: %+v", got)
	}
	if !bytes.Equal(before, raw) {
		t.Fatal("rejection changed caller bytes")
	}
}

// The three exact active schemas parse to the specified values without changing
// the caller buffer. All are grammar results, including the widening operations.
func TestActiveSchemas(t *testing.T) {
	for _, f := range fixtures {
		t.Run(f.op, func(t *testing.T) {
			raw := []byte(f.raw)
			got, err := owneracts.Parse(f.op, raw)
			if err != nil || got != f.want || string(raw) != f.raw {
				t.Fatalf("got %+v, %v; want %+v and unchanged input", got, err, f.want)
			}
		})
	}
}

// Operation is an explicit, closed selector, checked before size or syntax. The
// argument object cannot select an operation or activate either reserved name.
func TestOperationSelection(t *testing.T) {
	for _, op := range []string{"", "launch.approve", "host.change", "owner-dm.mirror-disable", "OWNER-DM.BIND", "owner-dm.bind ", "grant.issue", "revoke", "owner-acts/1", "unknown", "owner-dm.bind\x00"} {
		t.Run(op, func(t *testing.T) {
			for _, raw := range [][]byte{[]byte(fixtures[0].raw), nil, bytes.Repeat([]byte{'x'}, 2049)} {
				reject(t, op, raw, "arguments_operation_unsupported")
			}
		})
	}
	for _, f := range fixtures {
		m := object(t, f.raw)
		m["operation"] = f.op
		reject(t, f.op, canonical(t, m), "arguments_invalid")
	}
}

// Every member is required and typed; no unknown, null, nested or array member
// survives, including equal-cardinality substitutions and adjacent op schemas.
func TestClosedMembersAndTypes(t *testing.T) {
	for _, f := range fixtures {
		t.Run(f.op, func(t *testing.T) {
			for key, value := range object(t, f.raw) {
				t.Run(key, func(t *testing.T) {
					m := object(t, f.raw)
					delete(m, key)
					reject(t, f.op, canonical(t, m), "arguments_invalid")
					m["unknown"] = value
					reject(t, f.op, canonical(t, m), "arguments_invalid")
					for _, wrong := range []any{nil, []any{}, []any{value}, map[string]any{}, map[string]any{"nested": value}, int64(1), "1", "false", "true", true, false} {
						// Skip only values of the specified scalar type, exercised below.
						switch value.(type) {
						case int64:
							if _, ok := wrong.(int64); ok {
								continue
							}
						case string:
							if _, ok := wrong.(string); ok {
								continue
							}
						case bool:
							if _, ok := wrong.(bool); ok {
								continue
							}
						}
						m = object(t, f.raw)
						m[key] = wrong
						reject(t, f.op, canonical(t, m), "arguments_invalid")
					}
				})
			}
			for _, key := range []string{"unknown", "confirmed", "current", "class", "request_digest", "next_host"} {
				m := object(t, f.raw)
				m[key] = true
				reject(t, f.op, canonical(t, m), "arguments_invalid")
			}
			for key, value := range object(t, f.raw) {
				duplicate := `{"` + key + `":` + string(canonical(t, value)) + `,` + f.raw[1:]
				reject(t, f.op, []byte(duplicate), "arguments_invalid")
			}
			for _, other := range fixtures {
				if other.op != f.op {
					reject(t, f.op, []byte(other.raw), "arguments_invalid")
				}
			}
		})
	}
}

// ASCII identifiers are opaque, not resolved or normalized: every printable
// non-space byte is allowed, including correctly escaped quote/backslash bytes.
func TestIdentifierBounds(t *testing.T) {
	for _, f := range fixtures {
		for _, key := range []string{"source_room", "source_recipient", "owner_recipient", "bound_room"} {
			if _, present := object(t, f.raw)[key]; !present {
				continue
			}
			t.Run(f.op+"/"+key, func(t *testing.T) {
				for _, s := range []string{"!", "~", strings.Repeat("x", 255), `quote"slash\/>`, "123", "*"} {
					m := object(t, f.raw)
					m[key] = s
					if got, err := owneracts.Parse(f.op, canonical(t, m)); err != nil || stringField(got, key) != s {
						t.Fatalf("valid ASCII %q must be retained exactly, got %+v: %v", s, got, err)
					}
				}
				for b := byte(0x21); b <= 0x7e; b++ {
					m := object(t, f.raw)
					m[key] = string([]byte{b})
					if got, err := owneracts.Parse(f.op, canonical(t, m)); err != nil || stringField(got, key) != m[key] {
						t.Fatalf("ASCII %x must be retained exactly, got %+v: %v", b, got, err)
					}
				}
				for control := byte(0); control <= 0x20; control++ {
					m := object(t, f.raw)
					m[key] = string([]byte{control})
					reject(t, f.op, canonical(t, m), "arguments_invalid")
				}
				for _, s := range []string{"", " ", "x y", strings.Repeat("x", 256), "\x00", "\t", "\n", "\r", "\x1f", "\x7f", "\u00a0", "\u2003", "\u202e", "é", "e\u0301", "\uff01"} {
					m := object(t, f.raw)
					m[key] = s
					reject(t, f.op, canonical(t, m), "arguments_invalid")
				}
			})
		}
	}
}

// Revisions are integers with the profile's increment headroom, not the larger
// CCJ limit; only binding_revision may be zero. Check each applicable field.
func TestRevisionBounds(t *testing.T) {
	for _, f := range fixtures {
		for _, key := range []string{"authority_revision", "identity_generation", "binding_revision", "audience_revision"} {
			if _, present := object(t, f.raw)[key]; !present {
				continue
			}
			t.Run(f.op+"/"+key, func(t *testing.T) {
				min := int64(1)
				if key == "binding_revision" {
					min = 0
				}
				for _, n := range []int64{min, 1, 9007199254740990} {
					m := object(t, f.raw)
					m[key] = n
					if got, err := owneracts.Parse(f.op, canonical(t, m)); err != nil || integerField(got, key) != n {
						t.Fatalf("valid revision %d must be retained exactly, got %+v: %v", n, got, err)
					}
				}
				for _, n := range []int64{min - 1, -9007199254740991, 9007199254740991} {
					m := object(t, f.raw)
					m[key] = n
					reject(t, f.op, canonical(t, m), "arguments_invalid")
				}
				old := fmt.Sprint(object(t, f.raw)[key])
				for _, token := range []string{`"1"`, "1.0", "1e0", "1E+0", "+1", "01", "-0", "9007199254740992", "9223372036854775808", "-9223372036854775809", "NaN", "Infinity"} {
					raw := strings.Replace(f.raw, `"`+key+`":`+old, `"`+key+`":`+token, 1)
					reject(t, f.op, []byte(raw), "arguments_invalid")
				}
			})
		}
	}
}

// Profile/digests are exact literals/alphabets; mirror has the operation's
// literal boolean. No digest is matched to text, a room roster or protected state.
func TestProfileDigestsAndMirror(t *testing.T) {
	for _, f := range fixtures {
		for _, s := range []string{"", "owner-acts/0", "owner-acts/2", "OWNER-ACTS/1", "owner-acts/1 ", "owner-acts/1\n"} {
			m := object(t, f.raw)
			m["profile"] = s
			reject(t, f.op, canonical(t, m), "arguments_invalid")
		}
		for _, key := range []string{"text_sha256", "audience_digest"} {
			if _, present := object(t, f.raw)[key]; !present {
				continue
			}
			t.Run(f.op+"/"+key, func(t *testing.T) {
				prefix := ""
				if key == "audience_digest" {
					prefix = "sha256:"
				}
				if key == "audience_digest" {
					m := object(t, f.raw)
					m[key] = textHash
					reject(t, f.op, canonical(t, m), "arguments_invalid")
				}
				for _, s := range []string{strings.Repeat("0", 64), strings.Repeat("f", 64), textHash} {
					m := object(t, f.raw)
					m[key] = prefix + s
					if got, err := owneracts.Parse(f.op, canonical(t, m)); err != nil || stringField(got, key) != prefix+s {
						t.Fatalf("digest must be retained exactly, got %+v: %v", got, err)
					}
				}
				for _, s := range []string{"", prefix, prefix + strings.Repeat("0", 63), prefix + strings.Repeat("0", 65), prefix + strings.Repeat("A", 64), prefix + strings.Repeat("g", 64), prefix + strings.Repeat("0", 63) + " ", textHash + "x", "sha256:" + prefix + textHash, "SHA256:" + textHash, "sha512:" + textHash} {
					m := object(t, f.raw)
					m[key] = s
					reject(t, f.op, canonical(t, m), "arguments_invalid")
				}
			})
		}
		if f.op != "owner-dm.unbind" {
			m := object(t, f.raw)
			m["mirror"] = !m["mirror"].(bool)
			reject(t, f.op, canonical(t, m), "arguments_invalid")
		}
	}
}

// These wire variants reach the production CCJ route. Equivalent noncanonical
// encodings refuse rather than normalize; malformed values use the invalid code.
func TestWireGrammar(t *testing.T) {
	for _, f := range fixtures {
		t.Run(f.op, func(t *testing.T) {
			noncanonical := map[string]string{
				"leading-space": " " + f.raw, "trailing-lf": f.raw + "\n", "crlf": f.raw + "\r\n", "tab": "\t" + f.raw,
				"interior-whitespace": strings.Replace(f.raw, ":", ": ", 1),
				"key-order":           `{"text_sha256":"` + textHash + `",` + strings.TrimSuffix(strings.Replace(f.raw, `,"text_sha256":"`+textHash+`"`, "", 1)[1:], "}") + `}`,
				"escaped-key":         strings.Replace(f.raw, `"profile"`, `"\u0070rofile"`, 1),
				"escaped-value":       strings.Replace(f.raw, "owner-acts/1", `owner-acts\/1`, 1),
				"unicode-escape":      strings.Replace(f.raw, `"room"`, `"\u0072oom"`, 1),
			}
			for name, raw := range noncanonical {
				t.Run(name, func(t *testing.T) { reject(t, f.op, []byte(raw), "arguments_noncanonical") })
			}
			invalid := map[string][]byte{
				"empty": nil, "truncated": []byte(f.raw[:len(f.raw)-1]), "second-value": []byte(f.raw + "{}"),
				"bom": append([]byte{0xef, 0xbb, 0xbf}, []byte(f.raw)...), "utf16": {0xff, 0xfe, '{', 0, '}', 0},
				"invalid-utf8":       []byte(strings.Replace(f.raw, "room", "\xff", 1)),
				"raw-control":        []byte(strings.Replace(f.raw, "room", "r\x00m", 1)),
				"unicode-whitespace": []byte("\u00a0" + f.raw), "comment": []byte("/*a*/" + f.raw), "trailing-comment": []byte(f.raw + "//a"),
				"single-quotes": []byte(strings.ReplaceAll(f.raw, `"`, `'`)), "trailing-comma": []byte(strings.TrimSuffix(f.raw, "}") + ",}"),
				"bad-escape":        []byte(strings.Replace(f.raw, "room", `\x72oom`, 1)),
				"surrogate":         []byte(strings.Replace(f.raw, "room", `\ud800`, 1)),
				"duplicate":         []byte(`{"profile":"owner-acts/1",` + f.raw[1:]),
				"escaped-duplicate": []byte(`{"\u0070rofile":"owner-acts/1",` + f.raw[1:]),
			}
			for name, raw := range invalid {
				t.Run(name, func(t *testing.T) { reject(t, f.op, raw, "arguments_invalid") })
			}
			for _, raw := range []string{`null`, `true`, `1`, `"object"`, `[]`, `[` + f.raw + `]`, `{}`, `{"x":[[[[]]]]}`, `{"x":{"x":{"x":{"x":{}}}}}`} {
				reject(t, f.op, []byte(raw), "arguments_invalid")
			}
		})
	}
}

// Byte limits charge received bytes, including canonical quote escapes. Neighbor
// valid schemas at 2047/2048 and the same grammar at 2049 exercise the size gate;
// bind's narrower schema cannot reach 2048 even with maximal escaping.
func TestByteAndDepthCaps(t *testing.T) {
	for _, f := range fixtures {
		t.Run(f.op, func(t *testing.T) {
			m := object(t, f.raw)
			keys := []string{}
			for _, key := range []string{"source_room", "source_recipient", "owner_recipient", "bound_room"} {
				if _, ok := m[key]; ok {
					m[key] = strings.Repeat("x", 255)
					keys = append(keys, key)
				}
			}
			for _, key := range []string{"authority_revision", "identity_generation", "binding_revision", "audience_revision"} {
				if _, ok := m[key]; ok {
					m[key] = int64(9007199254740990)
				}
			}
			base := len(canonical(t, m))
			for _, target := range []int{base, 2047, 2048, 2049, base + len(keys)*255} {
				extra := target - base
				if extra < 0 || extra > len(keys)*255 {
					continue
				}
				for _, key := range keys {
					n := min(extra, 255)
					extra -= n
					m[key] = strings.Repeat(`"`, n) + strings.Repeat("x", 255-n)
				}
				b := canonical(t, m)
				if len(b) != target {
					t.Fatalf("fixture bytes=%d, want %d", len(b), target)
				}
				if target > 2048 {
					reject(t, f.op, b, "arguments_too_large")
				} else if _, err := owneracts.Parse(f.op, b); err != nil {
					t.Fatalf("valid %d-byte schema: %v", target, err)
				}
			}
			for _, size := range []int{2047, 2048, 2049, 4096} {
				code := "arguments_invalid"
				if size > 2048 {
					code = "arguments_too_large"
				}
				reject(t, f.op, bytes.Repeat([]byte{'x'}, size), code)
			}
			for _, depth := range []int{3, 4, 5, 16, 100} {
				raw := strings.Repeat(`{"x":`, depth) + "0" + strings.Repeat("}", depth)
				reject(t, f.op, []byte(raw), "arguments_invalid")
			}
		})
	}
}

// Decoded values own their storage: overwriting input and changing a returned
// value cannot change an earlier value copy. This is not concurrent-input safety.
func TestArgumentOwnership(t *testing.T) {
	for _, f := range fixtures {
		raw := []byte(f.raw)
		got, err := owneracts.Parse(f.op, raw)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := got
		for i := range raw {
			raw[i] = 'x'
		}
		got.SourceRoom = "changed"
		if snapshot != f.want {
			t.Fatalf("parsed snapshot changed: %+v", snapshot)
		}
	}
}

// This inventory checks names only; it neither proves behavior nor approves API.
func TestAPISurface(t *testing.T) { apicheck.Check(t) }
