package owneracts_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
)

// Unsupported names never produce mappings, regardless of other malformed
// inputs. No caller field can express class, raw A0, a target kind or text hash.
func TestMappingClosedSelection(t *testing.T) {
	for _, op := range []string{"", "launch.approve", "host.change", "grant.issue", "revoke", "owner-dm.bind ", "owner-dm.BIND", "owner-dm.bind\x00", strings.Repeat("x", 100000)} {
		in := mappingInput("owner-dm.bind")
		in.Operation = op
		mappingReject(t, in, "mapping_operation_unsupported")
		in.Owner = "\xff"
		mappingReject(t, in, "mapping_operation_unsupported")
	}
}

// Free hunt beyond byte identity: malformed metadata, public key encodings,
// namespace confusions and each time endpoint must hit local validation with
// zero outputs. These checks establish representation only, never enrollment.
func TestMappingMetadataRefusals(t *testing.T) {
	bad := []struct {
		name   string
		change func(*owneracts.MappingInput)
	}{}
	for _, s := range []string{"", "-a", "A", "a_b", "a/b", "a.b", "*", "a*", "a ", " a", "a\n", "é", strings.Repeat("a", 64)} {
		s := s
		bad = append(bad, struct {
			name   string
			change func(*owneracts.MappingInput)
		}{"identity/" + fmt.Sprintf("%x", s), func(in *owneracts.MappingInput) { in.Identity = s }})
	}
	for _, s := range []string{"", strings.Repeat("o", 256), "\xff", "o\xed\xa0\x80"} {
		s := s
		bad = append(bad, struct {
			name   string
			change func(*owneracts.MappingInput)
		}{"owner/" + fmt.Sprintf("%x", s), func(in *owneracts.MappingInput) { in.Owner = s }})
	}
	for _, field := range []string{"audience", "epoch"} {
		for _, s := range []string{"", strings.Repeat("0", 32), "epoch:" + strings.Repeat("0", 31), "owner-acts:" + strings.Repeat("0", 33), "OWNER-ACTS:" + strings.Repeat("0", 32), "epoch:" + strings.Repeat("A", 32), "owner-acts:" + strings.Repeat("g", 32), mappingAudience + "\n", mappingEpoch + " ", "epoch:" + strings.Repeat("0", 32) + "x"} {
			s, field := s, field
			bad = append(bad, struct {
				name   string
				change func(*owneracts.MappingInput)
			}{field + "/" + fmt.Sprintf("%x", s), func(in *owneracts.MappingInput) {
				if field == "audience" {
					in.Audience = s
				} else {
					in.Epoch = s
				}
			}})
		}
	}
	badKeys := []string{"", mappingKey + "=", strings.ToUpper(mappingKey), "P256:" + mappingKey[5:], "ed25519:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "p256:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, 33)), "p256:" + base64.RawURLEncoding.EncodeToString(append([]byte{4}, bytes.Repeat([]byte{1}, 32)...)), "p256:" + base64.RawURLEncoding.EncodeToString(append([]byte{3}, bytes.Repeat([]byte{255}, 32)...)), mappingKey + "\n", "p256:" + strings.Repeat("-", 43) + "/"}
	for _, s := range badKeys {
		s := s
		bad = append(bad, struct {
			name   string
			change func(*owneracts.MappingInput)
		}{"key/" + fmt.Sprintf("%x", s), func(in *owneracts.MappingInput) { in.Key = s }})
	}
	for _, field := range []string{"action", "nonce"} {
		for _, s := range []string{"", mappingAction + "=", mappingAction[:21], mappingAction + "x", "AAECAwQFBgcICQoLDA0ODx", "AAECAwQFBgcICQoLDA0OD/", mappingAction + "\n", strings.Repeat("A", 21) + "+"} {
			s, field := s, field
			bad = append(bad, struct {
				name   string
				change func(*owneracts.MappingInput)
			}{field + "/" + fmt.Sprintf("%x", s), func(in *owneracts.MappingInput) {
				if field == "action" {
					in.ActionID = s
				} else {
					in.Nonce = s
				}
			}})
		}
	}
	for _, field := range []string{"iat", "exp"} {
		for _, s := range []string{"", "1969-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "10000-01-01T00:00:00Z", "2026-01-02t03:04:05Z", "2026-01-02T03:04:05z", "2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05.0Z", "2026-01-02T03:04:60Z", "2026-02-30T03:04:05Z", "2026-01-02T3:04:05Z", "2026-01-02T03:04:05Z\n"} {
			s, field := s, field
			bad = append(bad, struct {
				name   string
				change func(*owneracts.MappingInput)
			}{field + "/" + fmt.Sprintf("%x", s), func(in *owneracts.MappingInput) {
				if field == "iat" {
					in.IssuedAt = s
				} else {
					in.ExpiresAt = s
				}
			}})
		}
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			in := mappingInput("owner-dm.bind")
			c.change(&in)
			mappingReject(t, in, "mapping_invalid")
		})
	}
	for _, exp := range []string{"2026-01-02T03:04:05Z", "2026-01-02T03:04:04Z", "2026-01-02T03:06:06Z", "9999-12-31T23:59:59Z"} {
		in := mappingInput("owner-dm.bind")
		in.ExpiresAt = exp
		mappingReject(t, in, "mapping_invalid")
	}
}

// Boundary controls reject neither valid old/future dates nor confirmed=false;
// canonical IDs may coincide because random generation/uniqueness is unproved.
func TestMappingMetadataNeighbors(t *testing.T) {
	for _, id := range []string{"a", "0", "a-", strings.Repeat("a", 63), "0" + strings.Repeat("-", 62)} {
		in := mappingInput("owner-dm.bind")
		in.Identity = id
		mapped(t, in)
	}
	for _, owner := range []string{strings.Repeat("x", 255), strings.Repeat("é", 127) + "x", " ", "\x00"} {
		in := mappingInput("owner-dm.bind")
		in.Owner = owner
		mapped(t, in)
	}
	for _, pair := range [][2]string{{"1970-01-01T00:00:00Z", "1970-01-01T00:00:01Z"}, {"9999-12-31T23:57:59Z", "9999-12-31T23:59:59Z"}, {"2024-02-29T23:59:59Z", "2024-03-01T00:00:00Z"}} {
		in := mappingInput("owner-dm.bind")
		in.IssuedAt, in.ExpiresAt = pair[0], pair[1]
		mapped(t, in)
	}
	for _, confirmed := range []bool{false, true} {
		in := mappingInput("owner-dm.bind")
		in.Confirmed = confirmed
		in.ActionID = in.Nonce
		mapped(t, in)
	}
}

// Each relevant A0 field is checked afresh; caller-mutable old Arguments cannot
// serve as evidence. Zero optional fields are data, not unavailable facts.
func TestMappingArgumentRefusals(t *testing.T) {
	for _, op := range []string{"owner-dm.bind", "owner-dm.unbind", "owner-dm.mirror-enable"} {
		t.Run(op, func(t *testing.T) {
			for _, field := range []string{"source", "recipient", "owner", "bound"} {
				if op == "owner-dm.bind" && field == "bound" {
					continue
				}
				for _, s := range []string{"", " ", "x\n", "\x7f", "é", "e\u0301", strings.Repeat("x", 256)} {
					in := mappingInput(op)
					switch field {
					case "source":
						in.Arguments.SourceRoom = s
					case "recipient":
						in.Arguments.SourceRecipient = s
					case "owner":
						in.Arguments.OwnerRecipient = s
					case "bound":
						in.Arguments.BoundRoom = s
					}
					mappingReject(t, in, "mapping_invalid")
				}
			}
			for _, field := range []string{"authority", "generation", "binding", "audience"} {
				if field == "audience" && op != "owner-dm.mirror-enable" {
					continue
				}
				min := int64(1)
				if field == "binding" {
					min = 0
				}
				for _, n := range []int64{math.MinInt64, min - 1, 9007199254740991, math.MaxInt64} {
					in := mappingInput(op)
					switch field {
					case "authority":
						in.Arguments.AuthorityRevision = n
					case "generation":
						in.Arguments.IdentityGeneration = n
					case "binding":
						in.Arguments.BindingRevision = n
					case "audience":
						in.Arguments.AudienceRevision = n
					}
					mappingReject(t, in, "mapping_invalid")
				}
			}
			in := mappingInput(op)
			in.Arguments.Mirror = !in.Arguments.Mirror
			mappingReject(t, in, "mapping_invalid")
			if op == "owner-dm.bind" {
				in = mappingInput(op)
				in.Arguments.BoundRoom = "bound"
				mappingReject(t, in, "mapping_invalid")
			}
			if op != "owner-dm.mirror-enable" {
				in = mappingInput(op)
				in.Arguments.AudienceRevision = 1
				mappingReject(t, in, "mapping_invalid")
				in = mappingInput(op)
				in.Arguments.AudienceDigest = "sha256:" + strings.Repeat("0", 64)
				mappingReject(t, in, "mapping_invalid")
			} else {
				for _, s := range []string{"", strings.Repeat("0", 64), "SHA256:" + strings.Repeat("0", 64), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("0", 63), "sha256:" + strings.Repeat("0", 65)} {
					in = mappingInput(op)
					in.Arguments.AudienceDigest = s
					mappingReject(t, in, "mapping_invalid")
				}
			}
		})
	}
}

// All operations accept their closed A0 revision endpoints and printable ASCII
// identifier endpoints. The complete returned A also passes the existing parser;
// that compatibility check supplements independent byte goldens, not replaces them.
func TestMappingArgumentNeighbors(t *testing.T) {
	for _, op := range []string{"owner-dm.bind", "owner-dm.unbind", "owner-dm.mirror-enable"} {
		for _, n := range []int64{1, 9007199254740990} {
			in := mappingInput(op)
			in.Arguments.AuthorityRevision = n
			in.Arguments.IdentityGeneration = n
			in.Arguments.BindingRevision = n - 1
			if op == "owner-dm.mirror-enable" {
				in.Arguments.AudienceRevision = n
			}
			for _, s := range []string{"!", "~", strings.Repeat("x", 255)} {
				in.Arguments.SourceRoom, in.Arguments.SourceRecipient, in.Arguments.OwnerRecipient = s, s, s
				if op != "owner-dm.bind" {
					in.Arguments.BoundRoom = s
				}
				got := mapped(t, in)
				parsed, err := owneracts.Parse(op, got.Arguments)
				if err != nil || parsed.SourceRoom != s || parsed.AuthorityRevision != n || parsed.BindingRevision != n-1 {
					t.Fatalf("computed full arguments lost typed values: %+v %v", parsed, err)
				}
			}
		}
	}
}

// Construct an exact complete-A byte length using legal ASCII quotes. The
// fixed text hash length is 64, so its value cannot affect this length oracle.
func mappingAtArgumentSize(t *testing.T, size int) owneracts.MappingInput {
	t.Helper()
	in := mappingInput("owner-dm.unbind")
	a := &in.Arguments
	a.SourceRoom, a.SourceRecipient, a.OwnerRecipient, a.BoundRoom = strings.Repeat("x", 255), strings.Repeat("x", 255), strings.Repeat("x", 255), strings.Repeat("x", 255)
	a.AuthorityRevision, a.IdentityGeneration, a.BindingRevision = 9007199254740990, 9007199254740990, 9007199254740990
	base := len(mappingGolden(t, "unbind", "arguments.json")) + (255 - 4) + (255 - 7) + (255 - 5) + (255 - 5) + (16 - 1) + (16 - 2) + (16 - 2)
	extra := size - base
	if extra < 0 || extra > 4*255 {
		t.Fatalf("invalid size fixture %d; base%d", size, base)
	}
	for _, s := range []*string{&a.SourceRoom, &a.SourceRecipient, &a.OwnerRecipient, &a.BoundRoom} {
		n := min(extra, 255)
		extra -= n
		*s = strings.Repeat(`"`, n) + strings.Repeat("x", 255-n)
	}
	return in
}

// Exact complete-A neighbors include the computed real text hash. Valid4096
// Render alone is not a positive control: other bounds constrain valid Render
// below it. Larger Render fixtures also exceed A and prove only zero refusal.
func TestMappingByteCaps(t *testing.T) {
	for _, n := range []int{2047, 2048, 2049} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			in := mappingAtArgumentSize(t, n)
			if n > 2048 {
				mappingReject(t, in, "mapping_too_large")
				return
			}
			got := mapped(t, in)
			if len(got.Arguments) != n {
				t.Fatalf("complete A length %d want%d", len(got.Arguments), n)
			}
		})
	}
	in := mappingAtArgumentSize(t, 2048)
	in.Owner = strings.Repeat("\x00", 255)
	in.Identity = strings.Repeat("a", 63)
	got := mapped(t, in)
	if len(got.Render) != 4015 {
		t.Fatalf("maximal-owner/identity boundary Render length%d want4015", len(got.Render))
	}
	for _, n := range []int{2129, 2130} {
		in = mappingAtArgumentSize(t, n)
		in.Owner = strings.Repeat("\x00", 255)
		in.Identity = strings.Repeat("a", 63)
		mappingReject(t, in, "mapping_too_large")
	}
}

// Every string's own bound is checked even when that field is irrelevant or
// invalid. This corpus is a bounded work probe, not an allocation benchmark.
func TestMappingHugeTypedStrings(t *testing.T) {
	huge := strings.Repeat("x", 100000)
	for _, field := range []string{"identity", "owner", "epoch", "aud", "action", "nonce", "iat", "exp", "key", "room", "recipient", "owner-recipient", "bound", "digest"} {
		t.Run(field, func(t *testing.T) {
			in := mappingInput("owner-dm.bind")
			switch field {
			case "identity":
				in.Identity = huge
			case "owner":
				in.Owner = huge
			case "epoch":
				in.Epoch = huge
			case "aud":
				in.Audience = huge
			case "action":
				in.ActionID = huge
			case "nonce":
				in.Nonce = huge
			case "iat":
				in.IssuedAt = huge
			case "exp":
				in.ExpiresAt = huge
			case "key":
				in.Key = huge
			case "room":
				in.Arguments.SourceRoom = huge
			case "recipient":
				in.Arguments.SourceRecipient = huge
			case "owner-recipient":
				in.Arguments.OwnerRecipient = huge
			case "bound":
				in.Arguments.BoundRoom = huge
			case "digest":
				in.Arguments.AudienceDigest = huge
			}
			mappingReject(t, in, "mapping_invalid")
		})
	}
}
