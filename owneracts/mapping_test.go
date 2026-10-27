package owneracts_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
)

// Fixed compressed public base-point encodings, not enrolled or private keys.
const mappingKey = "p256:A2sX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"
const mappingOtherKey = "p256:AmsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"
const mappingAction = "AAECAwQFBgcICQoLDA0ODw"
const mappingNonce = "EBESExQVFhcYGRobHB0eHw"
const mappingAudience = "owner-acts:0123456789abcdef0123456789abcdef"
const mappingEpoch = "epoch:fedcba9876543210fedcba9876543210"
const mappingDomain = "swarma-waggle operator-act/1\n"

func mappingInput(op string) owneracts.MappingInput {
	a := owneracts.ArgumentInput{SourceRoom: "room", SourceRecipient: "service", OwnerRecipient: "owner", AuthorityRevision: 7, IdentityGeneration: 11}
	if op != "owner-dm.bind" {
		a.BindingRevision = 12
		a.BoundRoom = "bound"
	}
	if op == "owner-dm.mirror-enable" {
		a.Mirror = true
		a.AudienceRevision = 13
		a.AudienceDigest = "sha256:" + strings.Repeat("0", 64)
	}
	return owneracts.MappingInput{Operation: op, Identity: "identity", Owner: "owner", Epoch: mappingEpoch, Audience: mappingAudience, ActionID: mappingAction, Nonce: mappingNonce, IssuedAt: "2026-01-02T03:04:05Z", ExpiresAt: "2026-01-02T03:06:05Z", Key: mappingKey, Arguments: a}
}

func mapped(t *testing.T, in owneracts.MappingInput) owneracts.Mapping {
	t.Helper()
	got, err := owneracts.Map(in)
	if err != nil {
		t.Fatalf("valid typed mapping refused: %v", err)
	}
	return got
}

func mappingReject(t *testing.T, in owneracts.MappingInput, code string) {
	t.Helper()
	before := in
	got, err := owneracts.Map(in)
	var local *owneracts.MappingError
	if !errors.As(err, &local) || local.Code != code || err.Error() != code {
		t.Fatalf("expected mapping-local %s, got %+v error=%v", code, got, err)
	}
	if !reflect.DeepEqual(got, owneracts.Mapping{}) {
		t.Fatalf("rejection returned usable mapping: %+v", got)
	}
	if in != before {
		t.Fatal("mapping changed typed input")
	}
}

func mappingGolden(t *testing.T, name, suffix string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + "." + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mappingSHA(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// These literal byte fixtures were hand-ordered from the closed field contract;
// their fixed hashes were calculated independently over those bytes. No mapping
// or canonicalizer under test generates expectations. No signatures are created.
func TestMappingGoldenBytes(t *testing.T) {
	for _, name := range []string{"bind", "unbind", "mirror-enable"} {
		t.Run(name, func(t *testing.T) {
			in := mappingInput("owner-dm." + name)
			got := mapped(t, in)
			for suffix, actual := range map[string][]byte{"render": got.Render, "arguments.json": got.Arguments, "body.json": got.Body, "preimage": got.SigningPreimage} {
				if !bytes.Equal(actual, mappingGolden(t, name, suffix)) {
					t.Fatalf("exact %s bytes differ:\n%s", suffix, actual)
				}
			}
			hashes := strings.Split(strings.TrimSuffix(string(mappingGolden(t, name, "hashes.txt")), "\n"), "\n")
			if mappingSHA(got.Render) != hashes[0] || got.ArgumentsDigest != hashes[1] || got.ContentID != hashes[2] {
				t.Fatalf("independent golden hashes differ: %+v", got)
			}
			mappingEquations(t, in, got)
		})
	}
}

// Supplement exact goldens with independently spelled public record equations.
// Consistency alone is not a schema oracle; goldens above fix membership/class.
func mappingEquations(t *testing.T, in owneracts.MappingInput, got owneracts.Mapping) {
	t.Helper()
	if !bytes.HasPrefix(got.Render, []byte("owner-acts/1\n")) || got.Render[len(got.Render)-1] != '}' {
		t.Fatal("Render framing changed")
	}
	if !bytes.Contains(got.Arguments, []byte(`"text_sha256":"`+mappingSHA(got.Render)+`"`)) {
		t.Fatal("text hash does not bind complete Render bytes")
	}
	if got.ArgumentsDigest != "sha256:"+mappingSHA(got.Arguments) {
		t.Fatal("arguments digest must bind complete A without domain/LF")
	}
	if got.ContentID != "sha256:"+mappingSHA(append([]byte(mappingDomain), got.Body...)) {
		t.Fatal("content ID must bind complete operator body and domain")
	}
	want := mappingDomain + `{"body":` + string(got.Body) + `,"key":"` + in.Key + `","role":"approver","version":"swarm-envelope/2"}`
	if string(got.SigningPreimage) != want {
		t.Fatal("raw preimage must contain exact complete body, full key, role, version and domain")
	}
	if bytes.Contains(got.Render, []byte(`"text_sha256"`)) || bytes.Contains(got.Render, []byte(`"arguments_digest"`)) || bytes.Contains(got.Render, []byte(`"signatures"`)) {
		t.Fatal("recursive/extra rendering member")
	}
	if bytes.Contains(got.Body, []byte(`"arguments":`)) || bytes.Contains(got.Body, []byte(`"key":`)) || bytes.Contains(got.Body, []byte(`"profile":`)) {
		t.Fatal("mapping altered closed operator body schema")
	}
}

// Every variable D field and operation-specific A0 field binds exact supplied
// bytes. Neighbors change the complete Render as specified, then all identities.
func TestMappingEveryFieldBinds(t *testing.T) {
	cases := []struct {
		name, op, old, next string
		change              func(*owneracts.MappingInput)
	}{
		{"key", "bind", mappingKey, mappingOtherKey, func(in *owneracts.MappingInput) { in.Key = mappingOtherKey }},
		{"confirmed", "bind", `"confirmed":false`, `"confirmed":true`, func(in *owneracts.MappingInput) { in.Confirmed = true }},
		{"identity", "bind", `"id":"identity"`, `"id":"identity-1"`, func(in *owneracts.MappingInput) { in.Identity = "identity-1" }},
		{"owner", "bind", `"owner":"owner"`, `"owner":"Owner"`, func(in *owneracts.MappingInput) { in.Owner = "Owner" }},
		{"audience", "bind", mappingAudience, "owner-acts:1123456789abcdef0123456789abcdef", func(in *owneracts.MappingInput) { in.Audience = "owner-acts:1123456789abcdef0123456789abcdef" }},
		{"epoch", "bind", mappingEpoch, "epoch:0edcba9876543210fedcba9876543210", func(in *owneracts.MappingInput) { in.Epoch = "epoch:0edcba9876543210fedcba9876543210" }},
		{"action", "bind", mappingAction, mappingNonce, func(in *owneracts.MappingInput) { in.ActionID = mappingNonce }},
		{"nonce", "bind", mappingNonce, mappingAction, func(in *owneracts.MappingInput) { in.Nonce = mappingAction }},
		{"iat", "bind", "03:04:05Z", "03:04:06Z", func(in *owneracts.MappingInput) { in.IssuedAt = "2026-01-02T03:04:06Z" }},
		{"exp", "bind", "03:06:05Z", "03:06:04Z", func(in *owneracts.MappingInput) { in.ExpiresAt = "2026-01-02T03:06:04Z" }},
		{"source-room", "bind", `"source_room":"room"`, `"source_room":"room>"`, func(in *owneracts.MappingInput) { in.Arguments.SourceRoom = "room>" }},
		{"source-recipient", "bind", `"source_recipient":"service"`, `"source_recipient":"Service"`, func(in *owneracts.MappingInput) { in.Arguments.SourceRecipient = "Service" }},
		{"owner-recipient", "bind", `"owner_recipient":"owner"`, `"owner_recipient":"Owner"`, func(in *owneracts.MappingInput) { in.Arguments.OwnerRecipient = "Owner" }},
		{"authority", "bind", `"authority_revision":7`, `"authority_revision":8`, func(in *owneracts.MappingInput) { in.Arguments.AuthorityRevision = 8 }},
		{"generation", "bind", `"identity_generation":11`, `"identity_generation":12`, func(in *owneracts.MappingInput) { in.Arguments.IdentityGeneration = 12 }},
		{"binding", "bind", `"binding_revision":0`, `"binding_revision":1`, func(in *owneracts.MappingInput) { in.Arguments.BindingRevision = 1 }},
		{"bound-room", "unbind", `"bound_room":"bound"`, `"bound_room":"bound>"`, func(in *owneracts.MappingInput) { in.Arguments.BoundRoom = "bound>" }},
		{"audience-revision", "mirror-enable", `"audience_revision":13`, `"audience_revision":14`, func(in *owneracts.MappingInput) { in.Arguments.AudienceRevision = 14 }},
		{"audience-digest", "mirror-enable", `"audience_digest":"sha256:` + strings.Repeat("0", 64) + `"`, `"audience_digest":"sha256:` + strings.Repeat("1", 64) + `"`, func(in *owneracts.MappingInput) { in.Arguments.AudienceDigest = "sha256:" + strings.Repeat("1", 64) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := mappingInput("owner-dm." + c.op)
			before := mapped(t, in)
			c.change(&in)
			got := mapped(t, in)
			want := strings.Replace(string(mappingGolden(t, c.op, "render")), c.old, c.next, 1)
			if bytes.Equal([]byte(want), before.Render) || string(got.Render) != want {
				t.Fatalf("field binding must retain exact %s bytes", c.name)
			}
			wantBody := strings.Replace(string(mappingGolden(t, c.op, "body.json")), c.old, c.next, 1)
			wantBody = strings.Replace(wantBody, before.ArgumentsDigest, got.ArgumentsDigest, 1)
			if string(got.Body) != wantBody {
				t.Fatalf("complete body must retain exact %s bytes and derived arguments digest", c.name)
			}
			if bytes.Equal(got.Arguments, before.Arguments) || got.ArgumentsDigest == before.ArgumentsDigest || bytes.Equal(got.Body, before.Body) || got.ContentID == before.ContentID || bytes.Equal(got.SigningPreimage, before.SigningPreimage) {
				t.Fatal("changed D field collapsed a mapping identity")
			}
			mappingEquations(t, in, got)
		})
	}
}

// Printable opaque argument bytes keep case and delimiters, including escaped
// quotes/backslashes. Non-ASCII and line-ending neighbors refuse; this exercises
// typed A0 only, not another external JSON or carrier-text intake route.
func TestMappingOpaqueArgumentIdentity(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range []struct{ value, token string }{
		{"room", `"room"`}, {"Room", `"Room"`}, {"room>", `"room>"`},
		{"room/", `"room/"`}, {"room:", `"room:"`}, {"room!", `"room!"`},
		{"room\"", `"room\""`}, {"room\\", `"room\\"`},
	} {
		in := mappingInput("owner-dm.bind")
		in.Arguments.SourceRoom = c.value
		got := mapped(t, in)
		want := strings.Replace(string(mappingGolden(t, "bind", "render")), `"source_room":"room"`, `"source_room":`+c.token, 1)
		if string(got.Render) != want || seen[got.ContentID] {
			t.Fatal("opaque argument identity was normalized or collapsed")
		}
		seen[got.ContentID] = true
		mappingEquations(t, in, got)
	}
	for _, suffix := range []string{" ", "\r", "\n", "\r\n", "\u0085", "\u2028", "\u2029", "é", "e\u0301", "\x00"} {
		in := mappingInput("owner-dm.bind")
		in.Arguments.SourceRoom += suffix
		mappingReject(t, in, "mapping_invalid")
	}
}

// The operator owner is bounded UTF-8 text, not an ASCII identifier. Valid
// whitespace, controls and Unicode forms remain byte-distinct; no NFC/trim/EOL
// normalization is permitted. This is not carrier/raw received-text validation.
func TestMappingOwnerRawIdentity(t *testing.T) {
	cases := []struct{ value, token string }{
		{" owner", `" owner"`}, {"owner ", `"owner "`}, {"owner\r", `"owner\r"`}, {"owner\n", `"owner\n"`}, {"owner\r\n", `"owner\r\n"`},
		{"owner\u0085", "\"owner\u0085\""}, {"owner\u2028", "\"owner\u2028\""}, {"owner\u2029", "\"owner\u2029\""},
		{"é", "\"é\""}, {"e\u0301", "\"e\u0301\""}, {"owner\x00", `"owner\u0000"`}, {"\"\\", `"\"\\"`},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%x", c.value), func(t *testing.T) {
			in := mappingInput("owner-dm.bind")
			in.Owner = c.value
			got := mapped(t, in)
			want := strings.Replace(string(mappingGolden(t, "bind", "render")), `"owner":"owner"`, `"owner":`+c.token, 1)
			if string(got.Render) != want || !bytes.Contains(got.Body, []byte(`"owner":`+c.token+`,`)) {
				t.Fatal("owner bytes were normalized, escaped differently or dropped")
			}
			if seen[got.ContentID] {
				t.Fatal("distinct accepted owner values collapsed")
			}
			seen[got.ContentID] = true
			mappingEquations(t, in, got)
		})
	}
}

func cloneMapping(v owneracts.Mapping) owneracts.Mapping {
	v.Render = bytes.Clone(v.Render)
	v.Arguments = bytes.Clone(v.Arguments)
	v.Body = bytes.Clone(v.Body)
	v.SigningPreimage = bytes.Clone(v.SigningPreimage)
	return v
}

// Separate output buffers and invocations are independent. Ordinary struct
// copies still follow Go slice semantics; this does not promise immutable plans.
func TestMappingOutputOwnership(t *testing.T) {
	in := mappingInput("owner-dm.mirror-enable")
	before := in
	original := mapped(t, in)
	snapshot := cloneMapping(original)
	for i := 0; i < 4; i++ {
		got := mapped(t, in)
		buffers := [][]byte{got.Render, got.Arguments, got.Body, got.SigningPreimage}
		buffers[i][0] ^= 0xff
		for j, other := range [][]byte{snapshot.Render, snapshot.Arguments, snapshot.Body, snapshot.SigningPreimage} {
			if i != j && !bytes.Equal(buffers[j], other) {
				t.Fatal("mutating one output changed another")
			}
		}
		if !reflect.DeepEqual(mapped(t, in), snapshot) || !reflect.DeepEqual(original, snapshot) {
			t.Fatal("output mutation changed another invocation")
		}
	}
	in.Owner = "changed"
	in.Arguments.SourceRoom = "changed"
	mapped(t, in)
	if !reflect.DeepEqual(original, snapshot) || !reflect.DeepEqual(mapped(t, before), snapshot) {
		t.Fatal("later input/invocation changed earlier outputs")
	}
}
