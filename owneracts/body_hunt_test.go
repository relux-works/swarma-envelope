package owneracts_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
)

// Separate post-sweep hunt: each supported operation requires the same exact
// target; legacy/reserved spellings cannot escape into another preparation path.
func TestBodyHuntOperationTarget(t *testing.T) {
	for _, op := range []string{"owner-dm.bind", "owner-dm.unbind", "owner-dm.mirror-enable"} {
		for _, target := range []any{
			map[string]any{"kind": "registration", "id": int64(1)},
			map[string]any{"kind": "account", "id": "identity"},
			map[string]any{"kind": "owner-dm", "id": "identity", "profile": "owner-acts/1"},
			map[string]any{"kind": "owner-dm", "id": "identity/*"},
		} {
			m := bodyObject(t)
			m["operation"], m["target"] = op, target
			bodyReject(t, bodyCanonical(t, m), "body_invalid")
		}
		m := bodyObject(t)
		m["operation"] = op
		want := bodyExpected()
		want.Operation = op
		bodyAccept(t, bodyCanonical(t, m), want)
	}
	for _, op := range []string{"revoke", "grant.issue", "launch.approve", "host.change"} {
		m := bodyObject(t)
		m["operation"], m["target"] = op, map[string]any{"kind": "registration", "id": int64(1)}
		bodyReject(t, bodyCanonical(t, m), "body_operation_unsupported")
	}
}

// The unsigned body is not an envelope, signed-record preimage or arguments
// object. No available/unavailable protected facts are requested or invented.
func TestBodyHuntShapeConfusion(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"body":` + bodyLiteral + `,"key":"untrusted","role":"approver","version":"swarm-envelope/2"}`),
		[]byte("swarma-waggle operator-act/1\n" + bodyLiteral),
		mappingGolden(t, "bind", "arguments.json"),
		mappingGolden(t, "bind", "preimage"),
		mappingGolden(t, "bind", "render"),
	} {
		bodyReject(t, raw, "body_invalid")
	}
	// An arbitrary but syntactically valid digest stays data: no fake A is used.
	m := bodyObject(t)
	m["arguments_digest"] = "sha256:" + strings.Repeat("1", 64)
	m["confirmed"] = true
	want := bodyExpected()
	want.ArgumentsDigest, want.Confirmed = m["arguments_digest"].(string), true
	bodyAccept(t, bodyCanonical(t, m), want)
}

// Compatibility uses actual complete mapper outputs and the preexisting fixed
// body/hash fixtures, not a fake key/envelope to validate the parser. These are
// additional integration controls; literal grammar expectations are independent.
func TestBodyHuntMapperCompatibility(t *testing.T) {
	for _, name := range []string{"bind", "unbind", "mirror-enable"} {
		in := mappingInput("owner-dm." + name)
		got := mapped(t, in)
		if !bytes.Equal(got.Body, mappingGolden(t, name, "body.json")) {
			t.Fatal("published mapping body fixture drift")
		}
		want := bodyExpected()
		want.Operation = in.Operation
		want.ArgumentsDigest = strings.Split(string(mappingGolden(t, name, "hashes.txt")), "\n")[1]
		bodyAccept(t, got.Body, want)
		in.Owner = ""
		mappingReject(t, in, "mapping_invalid")
		bodyReject(t, bodyOwner(`""`), "body_invalid")
	}
	// Shared private helper contracts stay identical on boundary owner/time/NAME.
	in := mappingInput("owner-dm.bind")
	in.Owner, in.Identity = "e\u0301\x00\r\n", strings.Repeat("a", 63)
	in.IssuedAt, in.ExpiresAt = "1970-01-01T00:00:00Z", "1970-01-01T00:02:00Z"
	got := mapped(t, in)
	want := bodyExpected()
	want.Owner, want.Identity, want.IssuedAt, want.ExpiresAt, want.ArgumentsDigest = in.Owner, in.Identity, in.IssuedAt, in.ExpiresAt, got.ArgumentsDigest
	bodyAccept(t, got.Body, want)
	in.ExpiresAt = "1970-01-01T00:02:01Z"
	mappingReject(t, in, "mapping_invalid")
}

// Strict local intake must not tighten the record parser's existing received
// transport. Both transport variants decode to the exact literal body values.
// Signed verifier E/O/current-/2/rights preservation runs in its existing tests.
func TestBodyHuntTransportSeparation(t *testing.T) {
	for _, raw := range [][]byte{
		append(append([]byte(" \r\n"), []byte(bodyLiteral)...), '\t'),
		bodyOwner(`"\u006fwner"`),
	} {
		v, err := record.Parse(raw, 8192, 16)
		if err != nil {
			t.Fatal("old transport unexpectedly tightened", err)
		}
		if canonical := bodyCanonical(t, v); string(canonical) != bodyLiteral {
			t.Fatal("old parser changed decoded values")
		}
		bodyReject(t, raw, "body_noncanonical")
	}
}

// Failure priority is deterministic: size, codec, canonical comparison, closed
// members, operation, then field values. No earlier failure returns partial data.
func TestBodyHuntRefusalOrder(t *testing.T) {
	raw := strings.Replace(bodyLiteral, "owner-dm.bind", "revoke", 1)
	raw = strings.Replace(raw, `"owner":"owner"`, `"owner":""`, 1)
	bodyReject(t, []byte(raw), "body_operation_unsupported")
	bodyReject(t, []byte(" "+raw), "body_noncanonical")
	bodyReject(t, []byte(strings.Replace(raw, `"owner":""`, `"owner":"","owner":""`, 1)), "body_invalid")
	bodyReject(t, []byte(strings.Replace(raw, `"iat":`, `"extra":true,"iat":`, 1)), "body_invalid")
	bodyReject(t, []byte(raw+strings.Repeat(" ", 8193-len(raw))), "body_too_large")
	// Malformed/deep/array values stay invalid even when another field is valid.
	for _, token := range []string{strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17), "[" + strings.TrimSuffix(strings.Repeat("0,", 65), ",") + "]"} {
		bodyReject(t, bodyOwner(token), "body_invalid")
	}
}
