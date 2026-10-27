package owneracts_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
)

// Static operation selection refuses aliases/reserved/legacy names with no
// profile fallback. Non-string operation or nonclosed shape is invalid earlier.
func TestBodyClosedOperations(t *testing.T) {
	for _, op := range []string{"", "revoke", "grant.issue", "launch.approve", "host.change", "owner-dm.BIND", "owner-dm.bind ", "owner-dm/bind", "owner-dm.bind\x00", strings.Repeat("x", 1000)} {
		m := bodyObject(t)
		m["operation"] = op
		bodyReject(t, bodyCanonical(t, m), "body_operation_unsupported")
	}
	m := bodyObject(t)
	m["operation"], m["key"] = "revoke", "untrusted"
	bodyReject(t, bodyCanonical(t, m), "body_invalid")
	bodyReject(t, []byte(" "+strings.Replace(bodyLiteral, "owner-dm.bind", "revoke", 1)), "body_noncanonical")
}

// Exact namespaces, NAME, content-ID and canonical 16-byte base64url constrain
// otherwise valid bodies. No key/arguments/currentness dependency is fabricated.
func TestBodyMetadataGrammar(t *testing.T) {
	for field, values := range map[string][]string{
		"type":             {"", "operator-act/2", "grant/1", "operator-act/1 ", "OPERATOR-act/1"},
		"aud":              {"", "owner-acts:", "epoch:" + strings.Repeat("0", 32), "owner-acts:" + strings.Repeat("0", 31), "owner-acts:" + strings.Repeat("0", 33), "owner-acts:" + strings.Repeat("A", 32), "owner-acts:" + strings.Repeat("g", 32), " owner-acts:" + strings.Repeat("0", 32)},
		"epoch":            {"", "epoch:", "owner-acts:" + strings.Repeat("0", 32), "epoch:" + strings.Repeat("0", 31), "epoch:" + strings.Repeat("0", 33), "epoch:" + strings.Repeat("F", 32), "epoch:" + strings.Repeat("g", 32), "epoch:" + strings.Repeat("0", 32) + "\n"},
		"arguments_digest": {"", strings.Repeat("0", 64), "sha256:" + strings.Repeat("0", 63), "sha256:" + strings.Repeat("0", 65), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64), "SHA256:" + strings.Repeat("0", 64), "sha256:" + strings.Repeat("0", 64) + "\n"},
		"owner":            {""},
	} {
		for i, value := range values {
			t.Run(fmt.Sprintf("%s/%d", field, i), func(t *testing.T) {
				m := bodyObject(t)
				m[field] = value
				bodyReject(t, bodyCanonical(t, m), "body_invalid")
			})
		}
	}
	for _, field := range []string{"nonce", "action_id"} {
		for _, s := range []string{"", "AA", "AAECAwQFBgcICQoLDA0ODw=", "AAECAwQFBgcICQoLDA0ODx", "AAECAwQFBgcICQoLDA0OD/", "AAECAwQFBgcICQoLDA0OD+", "AAECAwQFBgcICQoLDA0ODw\n", strings.Repeat("A", 21), strings.Repeat("A", 23)} {
			m := bodyObject(t)
			m[field] = s
			bodyReject(t, bodyCanonical(t, m), "body_invalid")
		}
	}
	for _, name := range []string{"", "-a", "A", "a_", "a/", "a.", "*", "a*", "a ", " a", "a\n", "é", strings.Repeat("a", 64)} {
		m := bodyObject(t)
		m["target"].(map[string]any)["id"] = name
		bodyReject(t, bodyCanonical(t, m), "body_invalid")
	}
	for _, kind := range []string{"", "Owner-dm", "registration", "account", "launch", "host-assignment", "owner-dm "} {
		m := bodyObject(t)
		m["target"].(map[string]any)["kind"] = kind
		bodyReject(t, bodyCanonical(t, m), "body_invalid")
	}
	for _, name := range []string{"a", "0", "a-", "a--0", strings.Repeat("a", 62), strings.Repeat("z", 63)} {
		want := bodyExpected()
		want.Identity = name
		m := bodyObject(t)
		m["target"].(map[string]any)["id"] = name
		bodyAccept(t, bodyCanonical(t, m), want)
	}
	// Distinct valid values independently fix every variable scalar expectation.
	want := bodyExpected()
	want.Audience = "owner-acts:" + strings.Repeat("f", 32)
	want.Epoch = "epoch:" + strings.Repeat("0", 32)
	want.ActionID, want.Nonce = "_____________________w", "---------------------w"
	want.ArgumentsDigest = "sha256:" + strings.Repeat("f", 64)
	m := bodyObject(t)
	m["aud"], m["epoch"], m["action_id"], m["nonce"], m["arguments_digest"] = want.Audience, want.Epoch, want.ActionID, want.Nonce, want.ArgumentsDigest
	bodyAccept(t, bodyCanonical(t, m), want)
}

// Original UTC-second spelling and calendar values, years1970..9999, positive
// intervals1..120s, leap/year/day boundaries are syntax only, never trusted time.
func TestBodyTimeGrammar(t *testing.T) {
	for _, pair := range [][2]string{
		{"1970-01-01T00:00:00Z", "1970-01-01T00:00:01Z"},
		{"9999-12-31T23:57:59Z", "9999-12-31T23:59:59Z"},
		{"2000-02-29T23:59:59Z", "2000-03-01T00:01:59Z"},
		{"2025-12-31T23:59:59Z", "2026-01-01T00:01:58Z"},
	} {
		want := bodyExpected()
		want.IssuedAt, want.ExpiresAt = pair[0], pair[1]
		m := bodyObject(t)
		m["iat"], m["exp"] = pair[0], pair[1]
		bodyAccept(t, bodyCanonical(t, m), want)
	}
	for _, field := range []string{"iat", "exp"} {
		for _, s := range []string{"", "1969-12-31T23:59:59Z", "0000-01-01T00:00:00Z", "10000-01-01T00:00:00Z", "2026-02-29T03:04:05Z", "1900-02-29T03:04:05Z", "2026-04-31T03:04:05Z", "2026-00-02T03:04:05Z", "2026-13-02T03:04:05Z", "2026-01-00T03:04:05Z", "2026-01-02T24:04:05Z", "2026-01-02T03:60:05Z", "2026-01-02T03:04:60Z", "2026-1-02T03:04:05Z", "2026-01-02T3:04:05Z", "2026-01-02t03:04:05Z", "2026-01-02T03:04:05z", "2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05.0Z", "2026-01-02T03:04:05Z\n"} {
			m := bodyObject(t)
			m[field] = s
			bodyReject(t, bodyCanonical(t, m), "body_invalid")
		}
	}
	for _, exp := range []string{"2026-01-02T03:04:05Z", "2026-01-02T03:04:04Z", "2026-01-02T03:06:06Z", "9999-12-31T23:59:59Z"} {
		m := bodyObject(t)
		m["exp"] = exp
		bodyReject(t, bodyCanonical(t, m), "body_invalid")
	}
}

// Every retained value survives caller-buffer reuse and independent calls;
// assigning an ordinary result/copy changes only that value, not input/others.
func TestBodyOwnership(t *testing.T) {
	raw := []byte(bodyLiteral)
	want := bodyExpected()
	first := bodyAccept(t, raw, want)
	second := bodyAccept(t, raw, want)
	copyValue := first
	copyValue.Owner, copyValue.Identity, copyValue.Confirmed = "changed", "other", true
	if first != want || second != want || string(raw) != bodyLiteral || copyValue == first {
		t.Fatal("result copies not independent")
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if first != want || second != want {
		t.Fatal("input reuse changed returned data")
	}
	bodyReject(t, raw, "body_invalid")
	bodyAccept(t, []byte(bodyLiteral), want)
	if first != want || second != want {
		t.Fatal("later calls changed prior data")
	}
	// Cover all fields in a modified copy; no mutable collections exist in Body.
	copyValue = owneracts.Body{}
	if first != want || copyValue == first {
		t.Fatal("zeroing copy changed result")
	}
}
