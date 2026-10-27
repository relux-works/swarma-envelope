package owneracts_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
)

// A fixture writer for the fixed12-field body, not a validator. Every expected
// value is set independently below; no key, A, signature or current fact is used.
func reviewBodyWire(b owneracts.Body) []byte {
	q := reviewBodyQuote
	return []byte(fmt.Sprintf(`{"action_id":%s,"arguments_digest":%s,"aud":%s,"confirmed":%t,"epoch":%s,"exp":%s,"iat":%s,"nonce":%s,"operation":%s,"owner":%s,"target":{"id":%s,"kind":%s},"type":%s}`,
		q(b.ActionID), q(b.ArgumentsDigest), q(b.Audience), b.Confirmed, q(b.Epoch), q(b.ExpiresAt), q(b.IssuedAt), q(b.Nonce), q(b.Operation), q(b.Owner), q(b.Identity), q(b.TargetKind), q(b.Type)))
}

// Every variable field changes independently; all returned fields equal the
// literal expectation before and after input overwrite, an error, a subsequent
// call and ordinary result-copy assignment. No unsafe concurrent mutation claim.
func TestReviewBodyHuntScalarsAndOwnership(t *testing.T) {
	if string(reviewBodyWire(reviewBodyExpected())) != reviewBodyLiteral {
		t.Fatal("independent fixture writer differs from literal")
	}
	cases := []struct {
		name string
		set  func(*owneracts.Body)
	}{
		{"action", func(b *owneracts.Body) { b.ActionID = "AAAAAAAAAAAAAAAAAAAAAQ" }},
		{"nonce", func(b *owneracts.Body) { b.Nonce = "_____________________g" }},
		{"digest", func(b *owneracts.Body) { b.ArgumentsDigest = "sha256:" + strings.Repeat("f", 64) }},
		{"audience", func(b *owneracts.Body) { b.Audience = "owner-acts:" + strings.Repeat("0", 32) }},
		{"epoch", func(b *owneracts.Body) { b.Epoch = "epoch:" + strings.Repeat("f", 32) }},
		{"confirmed", func(b *owneracts.Body) { b.Confirmed = false }},
		{"iat", func(b *owneracts.Body) { b.IssuedAt = "2000-02-29T23:58:00Z" }},
		{"exp", func(b *owneracts.Body) { b.ExpiresAt = "2000-03-01T00:01:59Z" }},
		{"operation", func(b *owneracts.Body) { b.Operation = "owner-dm.mirror-enable" }},
		{"identity", func(b *owneracts.Body) { b.Identity = "0-" }},
		{"owner", func(b *owneracts.Body) { b.Owner = "\x00\ufeffA\u030a\r\n " }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := reviewBodyExpected()
			tc.set(&want)
			raw := reviewBodyWire(want)
			got := reviewBodyOK(t, raw, want)
			other := reviewBodyOK(t, raw, want)
			for i := range raw {
				raw[i] = 0xff
			}
			reviewBodyNo(t, raw, "body_invalid")
			copyValue := got
			copyValue = owneracts.Body{Owner: "replacement"}
			if got != want || other != want || copyValue == got {
				t.Fatal("later call, overwrite or assignment changed another result")
			}
		})
	}
}

// Compound inputs expose each documented priority boundary. Codec malformed,
// noncanonical, wrong members and unsupported string operations stay distinct;
// malformed inputs never yield partial or availability/authority-shaped data.
func TestReviewBodyHuntOrder(t *testing.T) {
	unknown := strings.Replace(reviewBodyLiteral, "owner-dm.unbind", "host.change", 1)
	badFields := strings.Replace(unknown, `"target":{"id":"9-review","kind":"owner-dm"}`, `"target":null`, 1)
	for _, tc := range []struct{ name, raw, code string }{
		{"unsupported-before-target", badFields, "body_operation_unsupported"},
		{"canonical-before-operation", " " + badFields, "body_noncanonical"},
		{"members-before-operation", strings.Replace(badFields, `"epoch":`, `"current":true,"epoch":`, 1), "body_invalid"},
		{"noncanonical-before-members", " " + strings.Replace(badFields, `"epoch":`, `"current":true,"epoch":`, 1), "body_noncanonical"},
		{"duplicate-before-canonical", " " + strings.Replace(badFields, `"nonce":`, `"nonce":null,"nonce":`, 1), "body_invalid"},
		{"number-before-operation", strings.Replace(badFields, `"confirmed":true`, `"confirmed":9007199254740992`, 1), "body_invalid"},
		{"operation-type", strings.Replace(badFields, `"operation":"host.change"`, `"operation":false`, 1), "body_invalid"},
		{"known-operation-invalid-target", strings.Replace(badFields, "host.change", "owner-dm.unbind", 1), "body_invalid"},
		{"noncanonical-scalar", " true", "body_noncanonical"},
		{"canonical-scalar", "true", "body_invalid"},
		{"unsupported-string", strings.Replace(unknown, `"owner":"reviewer"`, `"owner":""`, 1), "body_operation_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) { reviewBodyNo(t, []byte(tc.raw), tc.code) })
	}
	reviewBodyNo(t, bytes.Repeat([]byte{0xff}, 8193), "body_too_large")
	// No envelope or selected-profile/currentness wrapper can be a local body.
	for _, name := range []string{"profile", "selected_profile", "current", "key", "body", "signatures", "preimage", "arguments"} {
		reviewBodyNo(t, []byte(`{"`+name+`":`+reviewBodyLiteral+`}`), "body_invalid")
	}
}

// Sixteen-byte base64 has four unused pad bits in its final character:
// only alphabet positions0,16,32,48 are canonical. Both independent fields are
// exercised at every position. Dates probe leap-century/2038 and interval edges;
// these are syntax controls, not qualified time, randomness or uniqueness.
func TestReviewBodyHuntMetadataEdges(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, field := range []string{"nonce", "action_id"} {
		for i := range len(alphabet) {
			want := reviewBodyExpected()
			s := strings.Repeat("A", 21) + string(alphabet[i])
			if field == "nonce" {
				want.Nonce = s
			} else {
				want.ActionID = s
			}
			if i%16 == 0 {
				reviewBodyOK(t, reviewBodyWire(want), want)
			} else {
				reviewBodyNo(t, reviewBodyWire(want), "body_invalid")
			}
		}
	}
	for _, pair := range [][2]string{
		{"2038-01-19T03:14:07Z", "2038-01-19T03:14:08Z"},
		{"2100-02-28T23:59:59Z", "2100-03-01T00:01:59Z"},
		{"2400-02-29T23:59:59Z", "2400-03-01T00:00:00Z"},
	} {
		want := reviewBodyExpected()
		want.IssuedAt, want.ExpiresAt = pair[0], pair[1]
		reviewBodyOK(t, reviewBodyWire(want), want)
	}
	for _, pair := range [][2]string{
		{"2100-02-29T23:59:59Z", "2100-03-01T00:00:00Z"},
		{"2000-02-29T23:59:59Z", "2000-02-29T23:59:59Z"},
		{"2000-03-01T00:00:00Z", "2000-02-29T23:59:59Z"},
		{"2000-02-29T23:59:59Z", "2000-03-01T00:02:00Z"},
	} {
		want := reviewBodyExpected()
		want.IssuedAt, want.ExpiresAt = pair[0], pair[1]
		reviewBodyNo(t, reviewBodyWire(want), "body_invalid")
	}
}
