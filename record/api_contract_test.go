package record_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
)

// Codec primitives bind exactly their advertised byte/domain fields. They
// intentionally confer no schema, key provenance or authority admission.
// Unknown domains, unsupported CCJ values and noncanonical encodings refuse.
func TestCodecPrimitiveContracts(t *testing.T) {
	body := map[string]any{"z": int64(1), "a": true}
	b, err := record.Canonical(body)
	if err != nil || string(b) != `{"a":true,"z":1}` {
		t.Fatal(string(b), err)
	}
	if _, err := record.Canonical(map[string]any{"x": 1.5}); refusalCode(err) != "envelope_malformed" {
		t.Fatal(err)
	}
	if got := record.Digest([]byte("abc")); got != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal(got)
	}
	id, err := record.ContentID("message/1", body)
	want := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("swarma-msg/2\n"+string(b))))
	if err != nil || id != want {
		t.Fatal(id, err)
	}
	pre, err := record.SigningPreimage("message/1", "key-control", "author", body)
	if err != nil || string(pre) != "swarma-msg/2\n"+`{"body":{"a":true,"z":1},"key":"key-control","role":"author","version":"swarm-envelope/2"}` {
		t.Fatal(string(pre), err)
	}
	if id, err := record.ContentID("unknown", body); id != "" || refusalCode(err) != "envelope_type_mismatch" {
		t.Fatal(id, err)
	}
	if pre, err := record.SigningPreimage("unknown", "key-control", "author", body); pre != nil || refusalCode(err) != "envelope_type_mismatch" {
		t.Fatal(pre, err)
	}
	if pre, err := record.SigningPreimage("message/1", "key-control", "author", map[string]any{"bad": 1.5}); pre != nil || refusalCode(err) != "envelope_malformed" {
		t.Fatal(pre, err)
	}
	if got, err := record.DecodeBase64("AQ", 1); err != nil || !bytes.Equal(got, []byte{1}) {
		t.Fatal(got, err)
	}
	for _, s := range []string{"AQ=", "AR", "+w", "AQAA"} {
		if got, err := record.DecodeBase64(s, 1); got != nil || refusalCode(err) != "envelope_malformed" {
			t.Fatal(got, err)
		}
	}
	if !record.IsContentID(want) || record.IsContentID(want+"0") || record.IsContentID("sha256:BA"+want[9:]) {
		t.Fatal("content-id alphabet")
	}
	for _, kind := range []string{"message/1", "grant/1", "operator-act/1", "attestation/1", "revocation/1"} {
		if !record.Registered(record.Tag(kind)) {
			t.Fatal(kind)
		}
	}
	if record.Tag("unknown") != "" || record.Registered("swarma-msg/20") || record.Registered("swarma-msg/2 ") {
		t.Fatal("registry widened")
	}
	e := &record.Error{Code: "control"}
	if e.Error() != e.Code {
		t.Fatal(e)
	}
}

// Domain-only verification requires the exact registered tag, canonical record
// and strict signature, with a valid neighbor. It deliberately does not admit
// envelope schemas or external issuer authority.
func TestCheckDomainContract(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, 32))
	key := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	raw := []byte("swarma-msg/2\n{}")
	sig := ed25519.Sign(private, raw)
	if err := record.CheckDomain(raw, "swarma-msg/2", key, sig); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		raw            []byte
		expected, code string
	}{
		{raw, "unknown", "domain_unknown"},
		{raw, "swarma-waggle grant/1", "domain_mismatch"},
		{[]byte("swarma-msg/2\n{ }"), "swarma-msg/2", "envelope_malformed"},
		{[]byte("swarma-msg/2\n[]"), "swarma-msg/2", "envelope_signature_invalid"},
	} {
		if err := record.CheckDomain(tc.raw, tc.expected, key, sig); refusalCode(err) != tc.code {
			t.Fatal(err, "want", tc.code)
		}
	}
}
