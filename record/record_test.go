package record_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/relux-works/waggle/record"
)

func refusalCode(e error) string {
	if e == nil {
		return "accept"
	}
	r, ok := e.(*record.Error)
	if !ok {
		return "unexpected error"
	}
	return r.Code
}

// A received-size violation is refused before parsing/copying; the allocation
// count covers the error object, not the caller's already allocated input.
func TestParseSizeBeforeAllocation(t *testing.T) {
	raw := bytes.Repeat([]byte{'x'}, 65537)
	allocs := testing.AllocsPerRun(20, func() {
		_, err := record.Parse(raw, 65536, 16)
		if refusalCode(err) != "envelope_too_large" {
			t.Fatal(err)
		}
	})
	if allocs > 1 {
		t.Fatalf("oversize allocations %.0f", allocs)
	}
	if _, e := record.Parse([]byte(`{"a":1}`), 65536, 16); e != nil {
		t.Fatal(e)
	}
}

// Structural controls prove duplicate/Unicode/number/container limits while
// a nearby valid document remains admitted. This is bounded parser coverage.
func TestStrictParse(t *testing.T) {
	for _, raw := range []string{`{"a":1,"\u0061":2}`, `{"a":-0}`, `{"a":1.0}`, `{"a":"\ud800"}`, strings.Repeat("[", 17) + strings.Repeat("]", 17), "[" + strings.Repeat("0,", 64) + "0]", `"` + strings.Repeat("a", 8193) + `"`} {
		if _, e := record.Parse([]byte(raw), 65536, 16); refusalCode(e) != "envelope_malformed" {
			t.Errorf("input length%d: %v", len(raw), e)
		}
	}
	if _, e := record.Parse([]byte("["+strings.Repeat("0,", 63)+"0]"), 65536, 16); e != nil {
		t.Fatal(e)
	}
}

// Known public-key lengths are rejected without decoding an oversized string.
func TestKeySizeBeforeAllocation(t *testing.T) {
	key := "ed25519:" + strings.Repeat("A", 1<<20)
	n := testing.AllocsPerRun(10, func() {
		_, _, e := record.KeyBytes(key)
		if refusalCode(e) != "envelope_malformed" {
			t.Fatal(e)
		}
	})
	if n > 1 {
		t.Fatalf("oversize key allocations %.0f", n)
	}
}

// Ordinary signatures are accepted; scalar, noncanonical and torsion controls
// are refused even where equation-only verification might be permissive.
func TestStrictEd25519(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	key := "ed25519:" + base64.RawURLEncoding.EncodeToString(public)
	msg := []byte("strict signature control")
	sig := ed25519.Sign(private, msg)
	if e := record.VerifySignature(key, sig, msg); e != nil {
		t.Fatal(e)
	}
	badS := append([]byte(nil), sig...)
	for i := 32; i < 64; i++ {
		badS[i] = 255
	}
	if refusalCode(record.VerifySignature(key, badS, msg)) != "envelope_signature_invalid" {
		t.Fatal("noncanonical scalar")
	}
	for _, point := range [][]byte{append([]byte{1}, make([]byte, 31)...), make([]byte, 32), bytes.Repeat([]byte{255}, 32)} {
		k := "ed25519:" + base64.RawURLEncoding.EncodeToString(point)
		if refusalCode(record.ValidateKey(k)) != "envelope_signature_invalid" {
			t.Fatal("invalid point admitted")
		}
		r := append([]byte(nil), sig...)
		copy(r[:32], point)
		if refusalCode(record.VerifySignature(key, r, msg)) != "envelope_signature_invalid" {
			t.Fatal("invalid R admitted")
		}
	}
	if e := record.VerifySignature(key, sig, append(msg, '!')); refusalCode(e) != "envelope_signature_invalid" {
		t.Fatal("wrong message admitted")
	}
}

// Size and tag decisions precede payload/identity; an unavailable identity
// policy cannot silently disable narrowing on a multi-agent provider.
func TestSignerOrderedRefusals(t *testing.T) {
	for _, tc := range []struct {
		raw  []byte
		p    record.IdentityPolicy
		code string
	}{{bytes.Repeat([]byte{'x'}, 24577), record.IdentityPolicy{}, "signer_preimage_too_large"}, {[]byte("bad"), record.IdentityPolicy{}, "signer_tag_malformed"}, {[]byte("swarma-msg/20\n{}"), record.IdentityPolicy{}, "signer_domain_refused"}, {[]byte("swarma-msg/2\n{ }"), record.IdentityPolicy{}, "signer_payload_invalid"}, {[]byte("swarma-msg/2\n{}"), record.IdentityPolicy{MultiAgent: true}, "signer_identity_unavailable"}, {[]byte("swarma-msg/2\n{}"), record.IdentityPolicy{Invalid: true}, "signer_identity_unavailable"}} {
		a, e := record.AdmitSigner(tc.raw, tc.p)
		if refusalCode(e) != tc.code || a != (record.SignerAdmission{}) {
			t.Errorf("got%+v,%v want%s", a, e, tc.code)
		}
	}
	if _, e := record.AdmitSigner([]byte("swarma-msg/2\n{}"), record.IdentityPolicy{}); e != nil {
		t.Fatal(e)
	}
}

// The parser must return or refuse without panic for bounded arbitrary bytes.
// Fuzzing is a smoke test, not an exhaustive parser/crypto proof.
func FuzzParse(f *testing.F) {
	for _, b := range [][]byte{nil, []byte(`{}`), []byte(`{"a":1,"a":2}`), {255}, bytes.Repeat([]byte{'['}, 17)} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, e := record.Parse(b, 65536, 16)
		if e == nil {
			if _, e = record.Canonical(v); e != nil {
				t.Fatal(e)
			}
		}
	})
}
