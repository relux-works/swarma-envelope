package cryptocheck

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestScopeStrictPointsAndOwnedInputs(t *testing.T) {
	base := append([]byte{0x58}, bytes.Repeat([]byte{0x66}, 31)...)
	mixed := append([]byte{0x95}, bytes.Repeat([]byte{0x99}, 31)...)
	identity := make([]byte, 32)
	identity[0] = 1
	negativeZero := append([]byte(nil), identity...)
	negativeZero[31] = 128
	noncanonical := bytes.Repeat([]byte{255}, 32)
	noncanonical[0] = 237
	noncanonical[31] = 127
	s := new(Scope)
	for _, tc := range []struct {
		name  string
		point []byte
		valid bool
	}{
		{"base", base, true}, {"mixed", mixed, false}, {"identity", identity, false},
		{"small", make([]byte, 32), false}, {"negative-zero", negativeZero, false},
		{"noncanonical", noncanonical, false}, {"short", base[:31], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(s.points)
			for i := 0; i < 2; i++ {
				if got := s.point(tc.point); got != tc.valid {
					t.Fatalf("got %v want %v", got, tc.valid)
				}
			}
			if !tc.valid && len(s.points) != before {
				t.Fatal("invalid point retained")
			}
		})
	}
	mutable := append([]byte(nil), base...)
	if !s.point(mutable) {
		t.Fatal("valid")
	}
	copy(mutable, mixed)
	if s.point(mutable) {
		t.Fatal("changed backing bytes reused")
	}
	if len(new(Scope).points) != 0 {
		t.Fatal("new scope not empty")
	}
	full := &Scope{points: map[[32]byte]struct{}{}}
	for i := 0; i < pointLimit; i++ {
		var k [32]byte
		k[0] = byte(i)
		full.points[k] = struct{}{}
	}
	if !full.point(base) || full.point(mixed) || len(full.points) != pointLimit {
		t.Fatal("bounded fallback")
	}
}

func TestScopeSignatureChangesStillCheckEquation(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pub := private.Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
	msg := []byte("pure validation reuse")
	sig := ed25519.Sign(private, msg)
	s := new(Scope)
	if ValidateKey("ed25519", pub, s) != "" || VerifySignature("ed25519", pub, sig, msg, s) != "" {
		t.Fatal("valid control")
	}
	scalar := append([]byte(nil), sig...)
	scalar[32] ^= 1
	high := append([]byte(nil), sig...)
	for i := 32; i < 64; i++ {
		high[i] = 255
	}
	badR := append([]byte(nil), sig...)
	copy(badR[:32], make([]byte, 32))
	for _, tc := range []struct {
		name          string
		pub, sig, msg []byte
	}{
		{"unchanged", pub, sig, msg}, {"message", pub, sig, []byte("changed")},
		{"key", other, sig, msg}, {"scalar", pub, scalar, msg}, {"high-scalar", pub, high, msg},
		{"R", pub, badR, msg}, {"short", pub, sig[:63], msg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifySignature("ed25519", tc.pub, tc.sig, tc.msg, s)
			want := VerifySignature("ed25519", tc.pub, tc.sig, tc.msg, nil)
			if got != want || (got == "") != (tc.name == "unchanged") {
				t.Fatalf("scoped=%q uncached=%q", got, want)
			}
		})
	}
}
