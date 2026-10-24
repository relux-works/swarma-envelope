package record_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/relux-works/waggle/record"
)

// The Edwards base point is prime order. Adding (0,-1), the nontrivial
// order-two point, yields the canonical mixed-order point encoded below.
// Rejecting both identically would fail the adjacent valid control.
func TestMixedOrderPoint(t *testing.T) {
	base := append([]byte{0x58}, bytes.Repeat([]byte{0x66}, 31)...)
	mixed := append([]byte{0x95}, bytes.Repeat([]byte{0x99}, 31)...)
	key := func(b []byte) string { return "ed25519:" + base64.RawURLEncoding.EncodeToString(b) }
	if e := record.ValidateKey(key(base)); e != nil {
		t.Fatal(e)
	}
	if refusalCode(record.ValidateKey(key(mixed))) != "envelope_signature_invalid" {
		t.Fatal("mixed-order point admitted")
	}
}

// Raw P-256 low-S succeeds; its equivalent high-S twin, zero scalar and
// uncompressed key refuse with the intended classifications. DER is not raw.
func TestStrictP256(t *testing.T) {
	curve := elliptic.P256()
	d := big.NewInt(7)
	x, y := curve.ScalarBaseMult(d.Bytes())
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	key := "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(curve, x, y))
	msg := []byte("raw P-256 control")
	h := sha256.Sum256(msg)
	r, s, e := ecdsa.Sign(rand.Reader, private, h[:])
	if e != nil {
		t.Fatal(e)
	}
	n := curve.Params().N
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s.Cmp(half) > 0 {
		s.Sub(n, s)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if e := record.VerifySignature(key, sig, msg); e != nil {
		t.Fatal(e)
	}
	high := append([]byte(nil), sig...)
	new(big.Int).Sub(n, s).FillBytes(high[32:])
	if refusalCode(record.VerifySignature(key, high, msg)) != "signature_high_s" {
		t.Fatal("high-S twin admitted")
	}
	zero := make([]byte, 64)
	if refusalCode(record.VerifySignature(key, zero, msg)) != "envelope_signature_invalid" {
		t.Fatal("zero scalar admitted")
	}
	uncompressed := "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.Marshal(curve, x, y))
	if refusalCode(record.ValidateKey(uncompressed)) != "envelope_malformed" {
		t.Fatal("uncompressed key admitted")
	}
	der, e := ecdsa.SignASN1(rand.Reader, private, h[:])
	if e != nil {
		t.Fatal(e)
	}
	if e = record.VerifySignature(key, der, msg); e == nil {
		t.Fatal("DER admitted")
	}
}
