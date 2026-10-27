package verifier

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
	"testing"
)

// Representation-only scalar fixtures are NOT equation witnesses or signed
// acts. They pin fixed32 leading zeros, signs, range, low-S and exact72 capacity.
func TestNativeP256ScalarRepresentation(t *testing.T) {
	n := elliptic.P256().Params().N
	for _, r := range []*big.Int{big.NewInt(1), big.NewInt(127), big.NewInt(128), new(big.Int).Sub(n, big.NewInt(1))} {
		for _, s := range []*big.Int{big.NewInt(1), big.NewInt(127), big.NewInt(128), new(big.Int).Sub(n, big.NewInt(1))} {
			der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
			if err != nil {
				t.Fatal(err)
			}
			raw, ok := ownerActNativeP256(der)
			if !ok {
				t.Fatal("valid scalar representation refused")
			}
			want := make([]byte, 64)
			r.FillBytes(want[:32])
			low := new(big.Int).Set(s)
			twin := new(big.Int).Sub(n, s)
			if twin.Cmp(low) < 0 {
				low = twin
			}
			low.FillBytes(want[32:])
			if !bytes.Equal(raw[:], want) {
				t.Fatal("fixed32 scalar representation differs")
			}
			if r.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 && s.Cmp(r) == 0 && len(der) != 72 {
				t.Fatal("shape-only72 witness differs")
			}
		}
	}
	for _, v := range []*big.Int{big.NewInt(-1), big.NewInt(0), new(big.Int).Set(n), new(big.Int).Add(n, big.NewInt(1))} {
		for _, swap := range []bool{false, true} {
			r, s := v, big.NewInt(1)
			if swap {
				r, s = s, r
			}
			der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
			if err != nil {
				t.Fatal(err)
			}
			raw, ok := ownerActNativeP256(der)
			if ok || raw != [64]byte{} {
				t.Fatalf("invalid scalar admitted: %s swap=%v", v, swap)
			}
		}
	}
}

// Oversized/too-short byte slices allocate nothing in private conversion,
// independent of their contents, before any ASN.1 decoding. This bounded
// allocation control cannot prove temporal ordering for every compiler/build.
func TestNativeP256BoundsBeforeDecode(t *testing.T) {
	// 73-byte SEQUENCE with two well-formed positive integers; decoding it would
	// allocate big.Int storage before rejecting its out-of-range scalar.
	large := append([]byte{0x30, 71, 2, 34, 1}, make([]byte, 33)...)
	large = append(large, 2, 33, 1)
	large = append(large, make([]byte, 32)...)
	if len(large) != 73 {
		t.Fatal("oversize plant length")
	}
	for _, der := range [][]byte{nil, make([]byte, 7), large, make([]byte, 1<<20)} {
		allocations := testing.AllocsPerRun(100, func() {
			raw, ok := ownerActNativeP256(der)
			if ok || raw != [64]byte{} {
				t.Fatal("bound refusal differs")
			}
		})
		if allocations != 0 {
			t.Fatalf("bound reached decode/allocation: %v allocations", allocations)
		}
	}
}
