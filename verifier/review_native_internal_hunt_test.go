package verifier

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
	"testing"
)

// Representation-only midpoint/neighbour checks are not signed-act fixtures.
// P-256's odd order admits a unique low representative; its shared order must
// remain unchanged across normalization, refusal and subsequent conversions.
func TestReviewNativeHuntMidpointOrder(t *testing.T) {
	n := elliptic.P256().Params().N
	before := new(big.Int).Set(n)
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	for _, s := range []*big.Int{big.NewInt(1), new(big.Int).Set(half), new(big.Int).Add(half, big.NewInt(1)), new(big.Int).Sub(n, big.NewInt(1))} {
		for _, r := range []*big.Int{big.NewInt(1), big.NewInt(128), new(big.Int).Lsh(big.NewInt(1), 255), new(big.Int).Sub(n, big.NewInt(1))} {
			der, e := asn1.Marshal(struct{ R, S *big.Int }{r, s})
			if e != nil {
				t.Fatal(e)
			}
			original := bytes.Clone(der)
			raw, ok := ownerActNativeP256(der)
			if !ok {
				t.Fatal("valid numeric representation refused")
			}
			gotR, gotS := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
			if gotR.Cmp(r) != 0 || gotS.Sign() <= 0 || gotS.Cmp(half) > 0 || (gotS.Cmp(s) != 0 && new(big.Int).Add(gotS, s).Cmp(before) != 0) {
				t.Fatal("incorrect fixed32/low representative")
			}
			if n.Cmp(before) != 0 || !bytes.Equal(der, original) {
				t.Fatal("shared curve order or DER mutated")
			}
		}
	}
	for _, s := range []*big.Int{big.NewInt(0), new(big.Int).Set(n), new(big.Int).Add(n, big.NewInt(1))} {
		der, e := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), s})
		if e != nil {
			t.Fatal(e)
		}
		raw, ok := ownerActNativeP256(der)
		if ok || raw != [64]byte{} || n.Cmp(before) != 0 {
			t.Fatal("invalid scalar affected output/order")
		}
	}
}
