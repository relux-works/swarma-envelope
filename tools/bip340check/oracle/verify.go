// Package oracle is a test/tool-only public BIP-340 reference. It is deliberately
// slow, non-constant-time and unsuitable for secrets or production verification.
// Equations follow the pinned official specification; only stdlib arithmetic is
// used. It does not parse envelopes or confer authority.
package oracle

import (
	"crypto/sha256"
	"math/big"
)

type point struct{ x, y *big.Int } // nil coordinates denote infinity.
func integer(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid reference constant")
	}
	return n
}
func params() (*big.Int, *big.Int, point) {
	return integer("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"), integer("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"), point{integer("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"), integer("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")}
}
func mod(x, p *big.Int) *big.Int { return new(big.Int).Mod(x, p) }
func lift(b []byte, p *big.Int) (point, bool) {
	if len(b) != 32 {
		return point{}, false
	}
	x := new(big.Int).SetBytes(b)
	if x.Cmp(p) >= 0 {
		return point{}, false
	}
	c := mod(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), p), big.NewInt(7)), p)
	y := new(big.Int).Exp(c, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2), p)
	if mod(new(big.Int).Mul(y, y), p).Cmp(c) != 0 {
		return point{}, false
	}
	if y.Bit(0) != 0 {
		y.Sub(p, y)
	}
	return point{x, y}, true
}
func add(a, b point, p *big.Int) point {
	if a.x == nil {
		return b
	}
	if b.x == nil {
		return a
	}
	var top, bottom *big.Int
	if a.x.Cmp(b.x) == 0 {
		if a.y.Cmp(b.y) != 0 || a.y.Sign() == 0 {
			return point{}
		}
		top = new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x))
		bottom = new(big.Int).Mul(big.NewInt(2), a.y)
	} else {
		top = new(big.Int).Sub(b.y, a.y)
		bottom = new(big.Int).Sub(b.x, a.x)
	}
	inv := new(big.Int).ModInverse(mod(bottom, p), p)
	if inv == nil {
		return point{}
	}
	slope := mod(new(big.Int).Mul(top, inv), p)
	x := mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(slope, slope), a.x), b.x), p)
	y := mod(new(big.Int).Sub(new(big.Int).Mul(slope, new(big.Int).Sub(a.x, x)), a.y), p)
	return point{x, y}
}
func mul(a point, k, p *big.Int) point {
	r := point{}
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) != 0 {
			r = add(r, a, p)
		}
		a = add(a, a, p)
	}
	return r
}

// ValidKey checks exactly 32 x-only bytes, x<p and lift_x success. There is no
// public-key parity bit; lift_x always chooses even y.
func ValidKey(public []byte) bool { p, _, _ := params(); _, ok := lift(public, p); return ok }

// Verify follows BIP-340 for the ORIGINAL message of arbitrary byte length.
// The envelope adapter, separately, supplies SHA256(original signing preimage).
func Verify(public, message, signature []byte) bool {
	if len(public) != 32 || len(signature) != 64 {
		return false
	}
	p, n, g := params()
	a, ok := lift(public, p)
	if !ok {
		return false
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if r.Cmp(p) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	tag := sha256.Sum256([]byte("BIP0340/challenge"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write(signature[:32])
	h.Write(public)
	h.Write(message)
	e := new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), n)
	a.y = new(big.Int).Sub(p, a.y)
	result := add(mul(g, s, p), mul(a, e, p), p)
	return result.x != nil && result.y.Bit(0) == 0 && result.x.Cmp(r) == 0
}
