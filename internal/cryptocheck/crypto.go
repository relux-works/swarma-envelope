// Package cryptocheck implements strict public-value cryptographic checks.
// It is internal so consumers cannot inject a prevalidated scope.
package cryptocheck

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Scope belongs to exactly one synchronous verifier operation. Only successful
// pure point membership is retained, keyed by the complete encoding. It never
// holds signatures, authorization, time, policy, or mutable input references.
type Scope struct{ points map[[32]byte]struct{} }

const pointLimit = 128

func (s *Scope) point(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	k := [32]byte(b)
	if s != nil {
		if _, ok := s.points[k]; ok {
			return true
		}
	}
	if !primePoint(b) {
		return false
	}
	if s != nil && len(s.points) < pointLimit {
		if s.points == nil {
			s.points = make(map[[32]byte]struct{})
		}
		s.points[k] = struct{}{}
	}
	return true
}
func ValidateKey(alg string, b []byte, scope *Scope) string {
	if alg == "ed25519" {
		if !scope.point(b) {
			return "envelope_signature_invalid"
		}
	} else if alg == "bip340" {
		if _, err := schnorr.ParsePubKey(b); err != nil {
			return "envelope_signature_invalid"
		}
	} else if alg == "p256" {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
		if x == nil || y == nil {
			return "envelope_signature_invalid"
		}
	}
	if alg != "ed25519" && alg != "p256" && alg != "bip340" {
		return "envelope_signature_invalid"
	}
	return ""

}
func VerifySignature(alg string, pub, sig, preimage []byte, scope *Scope) string {
	if len(sig) != 64 {
		return "envelope_signature_invalid"
	}
	if alg == "ed25519" {
		if !scope.point(pub) || !scope.point(sig[:32]) || little(sig[32:]).Cmp(order()) >= 0 || !ed25519.Verify(pub, preimage, sig) {
			return "envelope_signature_invalid"
		}
		return ""
	}
	if alg == "bip340" {
		h := sha256.Sum256(preimage)
		return verifyBIP340(pub, sig, h[:])
	}
	if alg != "p256" {
		return "envelope_signature_invalid"
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pub)
	if x == nil || y == nil {
		return "envelope_signature_invalid"
	}
	n := elliptic.P256().Params().N
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return "envelope_signature_invalid"
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		return "signature_high_s"
	}
	h := sha256.Sum256(preimage)
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], r, s) {
		return "envelope_signature_invalid"
	}
	return ""

}

// verifyBIP340 accepts only a fixed32 message, never an envelope preimage.
func verifyBIP340(pub, sig, message []byte) string {
	if len(sig) != 64 || len(message) != 32 {
		return "envelope_signature_invalid"
	}
	// The pinned parser reduces s modulo n. Admit the ORIGINAL received r/s
	// before parsing; BIP-340 deliberately has no P-256 low-S restriction.
	if !bip340ScalarBounds(sig) {
		return "envelope_signature_invalid"
	}
	key, err := schnorr.ParsePubKey(pub)
	if err != nil {
		return "envelope_signature_invalid"
	}
	signature, err := schnorr.ParseSignature(sig)
	if err != nil {
		return "envelope_signature_invalid"
	}
	if !signature.Verify(message, key) {
		return "envelope_signature_invalid"
	}
	return ""
}

// A strict original-byte admission predicate, before a reducing parser.
func bip340ScalarBounds(sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	params := btcec.S256().Params()
	return new(big.Int).SetBytes(sig[:32]).Cmp(params.P) < 0 && new(big.Int).SetBytes(sig[32:]).Cmp(params.N) < 0
}

func little(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}
func order() *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), 252)
	c, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return n.Add(n, c)
}

// Extended Edwards coordinates keep public subgroup tests inversion-free in
// the multiplication loop. All parameters are local; no mutable global cache.
type edPoint struct{ x, y, z, t *big.Int }

func primePoint(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	q := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	mod := func(x *big.Int) *big.Int { return x.Mod(x, q) }
	enc := append([]byte(nil), b...)
	sign := enc[31] >> 7
	enc[31] &= 127
	y := little(enc)
	if y.Cmp(q) >= 0 {
		return false
	}
	inv := new(big.Int).ModInverse(big.NewInt(121666), q)
	d := mod(new(big.Int).Mul(big.NewInt(-121665), inv))
	yy := mod(new(big.Int).Mul(y, y))
	den := mod(new(big.Int).Add(new(big.Int).Mul(d, yy), big.NewInt(1)))
	if den.ModInverse(den, q) == nil {
		return false
	}
	xx := mod(new(big.Int).Mul(new(big.Int).Sub(yy, big.NewInt(1)), den))
	ex := new(big.Int).Rsh(new(big.Int).Add(q, big.NewInt(3)), 3)
	x := new(big.Int).Exp(xx, ex, q)
	if mod(new(big.Int).Mul(x, x)).Cmp(xx) != 0 {
		sqrtMinus := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(q, big.NewInt(1)), 2), q)
		mod(x.Mul(x, sqrtMinus))
	}
	if mod(new(big.Int).Mul(x, x)).Cmp(xx) != 0 || x.Sign() == 0 && sign != 0 {
		return false
	}
	if x.Bit(0) != uint(sign) {
		x.Sub(q, x)
	}
	p := edPoint{x, y, big.NewInt(1), mod(new(big.Int).Mul(x, y))}
	identity := func(p edPoint) bool { return p.x.Sign() == 0 && mod(new(big.Int).Sub(p.y, p.z)).Sign() == 0 }
	if identity(p) {
		return false
	}
	add := func(p, r edPoint) edPoint {
		a := mod(new(big.Int).Mul(new(big.Int).Sub(p.y, p.x), new(big.Int).Sub(r.y, r.x)))
		b := mod(new(big.Int).Mul(new(big.Int).Add(p.y, p.x), new(big.Int).Add(r.y, r.x)))
		c := mod(new(big.Int).Mul(new(big.Int).Mul(new(big.Int).Mul(big.NewInt(2), d), p.t), r.t))
		z := mod(new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(p.z, r.z)))
		e, f, g, h := mod(new(big.Int).Sub(b, a)), mod(new(big.Int).Sub(z, c)), mod(new(big.Int).Add(z, c)), mod(new(big.Int).Add(b, a))
		return edPoint{mod(new(big.Int).Mul(e, f)), mod(new(big.Int).Mul(g, h)), mod(new(big.Int).Mul(f, g)), mod(new(big.Int).Mul(e, h))}
	}
	r := edPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	l := order()
	for i := 0; i < l.BitLen(); i++ {
		if l.Bit(i) != 0 {
			r = add(r, p)
		}
		p = add(p, p)
	}
	return identity(r)
}
