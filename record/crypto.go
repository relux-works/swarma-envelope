package record

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"strings"
)

// KeyBytes checks algorithm spelling, canonical base64 and encoded length.
// ValidateKey additionally checks point encoding and subgroup membership.
func KeyBytes(key string) (string, []byte, error) {
	alg, text, ok := strings.Cut(key, ":")
	n := 32
	if alg == "p256" {
		n = 33
	} else if alg != "ed25519" {
		ok = false
	}
	if !ok {
		return "", nil, refusal("envelope_malformed")
	}
	b, e := DecodeBase64(text, n)
	return alg, b, e
}

// ValidateKey refuses noncanonical, identity, small/mixed-order Edwards points
// and invalid compressed P-256 points. Only public values enter this arithmetic.
func ValidateKey(key string) error {
	alg, b, e := KeyBytes(key)
	if e != nil {
		return e
	}
	if alg == "ed25519" {
		if !primePoint(b) {
			return refusal("envelope_signature_invalid")
		}
	} else {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), b)
		if x == nil || y == nil {
			return refusal("envelope_signature_invalid")
		}
	}
	return nil
}

// VerifySignature uses ordinary stdlib Ed25519 or SHA-256/ECDSA P-256.
// Strict point/subgroup and scalar checks precede the stdlib equation.
func VerifySignature(key string, sig, preimage []byte) error {
	alg, pub, e := KeyBytes(key)
	if e != nil {
		return e
	}
	if len(sig) != 64 {
		return refusal("envelope_signature_invalid")
	}
	if alg == "ed25519" {
		if !primePoint(pub) || !primePoint(sig[:32]) || little(sig[32:]).Cmp(order()) >= 0 || !ed25519.Verify(pub, preimage, sig) {
			return refusal("envelope_signature_invalid")
		}
		return nil
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pub)
	if x == nil || y == nil {
		return refusal("envelope_signature_invalid")
	}
	n := elliptic.P256().Params().N
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return refusal("envelope_signature_invalid")
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		return refusal("signature_high_s")
	}
	h := sha256.Sum256(preimage)
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], r, s) {
		return refusal("envelope_signature_invalid")
	}
	return nil
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
