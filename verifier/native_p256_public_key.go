package verifier

import (
	"crypto/elliptic"
	"encoding/base64"

	"github.com/relux-works/swarma-envelope/record"
)

// NativeP256PublicKeyError is a fixed local representation refusal. It contains
// no input or native diagnostic; every failure spells native_public_key_invalid.
type NativeP256PublicKeyError struct{}

func (*NativeP256PublicKeyError) Error() string { return "native_public_key_invalid" }

// NativeP256KeyID converts exactly 65 binary bytes (04 || X32 || Y32) into the
// ordinary canonical p256: compressed SEC1 key ID. Length and prefix checks
// precede input-dependent allocation or parsing. Standard-library fixed P-256
// validation owns field/on-curve/nonidentity admission; leading coordinate zeroes
// and all binary bytes are data. P and -P retain distinct Y-parity prefixes.
// No alternate representation, trimming, field reduction or sign normalization
// is supported. Every refusal returns an empty string and the fixed local error.
//
// Caller bytes must remain stable during this synchronous call. The function
// neither mutates nor retains input; the returned ordinary string owns its
// lifetime. Repeated conversion supplies mathematical syntax only, not native
// origin, key custody, enrollment, expected selection, presence or authority.
// PrepareOwnerAct and both assembly paths must still independently match their
// original protected selection/plan/key and verify the exact signing preimage.
func NativeP256KeyID(nativePublic []byte) (string, error) {
	if len(nativePublic) != 65 || nativePublic[0] != 4 {
		return "", &NativeP256PublicKeyError{}
	}
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, nativePublic)
	if x == nil || y == nil {
		return "", &NativeP256PublicKeyError{}
	}
	compressed := elliptic.MarshalCompressed(curve, x, y)
	key := "p256:" + base64.RawURLEncoding.EncodeToString(compressed)
	if record.ValidateKey(key) != nil {
		return "", &NativeP256PublicKeyError{}
	}
	return key, nil
}
