package record

import (
	"github.com/relux-works/swarma-envelope/internal/cryptocheck"
	"strings"
)

// KeyBytes checks algorithm spelling, canonical base64 and encoded length.
// ValidateKey additionally checks point encoding and subgroup membership.
func KeyBytes(key string) (string, []byte, error) {
	alg, text, ok := strings.Cut(key, ":")
	n := 32
	if alg == "p256" {
		n = 33
	} else if alg != "ed25519" && alg != "bip340" {
		ok = false
	}
	if !ok {
		return "", nil, refusal("envelope_malformed")
	}
	b, e := DecodeBase64(text, n)
	return alg, b, e
}

// ValidateKey preserves strict encoding, point and subgroup validation.
func ValidateKey(key string) error {
	alg, pub, err := KeyBytes(key)
	if err != nil {
		return err
	}
	if code := cryptocheck.ValidateKey(alg, pub, nil); code != "" {
		return refusal(code)
	}
	return nil
}

// VerifySignature checks the selected algorithm over the unchanged signing preimage.
func VerifySignature(key string, sig, preimage []byte) error {
	alg, pub, err := KeyBytes(key)
	if err != nil {
		return err
	}
	if code := cryptocheck.VerifySignature(alg, pub, sig, preimage, nil); code != "" {
		return refusal(code)
	}
	return nil
}
