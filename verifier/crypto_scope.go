package verifier

import (
	"github.com/relux-works/swarma-envelope/internal/cryptocheck"
	"github.com/relux-works/swarma-envelope/record"
)

func validationKey(f facts, key string) error {
	alg, pub, err := record.KeyBytes(key)
	if err != nil {
		return err
	}
	scope, _ := f["_cryptoScope"].(*cryptocheck.Scope)
	if code := cryptocheck.ValidateKey(alg, pub, scope); code != "" {
		return &record.Error{Code: code}
	}
	return nil
}
func verificationSignature(f facts, key string, sig, preimage []byte) error {
	alg, pub, err := record.KeyBytes(key)
	if err != nil {
		return err
	}
	scope, _ := f["_cryptoScope"].(*cryptocheck.Scope)
	if code := cryptocheck.VerifySignature(alg, pub, sig, preimage, scope); code != "" {
		return &record.Error{Code: code}
	}
	return nil
}
