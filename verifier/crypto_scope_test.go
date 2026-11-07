package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"github.com/relux-works/swarma-envelope/internal/cryptocheck"
	"github.com/relux-works/swarma-envelope/record"
	"testing"
)

func TestConsumerCryptoScopeIsOperationLocal(t *testing.T) {
	v := New(Context{})
	a, b := v.consumerFacts(), v.consumerFacts()
	sa, oka := a["_cryptoScope"].(*cryptocheck.Scope)
	sb, okb := b["_cryptoScope"].(*cryptocheck.Scope)
	if !oka || !okb || sa == sb || sa == nil || sb == nil {
		t.Fatal("scope shared between calls")
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	key := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	msg := []byte("operation-local")
	sig := ed25519.Sign(private, msg)
	for _, f := range []facts{a, b, {}} {
		for _, k := range []string{key, "ed25519:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "ED25519:bad", "ed25519:bad"} {
			if errorCode(validationKey(f, k)) != errorCode(record.ValidateKey(k)) {
				t.Fatal("key refusal changed")
			}
		}
		if verificationSignature(f, key, sig, msg) != nil {
			t.Fatal("valid signature")
		}
		for _, changed := range [][]byte{[]byte("changed"), nil} {
			if errorCode(verificationSignature(f, key, sig, changed)) != errorCode(record.VerifySignature(key, sig, changed)) {
				t.Fatal("input change reused authority")
			}
		}
	}
}
