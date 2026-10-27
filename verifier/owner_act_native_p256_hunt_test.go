package verifier_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Separate post-formal hunt: a genuine short DER signature plus a third INTEGER
// remains within72 bytes, so strict membership cannot hide behind the byte cap.
func TestNativeP256HuntThirdInteger(t *testing.T) {
	for i := 0; i < 2048; i++ {
		f := prepareFixtureFor(t, "unbind")
		f.owner(fmt.Sprint("native-third", i))
		p, _ := prepareAccept(t, f)
		raw := assembleSign(t, f.preimage, false)
		der := nativeDER(t, raw, false)
		if len(der) > 69 {
			continue
		}
		nativeAccept(t, p, f, raw, der)
		bad := append(bytes.Clone(der), 2, 1, 1)
		bad[1] += 3
		if len(bad) > 72 {
			t.Fatal("third INTEGER witness exceeds native cap")
		}
		nativeReject(t, p, prepareKey, bad)
		t.Logf("real witness owner=native-third%d DER=%d with-third=%d", i, len(der), len(bad))
		return
	}
	t.Fatal("bounded real short-DER fixture search exhausted")
}

// Real stdlib P384 signatures are foreign to this explicit P256 path; a valid
// ASN.1 representation/equation on another curve supplies no P256 signed intent.
func TestNativeP256HuntForeignCurve(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	c := elliptic.P384()
	x, y := c.ScalarBaseMult([]byte{1})
	k := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: big.NewInt(1)}
	h := sha256.Sum256(f.preimage)
	der, err := k.Sign(nil, h[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(&k.PublicKey, h[:], der) {
		t.Fatal("foreign curve fixture not genuine", err)
	}
	nativeReject(t, p, prepareKey, der)
	raw := assembleSign(t, f.preimage, false)
	masquerade := bytes.Clone(raw)
	masquerade[0], masquerade[1] = 0x30, 62
	nativeReject(t, p, prepareKey, masquerade)
}

// Every consumer entry still refuses high-S/DER before later authority gates.
// The low-S control reaches a later missing-audience refusal, not crypto success
// as an effect permit; the full E1-E8 positive is TestNativeP256RawWireBoundary.
func TestNativeP256HuntConsumerBoundaries(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	low := assembleSign(t, f.preimage, false)
	high := bytes.Clone(low)
	new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(low[32:])).FillBytes(high[32:])
	result := nativeAccept(t, p, f, low, nativeDER(t, low, true))
	wire, _ := result.Bytes()
	got := verifier.New(verifier.Context{}).VerifyEnvelope(wire, "operator-act/1")
	if got.Code != "signer_unavailable" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
		t.Fatal("native result supplied independent consumer authority", got.Code)
	}
	v := verifier.New(verifier.Context{RequiredRoles: evidence(t, []any{"approver"})})
	for _, tc := range []struct {
		sig  []byte
		code string
	}{{low, "audience_mismatch"}, {high, "signature_high_s"}, {nativeDER(t, low, false), "envelope_malformed"}} {
		wire := assembleExpected(f, tc.sig)
		for name, check := range map[string]func() verifier.Result{
			"envelope":  func() verifier.Result { return v.VerifyEnvelope(wire, "operator-act/1") },
			"operator":  func() verifier.Result { return v.VerifyOperator(wire) },
			"owner-act": func() verifier.Result { return v.VerifyOwnerAct(wire, f.args, f.render, verifier.OwnerActContext{}) },
		} {
			got := check()
			if got.Code != tc.code || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
				t.Fatalf("%s want %s zero plan got %s", name, tc.code, got.Code)
			}
		}
	}
}
