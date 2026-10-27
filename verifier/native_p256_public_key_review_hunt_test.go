package verifier_test

import (
	"bytes"
	"encoding/base64"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
	"reflect"
	"testing"
)

// Distinct helper hunt: framing and coordinate classes refuse with the exact
// local error and no output. Nearby literal 3G accepts after every refusal.
func TestReviewNativePublicShapes(t *testing.T) {
	g := reviewNativeAccept(t, 0)
	for n := 0; n < 65; n++ {
		reviewNativeRefuse(t, bytes.Clone(g[:n]))
	}
	for n := 0; n < 256; n++ {
		if n == 4 {
			continue
		}
		b := bytes.Clone(g)
		b[0] = byte(n)
		reviewNativeRefuse(t, b)
	}
	prime := reviewNativeBytes(t, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
	for _, offset := range []int{1, 33} {
		for _, v := range [][]byte{prime, bytes.Repeat([]byte{255}, 32), make([]byte, 32)} {
			b := bytes.Clone(g)
			copy(b[offset:offset+32], v)
			reviewNativeRefuse(t, b)
		}
	}
	z := make([]byte, 65)
	z[0] = 4
	reviewNativeRefuse(t, z)
	b := bytes.Clone(g)
	b[64] ^= 1
	reviewNativeRefuse(t, b)
	reviewNativeRefuse(t, reviewNativeBytes(t, "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
	for _, v := range reviewNativePublicVectors {
		k, e := base64.RawURLEncoding.DecodeString(v.key[5:])
		if e != nil {
			t.Fatal(e)
		}
		reviewNativeRefuse(t, k)
	}
	for _, b := range [][]byte{append([]byte{4, 65}, g...), []byte(base64.StdEncoding.EncodeToString(g)), append([]byte{239, 187, 191}, g...), []byte(`{"point":"x"}`)} {
		reviewNativeRefuse(t, b)
	}
}

// Allocation evidence applies only to this Go toolchain and these malformed
// bounds. It supplements manual ordering; it is not an asymptotic proof.
func TestReviewNativePublicEarlyBounds(t *testing.T) {
	reviewNativeAccept(t, 0)
	for _, b := range [][]byte{nil, make([]byte, 64), make([]byte, 65), make([]byte, 1<<20)} {
		if a := testing.AllocsPerRun(8, func() {
			k, e := verifier.NativeP256KeyID(b)
			if k != "" || e == nil {
				t.Fatal("expected early refusal")
			}
		}); a != 0 {
			t.Fatalf("early bound allocated %g", a)
		}
	}
}

// Stable synchronous inputs own no retained state; returned IDs survive later
// calls and caller mutation, and the enclosing allocation is unchanged.
func TestReviewNativePublicOwnership(t *testing.T) {
	b := append([]byte{99, 0, 10}, reviewNativeBytes(t, reviewNativePublicVectors[0].native)...)
	b = append(b, 13, 255)
	before := bytes.Clone(b)
	k, e := verifier.NativeP256KeyID(b[3:68])
	if e != nil || k != reviewNativePublicVectors[0].key || !bytes.Equal(b, before) {
		t.Fatal("subslice or identity changed")
	}
	copy(b[3:68], reviewNativeBytes(t, reviewNativePublicVectors[1].native))
	q, e := verifier.NativeP256KeyID(b[3:68])
	if e != nil || q != reviewNativePublicVectors[1].key {
		t.Fatal("next identity lost")
	}
	clear(b[3:68])
	reviewNativeRefuse(t, b[3:68])
	if k != reviewNativePublicVectors[0].key || q != reviewNativePublicVectors[1].key || !bytes.Equal(b[:3], before[:3]) || !bytes.Equal(b[68:], before[68:]) {
		t.Fatal("retention or surroundings changed")
	}
	var typed *verifier.NativeP256PublicKeyError
	if typed.Error() != "native_public_key_invalid" {
		t.Fatal("fixed nil-receiver error changed")
	}
}

// Both independently selected G/-G plans exist BEFORE conversion. Genuine
// software signatures test both key and message associations; conversion never
// supplies enrollment, current consumer facts, native origin or presence.
func TestReviewNativePublicAssociation(t *testing.T) {
	a, b := prepareFixtureFor(t, "unbind"), prepareFixtureFor(t, "unbind")
	b.enrollment["device"] = prepareOtherKey
	b.render = bytes.Replace(b.render, []byte(prepareKey), []byte(prepareOtherKey), 1)
	b.rehash()
	pa, da := prepareAccept(t, a)
	pb, db := prepareAccept(t, b)
	ka, e := verifier.NativeP256KeyID(reviewNativeBytes(t, reviewNativePublicVectors[0].native))
	if e != nil || ka != prepareKey {
		t.Fatal("G")
	}
	kb, e := verifier.NativeP256KeyID(reviewNativeBytes(t, reviewNativePublicVectors[1].native))
	if e != nil || kb != prepareOtherKey {
		t.Fatal("-G")
	}
	for _, c := range []struct {
		p          *verifier.OwnerActSigningPlan
		f          prepareFixture
		key, other string
		neg        bool
	}{{pa, a, ka, kb, false}, {pb, b, kb, ka, true}} {
		raw := assembleSign(t, c.f.preimage, c.neg)
		wrongKeySig := assembleSign(t, c.f.preimage, !c.neg)
		good := assembleAccept(t, c.p, c.f, raw)
		nativeAccept(t, c.p, c.f, raw, nativeDER(t, raw, true))
		for _, v := range []struct {
			k string
			s []byte
		}{{c.other, raw}, {c.other, wrongKeySig}, {c.key, wrongKeySig}, {c.key, assembleSign(t, append(bytes.Clone(c.f.preimage), 10), c.neg)}} {
			assembleReject(t, c.p, v.k, v.s)
			nativeReject(t, c.p, v.k, nativeDER(t, v.s, true))
		}
		wire, _ := good.Bytes()
		r := verifier.New(verifier.Context{}).VerifyEnvelope(wire, "operator-act/1")
		if r.Code != "signer_unavailable" || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
			t.Fatal("missing authority supplied by conversion")
		}
		nativeKey := "p256:" + base64.RawURLEncoding.EncodeToString(reviewNativeBytes(t, reviewNativePublicVectors[0].native))
		if e := record.ValidateKey(nativeKey); e == nil || e.Error() != "envelope_malformed" {
			t.Fatal("wire native key admitted", e)
		}
		if _, _, e := record.KeyBytes(c.key); e != nil {
			t.Fatal("canonical wire control", e)
		}
	}
	bad := prepareFixtureFor(t, "unbind")
	bad.render = bytes.Replace(bad.render, []byte(prepareKey), []byte(prepareOtherKey), 1)
	bad.rehash()
	prepareReject(t, bad, "preparation_mismatch")
	afterA, _ := pa.Snapshot()
	afterB, _ := pb.Snapshot()
	if !reflect.DeepEqual(da, afterA) || !reflect.DeepEqual(db, afterB) {
		t.Fatal("original plans changed")
	}
}
