package verifier_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

// Separate free hunt AFTER the persisted formal sweep. Exact length/prefix
// admission rejects all truncations and every non04 prefix, including compressed,
// hybrid and infinity labels. Each refusal is paired with the next valid G call.
func TestNativeP256PublicKeyHuntFraming(t *testing.T) {
	good := publicHex(t, publicKeyGoldens[0].native)
	publicAccept(t, 0)
	publicReject(t, nil)
	publicReject(t, []byte{})
	for n := 0; n < 65; n++ {
		t.Run(fmt.Sprint("prefix", n), func(t *testing.T) { publicReject(t, bytes.Clone(good[:n])) })
	}
	for n := 0; n < 256; n++ {
		if n == 4 {
			continue
		}
		t.Run(fmt.Sprint("tag", n), func(t *testing.T) { b := bytes.Clone(good); b[0] = byte(n); publicReject(t, b) })
	}
	for _, n := range []int{66, 67, 128, 129, 130, 1 << 20} {
		b := make([]byte, n)
		copy(b, good)
		publicReject(t, b)
	}
	for _, i := range []int{0, 1} {
		publicReject(t, publicHex(t, publicKeyGoldens[i].compressed))
	}
}

// Out-of-field X/Y are rejected, not reduced. Zero/zero, zeroed individual
// coordinates, a deterministic neighboring offcurve point and the secp256k1
// generator (same65B04 form, different curve) are not P256 points. This does not
// reject valid coordinates merely for containing zero/control bytes.
func TestNativeP256PublicKeyHuntPoints(t *testing.T) {
	good := publicHex(t, publicKeyGoldens[0].native)
	publicAccept(t, 0)
	prime := publicHex(t, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
	for _, off := range []int{1, 33} {
		for label, value := range map[string][]byte{"prime": prime, "prime+1": new(big.Int).Add(new(big.Int).SetBytes(prime), big.NewInt(1)).FillBytes(make([]byte, 32)), "FF": bytes.Repeat([]byte{255}, 32), "zero": make([]byte, 32)} {
			t.Run(fmt.Sprintf("coordinate-%d-%s", off, label), func(t *testing.T) { b := bytes.Clone(good); copy(b[off:off+32], value); publicReject(t, b) })
		}
	}
	zero := make([]byte, 65)
	zero[0] = 4
	publicReject(t, zero)
	bad := bytes.Clone(good)
	bad[64] ^= 1
	publicReject(t, bad)
	secp := publicHex(t, "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	publicReject(t, secp)
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P384(), elliptic.P521()} {
		publicReject(t, elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy))
	}
	// G and -G are both legitimate: no public-point low-S/sign normalization.
	if publicAccept(t, 0) == publicAccept(t, 1) {
		t.Fatal("opposite public keys collapsed")
	}
}

// Wrappers are unsupported even around genuine public data. Real standard DER
// SPKI/PEM are used as refusal witnesses, never mocked successful native inputs.
func TestNativeP256PublicKeyHuntWrappers(t *testing.T) {
	good := publicHex(t, publicKeyGoldens[0].native)
	publicAccept(t, 0)
	der, err := x509.MarshalPKIXPublicKey(&assembleTestKey(false).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for name, b := range map[string][]byte{"DER-SPKI": der, "PEM": pemBytes, "text": []byte(publicKeyGoldens[0].native), "base64url": []byte(base64.RawURLEncoding.EncodeToString(good)), "base64": []byte(base64.StdEncoding.EncodeToString(good)), "json": []byte(`{"public":"` + publicKeyGoldens[0].native + `"}`), "p256": []byte(publicKeyGoldens[0].key), "BOM": append([]byte{239, 187, 191}, good...), "octet-DER": append([]byte{4, 65}, good...)} {
		t.Run(name, func(t *testing.T) { publicReject(t, b) })
	}
}

// Stable-input synchronous calls never retain or mutate input; earlier strings
// survive input mutation, subslice surroundings, refusal and different next call.
// Unsafe concurrent caller mutation is deliberately outside this claim.
func TestNativeP256PublicKeyHuntOwnership(t *testing.T) {
	a := publicHex(t, publicKeyGoldens[0].native)
	b := publicHex(t, publicKeyGoldens[1].native)
	backing := append([]byte{0, 255, 10}, a...)
	backing = append(backing, 13, 0, 255)
	input := backing[3:68]
	before := bytes.Clone(backing)
	first, err := verifier.NativeP256KeyID(input)
	if err != nil || first != publicKeyGoldens[0].key || !bytes.Equal(backing, before) {
		t.Fatal("subslice conversion mutated or lost data")
	}
	second, e := verifier.NativeP256KeyID(input)
	if e != nil || second != first {
		t.Fatal("repeat pure conversion differs")
	}
	copy(input, b)
	other, e := verifier.NativeP256KeyID(input)
	if e != nil || other != publicKeyGoldens[1].key {
		t.Fatal("different valid point refused or cached")
	}
	clear(input)
	publicReject(t, input)
	if first != publicKeyGoldens[0].key || second != publicKeyGoldens[0].key || other != publicKeyGoldens[1].key {
		t.Fatal("owned string changed after mutation or later call")
	}
	publicAccept(t, 0)
	publicAccept(t, 1)
}

// Early refusal allocation witness is scoped to the pinned Go1.26.10 toolchain:
// warmed valid setup outside the measured call, malformed lengths/prefixes give
// zero input-dependent allocations. This is not a universal performance proof.
func TestNativeP256PublicKeyHuntEarlyBounds(t *testing.T) {
	publicAccept(t, 0)
	short := make([]byte, 64)
	long := make([]byte, 1<<20)
	wrong := publicHex(t, publicKeyGoldens[0].native)
	wrong[0] = 6
	for name, b := range map[string][]byte{"short": short, "oversize": long, "wrong-prefix": wrong} {
		t.Run(name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(20, func() {
				key, err := verifier.NativeP256KeyID(b)
				if key != "" || err == nil {
					panic("expected framing refusal")
				}
			})
			if allocs != 0 {
				t.Fatalf("early bound allocated %g times before refusal", allocs)
			}
		})
	}
}

// Correct native G/-G conversion cannot select enrollment or replace expected
// key/plan/preimage. Real independently specified protected fixtures and genuine
// deterministic signatures supply nearby positive controls for BOTH keys. Raw
// and DER assembly still require exact original key and message associations.
func TestNativeP256PublicKeyHuntAssociation(t *testing.T) {
	selected := publicAccept(t, 0)
	different := publicAccept(t, 1)
	if selected != prepareKey || different != prepareOtherKey {
		t.Fatal("independent enrollment literals disagree")
	}
	f := prepareFixtureFor(t, "unbind")
	p, before := prepareAccept(t, f)
	raw := assembleSign(t, f.preimage, false)
	original := assembleAccept(t, p, f, raw)
	nativeAccept(t, p, f, raw, nativeDER(t, raw, true))
	otherOnOriginal := assembleSign(t, f.preimage, true)
	for _, pair := range []struct {
		key string
		sig []byte
	}{{different, raw}, {different, otherOnOriginal}, {selected, otherOnOriginal}} {
		assembleReject(t, p, pair.key, pair.sig)
		nativeReject(t, p, pair.key, nativeDER(t, pair.sig, false))
	}
	// A converted -G ID is ordinary data. Rebinding full content to -G while
	// retaining the independently selected G enrollment fails real preparation.
	g := prepareFixtureFor(t, "unbind")
	g.render = bytes.Replace(g.render, []byte(prepareKey), []byte(prepareOtherKey), 1)
	g.rehash()
	prepareReject(t, g, "preparation_mismatch")
	// Separately protected -G enrollment is an independent literal fixture choice,
	// not populated from conversion output. Its matching full content can prepare.
	g.enrollment["device"] = prepareOtherKey
	g.rehash()
	q, _ := prepareAccept(t, g)
	sigOther := assembleSign(t, g.preimage, true)
	assembleAccept(t, q, g, sigOther)
	nativeAccept(t, q, g, sigOther, nativeDER(t, sigOther, true))
	assembleReject(t, q, selected, sigOther)
	nativeReject(t, q, selected, nativeDER(t, sigOther, false))
	detached, _ := p.Snapshot()
	detached.Key = different
	clear(detached.Body)
	clear(detached.SigningPreimage)
	after, _ := p.Snapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("conversion/detached view changed immutable plan")
	}
	wire, ok := original.Bytes()
	if !ok || !bytes.Equal(wire, assembleExpected(f, raw)) {
		t.Fatal("prior immutable envelope changed")
	}
	got := verifier.New(verifier.Context{}).VerifyEnvelope(wire, "operator-act/1")
	if got.Code != "signer_unavailable" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
		t.Fatal("converted ID supplied missing consumer authority")
	}
}

// Conversion does not broaden received-wire admission. The canonical33B key
// remains valid; native65B, padded/case/space/standard-base64 key spellings refuse
// through unchanged record and actual envelope entry points with exact codes.
func TestNativeP256PublicKeyHuntWireBoundary(t *testing.T) {
	selected := publicAccept(t, 0)
	rawPub := publicHex(t, publicKeyGoldens[0].native)
	wireKey := "p256:" + base64.RawURLEncoding.EncodeToString(rawPub)
	if _, _, err := record.KeyBytes(wireKey); err == nil || err.Error() != "envelope_malformed" {
		t.Fatal("wire admitted native uncompressed length", err)
	}
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	sig := assembleSign(t, f.preimage, false)
	good := assembleAccept(t, p, f, sig)
	wire, _ := good.Bytes()
	ctx := verifier.Context{Time: evidence(t, map[string]any{"trusted": true, "fresh": true, "authority_until": "2026-01-02T03:10:00Z"}), Now: evidence(t, "2026-01-02T03:04:30Z"), WatermarkAvailable: evidence(t, true), Watermark: evidence(t, "2026-01-02T03:04:30Z"), IDJournalAvailable: evidence(t, true), IDJournal: evidence(t, map[string]any{}), Audience: evidence(t, "owner-acts:0123456789abcdef0123456789abcdef"), RequiredRoles: evidence(t, []any{"approver"}), AdmittedKeys: evidence(t, []any{prepareKey})}
	v := verifier.New(ctx)
	if got := v.VerifyEnvelope(wire, "operator-act/1"); got.Code != "accept" {
		t.Fatal("wire positive", got.Code)
	}
	for _, key := range []string{wireKey, selected + "=", "P256:" + strings.TrimPrefix(selected, "p256:"), " " + selected, selected + " ", "p256:" + base64.StdEncoding.EncodeToString(publicHex(t, publicKeyGoldens[0].compressed))} {
		if e := record.ValidateKey(key); e == nil || e.Error() != "envelope_malformed" {
			t.Fatal("alternate wire key admitted", e)
		}
		changed := bytes.Replace(wire, []byte(selected), []byte(key), 1)
		if bytes.Equal(changed, wire) {
			t.Fatal("wire witness unapplied")
		}
		got := v.VerifyEnvelope(changed, "operator-act/1")
		if got.Code != "envelope_malformed" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
			t.Fatalf("wire want envelope_malformed/zero plan got %s", got.Code)
		}
	}
}
