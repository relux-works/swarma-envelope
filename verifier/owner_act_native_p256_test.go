package verifier_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

// Fixtures use the existing test-only public D=1/-1 keys and deterministic Go
// signer. Expected raw low-S wire uses the independent literal-domain oracle.
func nativeDER(t *testing.T, raw []byte, high bool) []byte {
	t.Helper()
	r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
	if high {
		s.Sub(elliptic.P256().Params().N, s)
	}
	b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func nativeAccept(t *testing.T, p *verifier.OwnerActSigningPlan, f prepareFixture, raw, der []byte) *verifier.VerifiedOwnerActEnvelope {
	t.Helper()
	before, _ := p.Snapshot()
	input := bytes.Clone(der)
	result, err := verifier.AssembleOwnerActNativeP256(p, f.enrollment["device"].(string), der)
	if err != nil || result == nil {
		t.Fatalf("native valid result refused: %v", err)
	}
	wire, ok := result.Bytes()
	if !ok || !bytes.Equal(wire, assembleExpected(f, raw)) || len(wire) != before.PredictedEnvelopeBytes {
		t.Fatal("native canonical envelope differs from independent expected wire/size")
	}
	after, _ := p.Snapshot()
	if !reflect.DeepEqual(before, after) || !bytes.Equal(der, input) {
		t.Fatal("native success mutated plan/input")
	}
	return result
}
func nativeReject(t *testing.T, p *verifier.OwnerActSigningPlan, key string, der []byte) {
	t.Helper()
	control := prepareFixtureFor(t, "unbind")
	cp, _ := prepareAccept(t, control)
	good := assembleSign(t, control.preimage, false)
	cd := nativeDER(t, good, false)
	old := nativeAccept(t, cp, control, good, cd)
	want := bytes.Clone(assembleExpected(control, good))
	before, bok := p.Snapshot()
	input := bytes.Clone(der)
	result, err := verifier.AssembleOwnerActNativeP256(p, key, der)
	var local *verifier.OwnerActAssemblyError
	if result != nil || !errors.As(err, &local) || local.Code != "assembly_invalid" || err.Error() != "assembly_invalid" {
		t.Fatalf("want native assembly_invalid and nil whole output, got output=%v err=%v", result != nil, err)
	}
	after, aok := p.Snapshot()
	got, ok := old.Bytes()
	if bok != aok || !reflect.DeepEqual(before, after) || !bytes.Equal(der, input) || !ok || !bytes.Equal(got, want) {
		t.Fatal("native failure mutated input/plan/prior result")
	}
	nativeAccept(t, cp, control, good, cd)
}

// Exact low/high-S native pairs for all operations and both proposed confirmed
// values yield identical independently specified canonical raw-lowS intent.
// These booleans/signatures supply no native presence or consumer authority.
func TestNativeP256Operations(t *testing.T) {
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		for _, confirmed := range []string{"false", "true"} {
			t.Run(op+"/"+confirmed, func(t *testing.T) {
				f := prepareFixtureFor(t, op)
				f.body = bytes.Replace(f.body, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
				f.render = bytes.Replace(f.render, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
				f.rehash()
				p, d := prepareAccept(t, f)
				prepareExactData(t, f, d)
				raw := assembleSign(t, f.preimage, false)
				for _, high := range []bool{false, true} {
					der := nativeDER(t, raw, high)
					nativeAccept(t, p, f, raw, der)
				}
			})
		}
	}
}

// All identity families exercise the new public path with real signatures on
// original and wrong messages, not just inherited pre-plan parser rejection.
func TestNativeP256IdentityNormalization(t *testing.T) {
	for _, pair := range [][2]string{{"é", "e\u0301"}, {" owner", "owner"}, {"owner ", "owner"}, {"OWNER", "owner"}, {"a\u00a0b", "a b"}, {"a\u200bb", "ab"}, {"é", `\u00e9`}} {
		t.Run(fmt.Sprintf("%x-%x", pair[0], pair[1]), func(t *testing.T) {
			f, g := prepareFixtureFor(t, "unbind"), prepareFixtureFor(t, "unbind")
			f.owner(pair[0])
			g.owner(pair[1])
			p, d := prepareAccept(t, f)
			q, e := prepareAccept(t, g)
			prepareExactData(t, f, d)
			prepareExactData(t, g, e)
			raw, wrong := assembleSign(t, f.preimage, false), assembleSign(t, g.preimage, false)
			nativeAccept(t, p, f, raw, nativeDER(t, raw, false))
			nativeAccept(t, q, g, wrong, nativeDER(t, wrong, true))
			nativeReject(t, p, prepareKey, nativeDER(t, wrong, false))
			nativeReject(t, q, prepareKey, nativeDER(t, raw, true))
			changed := bytes.Replace(f.preimage, []byte(prepareJSON(pair[0])), []byte(prepareJSON(pair[1])), 1)
			if bytes.Equal(changed, f.preimage) {
				t.Fatal("normalisation plant unapplied")
			}
			nativeReject(t, p, prepareKey, nativeDER(t, assembleSign(t, changed, false), false))
			// Reverse raw rewrite keeps the second plan's arguments digest,
			// independently exercising NFD->NFC as well as NFC->NFD.
			reverse := bytes.Replace(g.preimage, []byte(prepareJSON(pair[1])), []byte(prepareJSON(pair[0])), 1)
			if bytes.Equal(reverse, g.preimage) {
				t.Fatal("reverse normalisation plant unapplied")
			}
			nativeReject(t, q, prepareKey, nativeDER(t, assembleSign(t, reverse, false), false))
			nativeReject(t, p, prepareKey, nativeDER(t, assembleSign(t, d.Review, false), false))
		})
	}
}
func TestNativeP256IdentityLineEndings(t *testing.T) {
	for _, line := range []string{"\r", "\n", "\r\n", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprintf("%x", line), func(t *testing.T) {
			rewrite := "\n"
			if line == "\n" {
				rewrite = "\r"
			}
			f, g := prepareFixtureFor(t, "unbind"), prepareFixtureFor(t, "unbind")
			f.owner("a" + line + "b")
			g.owner("a" + rewrite + "b")
			p, d := prepareAccept(t, f)
			q, e := prepareAccept(t, g)
			prepareExactData(t, f, d)
			prepareExactData(t, g, e)
			raw, wrong := assembleSign(t, f.preimage, false), assembleSign(t, g.preimage, false)
			nativeAccept(t, p, f, raw, nativeDER(t, raw, false))
			nativeAccept(t, q, g, wrong, nativeDER(t, wrong, false))
			nativeReject(t, p, prepareKey, nativeDER(t, wrong, true))
			nativeReject(t, q, prepareKey, nativeDER(t, raw, false))
			changed := bytes.Replace(f.preimage, []byte(prepareJSON("a"+line+"b")), []byte(prepareJSON("a"+rewrite+"b")), 1)
			if bytes.Equal(changed, f.preimage) {
				t.Fatal("line-ending plant unapplied")
			}
			nativeReject(t, p, prepareKey, nativeDER(t, assembleSign(t, changed, false), false))
			pre := bytes.Replace(f.preimage, []byte("/1\n"), []byte("/1"+line), 1)
			if !bytes.Equal(pre, f.preimage) {
				nativeReject(t, p, prepareKey, nativeDER(t, assembleSign(t, pre, false), false))
			}
		})
	}
}
func TestNativeP256IdentityTrailingBytes(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	raw := assembleSign(t, f.preimage, false)
	der := nativeDER(t, raw, false)
	nativeAccept(t, p, f, raw, der)
	for _, tail := range []string{"\x00", " ", "text", "\r", "\n", "\r\n", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprintf("%x", tail), func(t *testing.T) {
			nativeReject(t, p, prepareKey, append(bytes.Clone(der), tail...))
			nativeReject(t, p, prepareKey, nativeDER(t, assembleSign(t, append(bytes.Clone(f.preimage), tail...), false), false))
		})
	}
	for _, pre := range [][]byte{f.preimage[1:], f.preimage[:len(f.preimage)-1]} {
		nativeReject(t, p, prepareKey, nativeDER(t, assembleSign(t, pre, false), false))
	}
}

// Genuine signatures for independently specified non-plan messages/keys refuse
// exactly, including digest-only and message algorithms applied to prehashes.
func TestNativeP256Association(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, d := prepareAccept(t, f)
	raw := assembleSign(t, f.preimage, false)
	der := nativeDER(t, raw, false)
	nativeAccept(t, p, f, raw, der)
	h := sha256.Sum256(f.preimage)
	double := sha256.Sum256(h[:])
	wrong := map[string][]byte{"body": f.body, "A": f.args, "render": f.render, "escaped-review": d.Review, "contentID": []byte(d.ContentID), "digest-only": h[:], "doublehash-message": double[:],
		"domain":         bytes.Replace(f.preimage, []byte("operator-act/1\n"), []byte("grant/1\n"), 1),
		"role":           bytes.Replace(f.preimage, []byte(`"role":"approver"`), []byte(`"role":"author"`), 1),
		"version":        bytes.Replace(f.preimage, []byte(`"version":"swarm-envelope/2"`), []byte(`"version":"swarm-envelope/1"`), 1),
		"key-record":     prepareExpectedPreimage(f.body, prepareOtherKey),
		"body-confirmed": bytes.Replace(f.preimage, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1)}
	for name, pre := range wrong {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(pre, f.preimage) {
				t.Fatal("wrong-message plant unapplied")
			}
			nativeReject(t, p, prepareKey, nativeDER(t, assembleSign(t, pre, false), false))
		})
	}
	for _, key := range []string{"", prepareOtherKey, " " + prepareKey, prepareKey + " ", strings.ToUpper(prepareKey), prepareIssuer, prepareKey + "="} {
		nativeReject(t, p, key, der)
	}
	nativeReject(t, p, prepareKey, nativeDER(t, assembleSign(t, f.preimage, true), false))
	for _, zero := range []*verifier.OwnerActSigningPlan{nil, {}, new(verifier.OwnerActSigningPlan)} {
		nativeReject(t, zero, prepareKey, der)
	}
	// A detached proposed view is inert. Copies of authentic plans remain usable.
	detached, _ := p.Snapshot()
	clear(detached.Body)
	clear(detached.SigningPreimage)
	detached.Key = prepareOtherKey
	detached.PredictedEnvelopeBytes = 1
	copied := *p
	nativeAccept(t, &copied, f, raw, der)
	g := prepareFixtureFor(t, "bind")
	q, _ := prepareAccept(t, g)
	other := assembleSign(t, g.preimage, false)
	nativeAccept(t, q, g, other, nativeDER(t, other, false))
	nativeReject(t, p, prepareKey, nativeDER(t, other, false))
	g = prepareFixtureFor(t, "unbind")
	g.enrollment["device"] = prepareOtherKey
	g.render = bytes.Replace(g.render, []byte(prepareKey), []byte(prepareOtherKey), 1)
	g.rehash()
	q, _ = prepareAccept(t, g)
	other = assembleSign(t, g.preimage, true)
	nativeAccept(t, q, g, other, nativeDER(t, other, true))
	nativeReject(t, p, prepareOtherKey, nativeDER(t, other, false))
	nativeReject(t, q, prepareOtherKey, der)
}

// Native representation accepts only canonical DER; these malformed fixtures
// are not valid signed acts. Even canonical shape with a false equation refuses.
func TestNativeP256DERStrict(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	raw := assembleSign(t, f.preimage, false)
	der := nativeDER(t, raw, false)
	nativeAccept(t, p, f, raw, der)
	// Find a real <=70-byte low-S witness so an ignored inner NULL stays <=72.
	for i := 0; len(der) > 70 && i < 1024; i++ {
		f = prepareFixtureFor(t, "unbind")
		f.owner(fmt.Sprint("fixture", i))
		p, _ = prepareAccept(t, f)
		raw = assembleSign(t, f.preimage, false)
		der = nativeDER(t, raw, false)
	}
	if len(der) > 70 {
		t.Fatal("bounded real DER witness search exhausted")
	}
	nativeAccept(t, p, f, raw, der)
	third := append(bytes.Clone(der), 5, 0)
	third[1] += 2
	thirdInt := append(bytes.Clone(der), 2, 1, 1)
	thirdInt[1] += 3
	bad := map[string][]byte{
		"nil": nil, "empty": {}, "short": {0x30, 0}, "missing": {0x30, 3, 2, 1, 1}, "third-null": third, "third-int": thirdInt,
		"raw64": raw, "base64": []byte(base64.RawURLEncoding.EncodeToString(der)), "SSHSIG": []byte("-----BEGIN SSH SIGNATURE-----"), "WebAuthn": []byte(`{"signature":"DER"}`), "FIDO": {0, 1, 2, 3, 4, 5, 6, 7},
		"negative": {0x30, 6, 2, 1, 0xff, 2, 1, 1}, "zero": {0x30, 6, 2, 1, 0, 2, 1, 1}, "redundant-sign": {0x30, 7, 2, 2, 0, 1, 2, 1, 1},
		"missing-sign": {0x30, 6, 2, 1, 0x80, 2, 1, 1}, "empty-int": {0x30, 5, 2, 0, 2, 1, 1}, "integer-octets": {0x30, 6, 4, 1, 1, 2, 1, 1},
		"set": {0x31, 6, 2, 1, 1, 2, 1, 1}, "primitive-sequence": {0x10, 6, 2, 1, 1, 2, 1, 1}, "nested": {0x30, 8, 0x30, 3, 2, 1, 1, 2, 1, 1},
		"indefinite": {0x30, 0x80, 2, 1, 1, 2, 1, 1, 0, 0}, "overlong-sequence": {0x30, 0x81, 6, 2, 1, 1, 2, 1, 1}, "zero-length-prefix": {0x30, 0x82, 0, 6, 2, 1, 1, 2, 1, 1},
		"overlong-integer": {0x30, 7, 2, 0x81, 1, 1, 2, 1, 1}, "long-tag": {0x30, 7, 0x1f, 2, 1, 1, 2, 1, 1}, "huge-declared": {0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 2, 1},
		"bad-equation": {0x30, 6, 2, 1, 1, 2, 1, 1}, "oversized": make([]byte, 1<<20),
	}
	for _, v := range []*big.Int{big.NewInt(0), new(big.Int).Set(elliptic.P256().Params().N), new(big.Int).Add(elliptic.P256().Params().N, big.NewInt(1))} {
		for _, swap := range []bool{false, true} {
			r, s := v, big.NewInt(1)
			if swap {
				r, s = s, r
			}
			b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
			if err != nil {
				t.Fatal(err)
			}
			bad[fmt.Sprintf("scalar-%s-%v", v, swap)] = b
		}
	}
	for i := 0; i < len(der); i++ {
		bad[fmt.Sprint("truncated", i)] = bytes.Clone(der[:i])
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) { nativeReject(t, p, prepareKey, b) })
	}
	for i, tag := range map[int]byte{0: 0x31, 2: 4} {
		b := bytes.Clone(der)
		b[i] = tag
		nativeReject(t, p, prepareKey, b)
	}
	for _, delta := range []byte{1, 255} {
		b := bytes.Clone(der)
		b[1] += delta
		nativeReject(t, p, prepareKey, b)
	}
}

// A real high-S twin verifies mathematically but neither raw assembly nor wire
// normalizes it. DER wire is malformed by the exact raw64 schema, independently
// of later unavailable consumer authority. The nearby low-S wire accepts E1-E8.
func TestNativeP256RawWireBoundary(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	low := assembleSign(t, f.preimage, false)
	high := bytes.Clone(low)
	new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(low[32:])).FillBytes(high[32:])
	h := sha256.Sum256(f.preimage)
	if !ecdsa.Verify(&assembleTestKey(false).PublicKey, h[:], new(big.Int).SetBytes(high[:32]), new(big.Int).SetBytes(high[32:])) {
		t.Fatal("high-S fixture equation")
	}
	nativeAccept(t, p, f, low, nativeDER(t, low, true))
	assembleAccept(t, p, f, low)
	assembleReject(t, p, prepareKey, high)
	assembleReject(t, p, prepareKey, nativeDER(t, low, false))
	ctx := verifier.Context{Time: evidence(t, map[string]any{"trusted": true, "fresh": true, "authority_until": "2026-01-02T03:10:00Z"}), Now: evidence(t, "2026-01-02T03:04:30Z"), WatermarkAvailable: evidence(t, true), Watermark: evidence(t, "2026-01-02T03:04:30Z"), IDJournalAvailable: evidence(t, true), IDJournal: evidence(t, map[string]any{}), Audience: evidence(t, "owner-acts:0123456789abcdef0123456789abcdef"), RequiredRoles: evidence(t, []any{"approver"}), AdmittedKeys: evidence(t, []any{prepareKey})}
	v := verifier.New(ctx)
	for _, tc := range []struct {
		name string
		sig  []byte
		code string
	}{{"low", low, "accept"}, {"high", high, "signature_high_s"}, {"DER", nativeDER(t, low, false), "envelope_malformed"}} {
		t.Run(tc.name, func(t *testing.T) {
			got := v.VerifyEnvelope(assembleExpected(f, tc.sig), "operator-act/1")
			if got.Code != tc.code {
				t.Fatalf("wire want %s got %s", tc.code, got.Code)
			}
			if tc.code != "accept" && !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
				t.Fatal("wire refusal nonzero plan")
			}
		})
	}
	if err := record.VerifySignature(prepareKey, high, f.preimage); err == nil || err.Error() != "signature_high_s" {
		t.Fatal("record high-S refusal", err)
	}
}

// Caller DER, detached plan snapshots, output accessors, value copies and
// subsequent conversion/failure cannot alias or overwrite any retained result.
func TestNativeP256Ownership(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, before := prepareAccept(t, f)
	raw := assembleSign(t, f.preimage, false)
	der := nativeDER(t, raw, true)
	want := bytes.Clone(assembleExpected(f, raw))
	a := nativeAccept(t, p, f, raw, der)
	b := nativeAccept(t, p, f, raw, der)
	copyValue := *a
	clear(der)
	data, _ := p.Snapshot()
	clear(data.Body)
	clear(data.Arguments)
	clear(data.Render)
	clear(data.Review)
	clear(data.SigningPreimage)
	view, _ := a.Bytes()
	clear(view)
	for _, result := range []*verifier.VerifiedOwnerActEnvelope{a, b, &copyValue} {
		got, ok := result.Bytes()
		if !ok || !bytes.Equal(got, want) {
			t.Fatal("native input/output alias changed result")
		}
		clear(got)
	}
	after, _ := p.Snapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("native ownership changed plan")
	}
	nativeReject(t, p, prepareKey, der)
	nativeAccept(t, p, f, raw, nativeDER(t, raw, false))
	got, _ := a.Bytes()
	if !bytes.Equal(got, want) {
		t.Fatal("subsequent failure overwrote prior result")
	}
}

// An actual signed fixture reaches the72-byte native ceiling (both positive
// INTEGER sign octets), while producing the independent low-S wire oracle.
func TestNativeP256Real72ByteSignature(t *testing.T) {
	for i := 0; i < 64; i++ {
		f := prepareFixtureFor(t, "unbind")
		f.owner(fmt.Sprint("native-max", i))
		p, _ := prepareAccept(t, f)
		raw := assembleSign(t, f.preimage, false)
		der := nativeDER(t, raw, true)
		if len(der) == 72 {
			nativeAccept(t, p, f, raw, der)
			t.Logf("real high-S DER72 fixture owner=native-max%d", i)
			return
		}
	}
	t.Fatal("bounded real72-byte fixture search exhausted")
}
