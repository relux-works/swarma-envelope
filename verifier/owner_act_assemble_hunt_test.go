package verifier_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Separate free hunt, after the persisted formal sweep: all3 operations and
// both proposed confirmed bits produce the exact ordinary wire, without native
// presence/currentness. Repeated pure assembly consumes no native capability.
func TestAssembleHuntOperations(t *testing.T) {
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		for _, confirmed := range []string{"false", "true"} {
			t.Run(op+"/"+confirmed, func(t *testing.T) {
				f := prepareFixtureFor(t, op)
				f.body = bytes.Replace(f.body, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
				f.render = bytes.Replace(f.render, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
				f.rehash()
				p, _ := prepareAccept(t, f)
				sig := assembleSign(t, f.preimage, false)
				for i := 0; i < 2; i++ {
					assembleAccept(t, p, f, sig)
				}
			})
		}
	}
}

// No exported detached data can create/redirect a plan. Nil/zero plans/results
// are unusable, and full snapshot replacement leaves original state unchanged.
func TestAssembleHuntPrivateConstruction(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, before := prepareAccept(t, f)
	sig := assembleSign(t, f.preimage, false)
	for _, zero := range []*verifier.OwnerActSigningPlan{nil, {}, new(verifier.OwnerActSigningPlan)} {
		assembleReject(t, zero, prepareKey, sig)
	}
	for _, zero := range []*verifier.VerifiedOwnerActEnvelope{nil, {}, new(verifier.VerifiedOwnerActEnvelope)} {
		wire, ok := zero.Bytes()
		if ok || wire != nil {
			t.Fatal("unconstructed result produced bytes")
		}
	}
	d, _ := p.Snapshot()
	for _, raw := range [][]byte{d.Body, d.Arguments, d.Render, d.Review, d.SigningPreimage} {
		clear(raw)
	}
	d.Selection = verifier.OwnerActPreparationContext{}
	d.Key, d.ProfilePin, d.Class, d.ReviewVersion = prepareOtherKey, prepareRootID, "narrowing", "forged"
	d.ArgumentsDigest, d.TextSHA256, d.ContentID = "forged", "forged", "forged"
	d.PredictedEnvelopeBytes = 8192
	d = verifier.OwnerActSigningData{Key: prepareOtherKey, Body: []byte(`{}`), SigningPreimage: []byte("supplied digest"), Selection: f.context(t)}
	_ = d // No API admits this detached view as construction evidence.
	assembleAccept(t, p, f, sig)
	after, _ := p.Snapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("detached replacement changed original plan")
	}
	copied := *p
	assembleAccept(t, &copied, f, sig)
}

// The actual returned key is exact, not an algorithm guess/trim/newest fallback.
// A second genuinely enrolled -G fixture accepts only its own preimage/signature.
func TestAssembleHuntKeyBinding(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	sig := assembleSign(t, f.preimage, false)
	assembleAccept(t, p, f, sig)
	for _, key := range []string{prepareOtherKey, "", " " + prepareKey, prepareKey + " ", strings.ToUpper(prepareKey), prepareIssuer, "P256:" + strings.TrimPrefix(prepareKey, "p256:"), prepareKey + "=", "p256:bad", "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), assembleTestKey(false).X, assembleTestKey(false).Y))} {
		assembleReject(t, p, key, sig)
	}
	g := prepareFixtureFor(t, "unbind")
	g.enrollment["device"] = prepareOtherKey
	g.render = bytes.Replace(g.render, []byte(prepareKey), []byte(prepareOtherKey), 1)
	g.rehash()
	q, _ := prepareAccept(t, g)
	other := assembleSign(t, g.preimage, true)
	assembleAccept(t, q, g, other)
	assembleReject(t, p, prepareOtherKey, other)
	assembleReject(t, p, prepareKey, other)
	assembleReject(t, q, prepareKey, sig)
	assembleReject(t, q, prepareOtherKey, sig)
}

// Genuine low-S control is paired with malformed lengths, DER, raw64 with
// DER-like prefix, high-S twin, zero/out-of-range r/s and a damaged equation.
// Fixed nil-output refusal never normalizes caller raw high-S into a result.
func TestAssembleHuntRawSignature(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	good := assembleSign(t, f.preimage, false)
	assembleAccept(t, p, f, good)
	n := elliptic.P256().Params().N
	r, s := new(big.Int).SetBytes(good[:32]), new(big.Int).SetBytes(good[32:])
	high := bytes.Clone(good)
	new(big.Int).Sub(n, s).FillBytes(high[32:])
	h := sha256.Sum256(f.preimage)
	if !ecdsa.Verify(&assembleTestKey(false).PublicKey, h[:], r, new(big.Int).SetBytes(high[32:])) {
		t.Fatal("high-S witness is not genuine")
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string][]byte{"nil": nil, "empty": {}, "short63": good[:63], "long65": append(bytes.Clone(good), 0), "large": make([]byte, 8193), "DER": der, "highS": high, "zero": make([]byte, 64)}
	for _, part := range []string{"r", "s"} {
		for _, value := range []*big.Int{big.NewInt(0), new(big.Int).Set(n), new(big.Int).Add(n, big.NewInt(1))} {
			b := bytes.Clone(good)
			if part == "r" {
				value.FillBytes(b[:32])
			} else {
				value.FillBytes(b[32:])
			}
			bad[part+"-"+value.String()] = b
		}
	}
	damaged := bytes.Clone(good)
	damaged[0] ^= 1
	bad["damaged"] = damaged
	fakeDER := bytes.Clone(good)
	fakeDER[0] = 0x30
	fakeDER[1] = 62
	bad["raw64-DERlike"] = fakeDER
	for name, b := range bad {
		t.Run(name, func(t *testing.T) { assembleReject(t, p, prepareKey, b) })
	}
}

// Genuine signatures on independently stated WRONG raw messages are refused:
// body/A/render/review/hash-only/doublehash/domain/role/version/key/body changes.
// This is association evidence, not merely corrupted-signature rejection.
func TestAssembleHuntWrongPreimages(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, d := prepareAccept(t, f)
	assembleAccept(t, p, f, assembleSign(t, f.preimage, false))
	h := sha256.Sum256(f.preimage)
	double := sha256.Sum256(h[:])
	wrong := map[string][]byte{
		"body-only": f.body, "A-only": f.args, "Render": f.render, "Review": d.Review, "ContentID": []byte(d.ContentID), "message-digest": h[:], "doublehash-message": double[:],
		"wrong-domain":          bytes.Replace(f.preimage, []byte("operator-act/1\n"), []byte("grant/1\n"), 1),
		"wrong-role":            bytes.Replace(f.preimage, []byte(`"role":"approver"`), []byte(`"role":"author"`), 1),
		"wrong-version":         bytes.Replace(f.preimage, []byte(`"version":"swarm-envelope/2"`), []byte(`"version":"swarm-envelope/1"`), 1),
		"wrong-key":             prepareExpectedPreimage(f.body, prepareOtherKey),
		"wrong-body":            bytes.Replace(f.preimage, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1),
		"wrong-aud":             bytes.Replace(f.preimage, []byte("owner-acts:0123456789abcdef0123456789abcdef"), []byte("owner-acts:ffffffffffffffffffffffffffffffff"), 1),
		"wrong-argument-digest": bytes.Replace(f.preimage, []byte(d.ArgumentsDigest), []byte(preparePin), 1),
	}
	for name, pre := range wrong {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(pre, f.preimage) {
				t.Fatal("wrong preimage witness not applied")
			}
			assembleReject(t, p, prepareKey, assembleSign(t, pre, false))
		})
	}
}

// Caller input, each outward result buffer, copied values, repeat assembly and
// cross-call overwrites cannot change retained bytes or the immutable plan.
// Independent expected bytes are detached before any overwrite (no alias oracle).
func TestAssembleHuntOwnership(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, before := prepareAccept(t, f)
	sig := assembleSign(t, f.preimage, false)
	want := bytes.Clone(assembleExpected(f, sig))
	r := assembleAccept(t, p, f, sig)
	second := assembleAccept(t, p, f, sig)
	copyValue := *r
	view, ok := r.Bytes()
	if !ok {
		t.Fatal("result unavailable")
	}
	clear(view)
	again, ok := r.Bytes()
	if !ok || !bytes.Equal(again, want) {
		t.Fatal("Bytes leaked retained output alias")
	}
	clear(again)
	clear(sig)
	clear(f.body)
	clear(f.args)
	f.enrollment["device"] = prepareOtherKey
	f.installed["pin"] = prepareRootID
	for _, result := range []*verifier.VerifiedOwnerActEnvelope{r, second, &copyValue} {
		b, ok := result.Bytes()
		if !ok || !bytes.Equal(b, want) {
			t.Fatal("cross-call/input/accessor alias changed result")
		}
		clear(b)
	}
	after, _ := p.Snapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("result access changed plan")
	}
	other := prepareFixtureFor(t, "bind")
	op, _ := prepareAccept(t, other)
	os := assembleSign(t, other.preimage, false)
	assembleAccept(t, op, other, os)
	assembleReject(t, p, prepareKey, os)
	b, ok := r.Bytes()
	if !ok || !bytes.Equal(b, want) {
		t.Fatal("later failure changed old result")
	}
}

// The jointly attainable schema maxima produce a REAL verified2348-byte
// envelope, not a pretend admissible8192-byte control. A2049/body-owner256/target64
// neighbors remain inherited preparation failures before assembly can be called.
func TestAssembleHuntReachableBounds(t *testing.T) {
	f := prepareFixtureFor(t, "mirror-enable")
	f.owner(strings.Repeat("\x00", 255))
	f.body = bytes.Replace(f.body, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("a", 63)+`"`), 1)
	f.render = bytes.Replace(f.render, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("a", 63)+`"`), 1)
	f.argument("source_room", "room", strings.Repeat(`"`, 255))
	f.argument("source_recipient", "service", strings.Repeat(`"`, 255))
	f.argument("owner_recipient", "owner", strings.Repeat(`"`, 255))
	f.argument("bound_room", "bound", strings.Repeat("b", 136))
	p, d := prepareAccept(t, f)
	r := assembleAccept(t, p, f, assembleSign(t, f.preimage, false))
	b, _ := r.Bytes()
	if len(f.body) != 2043 || len(f.args) != 2048 || len(f.render) != 4021 || len(f.preimage) != 2186 || len(b) != 2348 || d.PredictedEnvelopeBytes != 2348 {
		t.Fatal("reachable maxima changed")
	}
	t.Logf("joint real maxima body=%d A=%d Render=%d preimage=%d verified-envelope=%d", len(f.body), len(f.args), len(f.render), len(f.preimage), len(b))
	f.argument("bound_room", strings.Repeat("b", 136), strings.Repeat("b", 137))
	prepareReject(t, f, "preparation_too_large")
	for _, which := range []string{"owner", "target"} {
		g := prepareFixtureFor(t, "mirror-enable")
		if which == "owner" {
			g.owner(strings.Repeat("x", 256))
		} else {
			g.body = bytes.Replace(g.body, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("a", 64)+`"`), 1)
		}
		prepareReject(t, g, "preparation_invalid")
	}
}

// Pure assembly does not synthesize consumer facts. The signed bytes still
// reach the existing missing-required-role refusal with a zero consumer plan.
func TestAssembleHuntNoConsumerAuthority(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	r := assembleAccept(t, p, f, assembleSign(t, f.preimage, false))
	wire, _ := r.Bytes()
	v := verifier.New(verifier.Context{})
	got := v.VerifyEnvelope(wire, "operator-act/1")
	if got.Code != "signer_unavailable" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
		t.Fatalf("missing independent consumer facts: %s %#v", got.Code, got.Plan)
	}
}
