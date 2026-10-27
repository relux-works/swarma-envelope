package verifier_test

import (
	"bytes"
	"crypto"
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

	"github.com/relux-works/swarma-envelope/verifier"
)

// Public test scalars only. Independent stdlib signing/equation checks supply
// real exact/wrong-message witnesses; production never signs or normalizes.
func reviewAssembleSign(t *testing.T, message []byte, scalar int64) []byte {
	t.Helper()
	c := elliptic.P256()
	d := big.NewInt(scalar)
	x, y := c.ScalarBaseMult(d.Bytes())
	k := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}
	digest := sha256.Sum256(message)
	der, err := k.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &pair)
	if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil {
		t.Fatal("review signature fixture decode", err)
	}
	if pair.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(c.Params().N), 1)) > 0 {
		pair.S.Sub(c.Params().N, pair.S)
	}
	if !ecdsa.Verify(&k.PublicKey, digest[:], pair.R, pair.S) {
		t.Fatal("review fixture equation")
	}
	sig := make([]byte, 64)
	pair.R.FillBytes(sig[:32])
	pair.S.FillBytes(sig[32:])
	return sig
}
func reviewAssemblePre(f prepareFixture) []byte {
	return []byte("swarma-waggle operator-act/1\n" + `{"body":` + string(f.body) + `,"key":"` + f.enrollment["device"].(string) + `","role":"approver","version":"swarm-envelope/2"}`)
}
func reviewAssembleWire(f prepareFixture, sig []byte) []byte {
	id := sha256.Sum256(append([]byte("swarma-waggle operator-act/1\n"), f.body...))
	return []byte(fmt.Sprintf(`{"body":%s,"id":"sha256:%x","signatures":[{"key":"%s","role":"approver","sig":"%s"}],"version":"swarm-envelope/2"}`, f.body, id, f.enrollment["device"], base64.RawURLEncoding.EncodeToString(sig)))
}
func reviewAssembleYes(t *testing.T, p *verifier.OwnerActSigningPlan, f prepareFixture, sig []byte) *verifier.VerifiedOwnerActEnvelope {
	t.Helper()
	before, ok := p.Snapshot()
	if !ok {
		t.Fatal("review positive plan missing")
	}
	if !bytes.Equal(before.SigningPreimage, reviewAssemblePre(f)) || !bytes.Equal(before.Body, f.body) || !bytes.Equal(before.Arguments, f.args) || !bytes.Equal(before.Render, f.render) {
		t.Fatal("review literal plan association")
	}
	input := bytes.Clone(sig)
	out, err := verifier.AssembleOwnerAct(p, f.enrollment["device"].(string), sig)
	if err != nil || out == nil {
		t.Fatalf("review valid signed intent refused: %v", err)
	}
	got, ok := out.Bytes()
	if !ok || !bytes.Equal(got, reviewAssembleWire(f, sig)) {
		t.Fatal("review complete wire differs")
	}
	after, _ := p.Snapshot()
	if !reflect.DeepEqual(before, after) || !bytes.Equal(input, sig) {
		t.Fatal("review positive mutated input or plan")
	}
	if len(got) != len(f.body)+305 || len(got) != before.PredictedEnvelopeBytes {
		t.Fatal("review exact envelope size")
	}
	return out
}
func reviewAssembleNo(t *testing.T, p *verifier.OwnerActSigningPlan, key string, sig []byte) {
	t.Helper()
	f := prepareFixtureFor(t, "mirror-enable")
	cp, _ := prepareAccept(t, f)
	good := reviewAssembleSign(t, reviewAssemblePre(f), 1)
	old := reviewAssembleYes(t, cp, f, good)
	want := reviewAssembleWire(f, good)
	before, valid := p.Snapshot()
	input := bytes.Clone(sig)
	got, err := verifier.AssembleOwnerAct(p, key, sig)
	var local *verifier.OwnerActAssemblyError
	if got != nil || !errors.As(err, &local) || local.Code != "assembly_invalid" || err.Error() != "assembly_invalid" {
		t.Fatalf("review expected assembly_invalid and nil output; result=%t err=%v", got != nil, err)
	}
	after, validAfter := p.Snapshot()
	wire, ok := old.Bytes()
	if valid != validAfter || !reflect.DeepEqual(before, after) || !bytes.Equal(input, sig) || !ok || !bytes.Equal(wire, want) {
		t.Fatal("review refusal changed existing state")
	}
	reviewAssembleYes(t, cp, f, good)
}

// Formal normalization checks both fully rebound valid plans and ONLY a changed
// raw owner spelling with the original A digest retained. Complete literal wire
// and genuine signatures ground both acceptance and exact refusal independently.
func TestReviewAssembleRawNormalization(t *testing.T) {
	pairs := [][2]string{{"\u212b", "\u00c5"}, {"\u00c5", "A\u030a"}, {"\ufeffx", "x"}, {"x\u200dy", "xy"}, {"x\u2066y\u2069", "xy"}, {" x ", "x"}, {"x\u00a0y", "x y"}, {"x\x00y", "xy"}, {"x\u202ey", "xy"}, {`x\u0000y`, "x\x00y"}, {"x\"\\y", "x/y"}, {"\U0010ffff", "\ufffd"}}
	for i, pair := range pairs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f, g := prepareFixtureFor(t, "bind"), prepareFixtureFor(t, "bind")
			f.owner(pair[0])
			g.owner(pair[1])
			f.enrollment["installation"] = "local\n" + pair[1]
			p, _ := prepareAccept(t, f)
			q, _ := prepareAccept(t, g)
			fp, gp := reviewAssemblePre(f), reviewAssemblePre(g)
			fs, gs := reviewAssembleSign(t, fp, 1), reviewAssembleSign(t, gp, 1)
			reviewAssembleYes(t, p, f, fs)
			reviewAssembleYes(t, q, g, gs)
			reviewAssembleNo(t, p, prepareKey, gs)
			reviewAssembleNo(t, q, prepareKey, fs)
			for j, entry := range []struct {
				p   *verifier.OwnerActSigningPlan
				pre []byte
			}{{p, fp}, {q, gp}} {
				old, new := pair[j], pair[1-j]
				needle := []byte(`"owner":` + prepareJSON(old))
				replacement := []byte(`"owner":` + prepareJSON(new))
				raw := bytes.Replace(entry.pre, needle, replacement, 1)
				if bytes.Equal(raw, entry.pre) {
					t.Fatal("review raw-only plant absent")
				}
				reviewAssembleNo(t, entry.p, prepareKey, reviewAssembleSign(t, raw, 1))
			}
		})
	}
	// Alternate escaped spellings of the SAME value still change signed bytes.
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	pre := reviewAssemblePre(f)
	for _, s := range []string{`"owner":"\u006fwner"`, `"owner":"ow\u006eer"`} {
		raw := bytes.Replace(pre, []byte(`"owner":"owner"`), []byte(s), 1)
		reviewAssembleNo(t, p, prepareKey, reviewAssembleSign(t, raw, 1))
	}
	reviewAssembleYes(t, p, f, reviewAssembleSign(t, pre, 1))
}

// Formal EOL cases preserve exact body and complete A associations, while raw
// message-only rewrites and changed domain separators must fail the NEW API.
func TestReviewAssembleRawLineEndings(t *testing.T) {
	for i, line := range []string{"\r", "\n", "\r\n", "\n\r", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			other := "\n"
			if line == other {
				other = "\r"
			}
			f := prepareFixtureFor(t, "mirror-enable")
			f.owner("left" + line + "right")
			p, _ := prepareAccept(t, f)
			pre := reviewAssemblePre(f)
			reviewAssembleYes(t, p, f, reviewAssembleSign(t, pre, 1))
			raw := bytes.Replace(pre, []byte(prepareJSON("left"+line+"right")), []byte(prepareJSON("left"+other+"right")), 1)
			if bytes.Equal(raw, pre) {
				t.Fatal("review raw EOL witness absent")
			}
			reviewAssembleNo(t, p, prepareKey, reviewAssembleSign(t, raw, 1))
			raw = bytes.Replace(pre, []byte("/1\n"), []byte("/1"+line), 1)
			if !bytes.Equal(raw, pre) {
				reviewAssembleNo(t, p, prepareKey, reviewAssembleSign(t, raw, 1))
			}
			g := prepareFixtureFor(t, "mirror-enable")
			g.owner("left" + other + "right")
			q, _ := prepareAccept(t, g)
			gs := reviewAssembleSign(t, reviewAssemblePre(g), 1)
			reviewAssembleYes(t, q, g, gs)
			reviewAssembleNo(t, p, prepareKey, gs)
			g = prepareFixtureFor(t, "bind")
			g.argument("source_room", "room", "a"+line+"b")
			prepareReject(t, g, "preparation_invalid")
		})
	}
}

// Formal trailers distinguish inherited body/A admission from assembly's new
// exact signed-message check. Each refusal preserves an older complete result.
func TestReviewAssembleRawTrailingBytes(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	f.owner("z\x00\n\t ")
	p, _ := prepareAccept(t, f)
	pre := reviewAssemblePre(f)
	reviewAssembleYes(t, p, f, reviewAssembleSign(t, pre, 1))
	for i, tail := range []string{"\n", "\r\n", "\n\r", "\x00", " ", "\t", "\v", "\ufeff", "\u0085", "\u2028", "\u2029", "{}", "[]", "\xff"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			reviewAssembleNo(t, p, prepareKey, reviewAssembleSign(t, append(bytes.Clone(pre), tail...), 1))
			for _, which := range []string{"body", "A"} {
				g := prepareFixtureFor(t, "unbind")
				if which == "body" {
					g.body = append(g.body, tail...)
				} else {
					g.args = append(g.args, tail...)
				}
				prepareReject(t, g, "preparation_invalid")
			}
		})
	}
	for _, raw := range [][]byte{pre[1:], pre[:len(pre)-1], pre[:len(pre)-2], bytes.TrimSuffix(pre, []byte("/2\"}"))} {
		if bytes.Equal(raw, pre) {
			t.Fatal("review dropped-byte witness absent")
		}
		reviewAssembleNo(t, p, prepareKey, reviewAssembleSign(t, raw, 1))
	}
	g := prepareFixtureFor(t, "unbind")
	g.owner(strings.TrimSpace(" z "))
	q, _ := prepareAccept(t, g)
	reviewAssembleYes(t, q, g, reviewAssembleSign(t, reviewAssemblePre(g), 1))
}
