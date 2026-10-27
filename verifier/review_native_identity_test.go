package verifier_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Review oracle: inherited fixture builders provide inputs and the reviewed
// stdlib signer supplies genuine equations. Expected wire uses a literal domain
// and full original body; no production conversion/serialization is an oracle.
func reviewNativeDER(t *testing.T, raw []byte, high bool) []byte {
	t.Helper()
	r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
	if high {
		s.Sub(assembleTestKey(false).Curve.Params().N, s)
	}
	b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func reviewNativeExpected(f prepareFixture, raw []byte) []byte {
	id := sha256.Sum256(append([]byte("swarma-waggle operator-act/1\n"), f.body...))
	return []byte(fmt.Sprintf("{\"body\":%s,\"id\":\"sha256:%x\",\"signatures\":[{\"key\":\"%s\",\"role\":\"approver\",\"sig\":\"%s\"}],\"version\":\"swarm-envelope/2\"}", f.body, id, f.enrollment["device"], base64.RawURLEncoding.EncodeToString(raw)))
}
func reviewNativeExercise(t *testing.T, f prepareFixture, wrong [][]byte, tails [][]byte) {
	t.Helper()
	p, err := verifier.PrepareOwnerAct(f.body, f.args, f.context(t))
	if err != nil {
		t.Fatal("fixture preparation", err)
	}
	snapshot, ok := p.Snapshot()
	if !ok || !bytes.Equal(snapshot.Body, f.body) || !bytes.Equal(snapshot.Arguments, f.args) || !bytes.Equal(snapshot.SigningPreimage, f.preimage) {
		t.Fatal("original plan identity")
	}
	raw := assembleSign(t, f.preimage, false)
	good := reviewNativeDER(t, raw, false)
	want := reviewNativeExpected(f, raw)
	accept := func(der []byte) *verifier.VerifiedOwnerActEnvelope {
		before := bytes.Clone(der)
		out, e := verifier.AssembleOwnerActNativeP256(p, snapshot.Key, der)
		if e != nil || out == nil {
			t.Fatalf("adjacent exact-message positive refused: %v", e)
		}
		wire, valid := out.Bytes()
		after, _ := p.Snapshot()
		if !valid || !bytes.Equal(wire, want) || len(wire) != snapshot.PredictedEnvelopeBytes || !bytes.Equal(der, before) || !reflect.DeepEqual(snapshot, after) {
			t.Fatal("complete original wire/plan/DER invariant")
		}
		return out
	}
	prior := accept(good)
	accept(reviewNativeDER(t, raw, true))
	var bad [][]byte
	for _, pre := range wrong {
		if bytes.Equal(pre, f.preimage) {
			t.Fatal("unapplied message comparison")
		}
		bad = append(bad, reviewNativeDER(t, assembleSign(t, pre, false), false))
		bad = append(bad, reviewNativeDER(t, assembleSign(t, pre, false), true))
	}
	for _, tail := range tails {
		bad = append(bad, append(bytes.Clone(good), tail...))
	}
	for i, der := range bad {
		before := bytes.Clone(der)
		out, e := verifier.AssembleOwnerActNativeP256(p, snapshot.Key, der)
		var local *verifier.OwnerActAssemblyError
		if out != nil || !errors.As(e, &local) || local.Code != "assembly_invalid" || e.Error() != "assembly_invalid" {
			t.Fatalf("case %d: exact refusal/nil violated", i)
		}
		after, _ := p.Snapshot()
		old, valid := prior.Bytes()
		if !reflect.DeepEqual(snapshot, after) || !bytes.Equal(der, before) || !valid || !bytes.Equal(old, want) {
			t.Fatal("refusal changed original input/plan/prior result")
		}
		accept(good)
	}
}

// Both raw rewrite directions retain the old arguments digest; fully remapped
// pairs also differ. Controls/invisibles and literal escapes are distinct bytes.
func TestReviewNativeIdentityNormalization(t *testing.T) {
	pairs := [][2]string{{"é", "e\u0301"}, {" owner", "owner"}, {"owner ", "owner"}, {"a\u00a0b", "a b"}, {"a\u200bb", "ab"}, {"a\u202eb", "ab"}, {"a\x00b", "ab"}, {"a\x7fb", "ab"}, {"a\tb", "a b"}, {"é", `\u00e9`}}
	for i, pair := range pairs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			for direction := 0; direction < 2; direction++ {
				from, to := pair[direction], pair[1-direction]
				f, g := prepareFixtureFor(t, "unbind"), prepareFixtureFor(t, "unbind")
				f.owner(from)
				g.owner(to)
				rewrite := bytes.Replace(f.preimage, []byte(prepareJSON(from)), []byte(prepareJSON(to)), 1)
				reviewNativeExercise(t, f, [][]byte{rewrite, g.preimage}, nil)
			}
		})
	}
}

// CR/LF/CRLF/NEL/LS/PS are checked inside the owner and at the domain separator;
// the new public API sees genuine wrong-message signatures in each case.
func TestReviewNativeIdentityLineEndings(t *testing.T) {
	for i, line := range []string{"\r", "\n", "\r\n", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			other := "\n"
			if line == "\n" {
				other = "\r"
			}
			f, g := prepareFixtureFor(t, "unbind"), prepareFixtureFor(t, "unbind")
			f.owner("a" + line + "b")
			g.owner("a" + other + "b")
			changed := bytes.Replace(f.preimage, []byte(prepareJSON("a"+line+"b")), []byte(prepareJSON("a"+other+"b")), 1)
			pre := bytes.Replace(f.preimage, []byte("/1\n"), []byte("/1"+other), 1)
			if bytes.Equal(pre, f.preimage) {
				pre = bytes.Replace(f.preimage, []byte("/1\n"), []byte("/1\r"), 1)
			}
			reviewNativeExercise(t, f, [][]byte{changed, g.preimage, pre}, nil)
		})
	}
}

// Appended/dropped preimage bytes and DER trailers refuse independently, with a
// real positive and an already-retained same-plan result checked after each.
func TestReviewNativeIdentityTrailingBytes(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	var wrong, tails [][]byte
	for _, s := range []string{"\x00", " ", "text", "\r", "\n", "\r\n", "\u0085", "\u2028", "\u2029"} {
		tails = append(tails, []byte(s))
		wrong = append(wrong, append(bytes.Clone(f.preimage), s...))
	}
	wrong = append(wrong, bytes.Clone(f.preimage[1:]), bytes.Clone(f.preimage[:len(f.preimage)-1]))
	reviewNativeExercise(t, f, wrong, tails)
}
