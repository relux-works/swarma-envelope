package verifier_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

func reviewAssembleKey(scalar int64) string {
	c := elliptic.P256()
	x, y := c.ScalarBaseMult(big.NewInt(scalar).Bytes())
	return "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(c, x, y))
}
func reviewAssembleFixture(t *testing.T, op string, scalar int64) prepareFixture {
	t.Helper()
	f := prepareFixtureFor(t, op)
	key := reviewAssembleKey(scalar)
	f.enrollment["device"] = key
	f.render = bytes.Replace(f.render, []byte(prepareKey), []byte(key), 1)
	f.rehash()
	return f
}

// Three additional genuinely enrolled public keys and every operation/bit pair
// prevent G/-G-only acceptance or cross-key signatures from satisfying the gate.
// Full output is decoded and independently verified with stdlib ECDSA as well
// as compared to the complete literal wire oracle; this is not native custody.
func TestReviewAssembleIndependentKeys(t *testing.T) {
	for _, scalar := range []int64{2, 3, 17} {
		for _, op := range []string{"bind", "unbind", "mirror-enable"} {
			for _, confirmed := range []string{"false", "true"} {
				t.Run(fmt.Sprintf("%d/%s/%s", scalar, op, confirmed), func(t *testing.T) {
					f := reviewAssembleFixture(t, op, scalar)
					f.body = bytes.Replace(f.body, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
					f.render = bytes.Replace(f.render, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
					f.rehash()
					p, _ := prepareAccept(t, f)
					pre := reviewAssemblePre(f)
					sig := reviewAssembleSign(t, pre, scalar)
					r := reviewAssembleYes(t, p, f, sig)
					wire, _ := r.Bytes()
					var env map[string]json.RawMessage
					if err := json.Unmarshal(wire, &env); err != nil {
						t.Fatal(err)
					}
					if len(env) != 4 || !bytes.Equal(env["body"], f.body) {
						t.Fatal("review closed top shape/body")
					}
					var entries []map[string]string
					if err := json.Unmarshal(env["signatures"], &entries); err != nil {
						t.Fatal(err)
					}
					if len(entries) != 1 || len(entries[0]) != 3 || entries[0]["key"] != reviewAssembleKey(scalar) || entries[0]["role"] != "approver" {
						t.Fatal("review closed signature shape")
					}
					raw, err := base64.RawURLEncoding.Strict().DecodeString(entries[0]["sig"])
					if err != nil || len(raw) != 64 || !bytes.Equal(raw, sig) {
						t.Fatal("review raw signature representation")
					}
					h := sha256.Sum256(pre)
					c := elliptic.P256()
					x, y := c.ScalarBaseMult(big.NewInt(scalar).Bytes())
					if !ecdsa.Verify(&ecdsa.PublicKey{Curve: c, X: x, Y: y}, h[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
						t.Fatal("review final independent equation")
					}
					reviewAssembleNo(t, p, prepareKey, sig)
					reviewAssembleNo(t, p, reviewAssembleKey(scalar), reviewAssembleSign(t, pre, 1))
				})
			}
		}
	}
}

// Exact raw64 bounds, canonical key spelling and strict high-S refusal apply to
// a non-G key too. The high-S twin is a valid ECDSA equation but forbidden raw
// representation, so an equation-only verifier cannot satisfy this test.
func TestReviewAssembleScalarAndMessageEdges(t *testing.T) {
	f := reviewAssembleFixture(t, "bind", 2)
	p, d := prepareAccept(t, f)
	pre := reviewAssemblePre(f)
	key := reviewAssembleKey(2)
	sig := reviewAssembleSign(t, pre, 2)
	reviewAssembleYes(t, p, f, sig)
	for _, n := range []int{0, 1, 31, 32, 33, 63, 65, 72, 8193, 1 << 20} {
		t.Run(fmt.Sprintf("length-%d", n), func(t *testing.T) { raw := make([]byte, n); copy(raw, sig); reviewAssembleNo(t, p, key, raw) })
	}
	backing := bytes.Repeat([]byte{0xa5}, 128)
	copy(backing[16:80], sig)
	before := bytes.Clone(backing)
	reviewAssembleYes(t, p, f, backing[16:80])
	if !bytes.Equal(backing, before) {
		t.Fatal("review caller guard bytes changed")
	}
	c := elliptic.P256()
	high := bytes.Clone(sig)
	new(big.Int).Sub(c.Params().N, new(big.Int).SetBytes(sig[32:])).FillBytes(high[32:])
	h := sha256.Sum256(pre)
	x, y := c.ScalarBaseMult([]byte{2})
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: c, X: x, Y: y}, h[:], new(big.Int).SetBytes(high[:32]), new(big.Int).SetBytes(high[32:])) {
		t.Fatal("review high-S twin equation absent")
	}
	reviewAssembleNo(t, p, key, high)
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(c.Params().N, big.NewInt(1)), new(big.Int).Set(c.Params().N), new(big.Int).Rsh(new(big.Int).Set(c.Params().N), 1)} {
		for _, offset := range []int{0, 32} {
			raw := bytes.Clone(sig)
			v.FillBytes(raw[offset : offset+32])
			if bytes.Equal(raw, sig) {
				t.Fatal("review scalar witness unchanged")
			}
			reviewAssembleNo(t, p, key, raw)
		}
	}
	for _, wrongKey := range []string{key + "\x00", key + "\n", strings.Replace(key, "p256:", "P256:", 1), key + "=", strings.Repeat("k", 8193)} {
		reviewAssembleNo(t, p, wrongKey, sig)
	}
	for name, raw := range map[string][]byte{"signed-digest": h[:], "review": d.Review, "render": d.Render, "A": d.Arguments, "body": f.body, "ID": []byte(d.ContentID), "domain-nul": bytes.Replace(pre, []byte("/1\n"), []byte("/1\x00"), 1), "no-domain": pre[bytes.IndexByte(pre, '\n')+1:], "role-endorsing": bytes.Replace(pre, []byte(`"role":"approver"`), []byte(`"role":"endorser"`), 1), "whitespace-record": bytes.Replace(pre, []byte(`{"body":`), []byte(`{ "body":`), 1)} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, pre) {
				t.Fatal("review wrong-message witness absent")
			}
			reviewAssembleNo(t, p, key, reviewAssembleSign(t, raw, 2))
		})
	}
}

// Every operation's completed result and its value copy survive caller buffer,
// snapshot, later result and failure mutations. JSON/zero construction cannot
// resurrect a private plan/result. No unsafe concurrent mutation is claimed.
func TestReviewAssembleDetachedResults(t *testing.T) {
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		t.Run(op, func(t *testing.T) {
			f := prepareFixtureFor(t, op)
			p, before := prepareAccept(t, f)
			sig := reviewAssembleSign(t, reviewAssemblePre(f), 1)
			want := reviewAssembleWire(f, sig)
			r := reviewAssembleYes(t, p, f, sig)
			copyResult := *r
			copyPlan := *p
			second := reviewAssembleYes(t, &copyPlan, f, sig)
			for _, entry := range []*verifier.VerifiedOwnerActEnvelope{r, &copyResult, second} {
				b, ok := entry.Bytes()
				if !ok {
					t.Fatal("review result missing")
				}
				clear(b)
				b = append(b[:0], []byte("forged")...)
				_ = b
				for _, other := range []*verifier.VerifiedOwnerActEnvelope{r, &copyResult, second} {
					raw, ok := other.Bytes()
					if !ok || !bytes.Equal(raw, want) {
						t.Fatal("review result alias changed retained bytes")
					}
				}
			}
			view, _ := p.Snapshot()
			for _, b := range [][]byte{view.Body, view.Arguments, view.Render, view.Review, view.SigningPreimage} {
				clear(b)
			}
			view.Selection = verifier.OwnerActPreparationContext{}
			view.ContentID = "changed"
			view.PredictedEnvelopeBytes = 0
			reviewAssembleYes(t, p, f, sig)
			reviewAssembleNo(t, p, prepareOtherKey, sig)
			clear(sig)
			clear(f.body)
			clear(f.args)
			f.enrollment["device"] = prepareOtherKey
			raw, ok := r.Bytes()
			after, _ := p.Snapshot()
			if !ok || !bytes.Equal(raw, want) || !reflect.DeepEqual(before, after) {
				t.Fatal("review input/later call changed old result")
			}
		})
	}
	var p verifier.OwnerActSigningPlan
	var r verifier.VerifiedOwnerActEnvelope
	if err := json.Unmarshal([]byte(`{"state":{"wire":"forged","data":{"Key":"fake"}}}`), &p); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"state":{"wire":"forged"}}`), &r); err != nil {
		t.Fatal(err)
	}
	for _, q := range []*verifier.OwnerActSigningPlan{nil, &p, new(verifier.OwnerActSigningPlan)} {
		reviewAssembleNo(t, q, prepareKey, make([]byte, 64))
	}
	for _, q := range []*verifier.VerifiedOwnerActEnvelope{nil, &r, new(verifier.VerifiedOwnerActEnvelope)} {
		b, ok := q.Bytes()
		if ok || b != nil {
			t.Fatal("review forged result admitted")
		}
	}
}

// A separately constructed SOH/backslash/target witness attains the joint
// stricter maxima with real signatures, then true-bit and A-length neighbors.
// Missing consumer facts still refuse the assembled signed intent unchanged.
func TestReviewAssembleBoundAndConsumerSeparation(t *testing.T) {
	f := reviewAssembleFixture(t, "mirror-enable", 3)
	f.owner(strings.Repeat("\x01", 255))
	for _, b := range []*[]byte{&f.body, &f.render} {
		*b = bytes.Replace(*b, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("z", 63)+`"`), 1)
	}
	f.argument("source_room", "room", strings.Repeat(`\`, 255))
	f.argument("source_recipient", "service", strings.Repeat(`\`, 255))
	f.argument("owner_recipient", "owner", strings.Repeat(`\`, 255))
	f.argument("bound_room", "bound", strings.Repeat("q", 136))
	p, d := prepareAccept(t, f)
	sig := reviewAssembleSign(t, reviewAssemblePre(f), 3)
	r := reviewAssembleYes(t, p, f, sig)
	wire, _ := r.Bytes()
	if len(f.body) != 2043 || len(f.args) != 2048 || len(f.render) != 4021 || len(d.SigningPreimage) != 2186 || len(wire) != 2348 {
		t.Fatal("review reachable size witness")
	}
	t.Logf("independent real joint sizes body=%d A=%d Render=%d preimage=%d envelope=%d", len(f.body), len(f.args), len(f.render), len(d.SigningPreimage), len(wire))
	v := verifier.New(verifier.Context{})
	for _, got := range []verifier.Result{v.VerifyEnvelope(wire, "operator-act/1"), v.VerifyOperator(wire), v.VerifyOwnerAct(wire, f.args, f.render, verifier.OwnerActContext{})} {
		if got.Code != "signer_unavailable" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
			t.Fatalf("review missing independent consumer facts: %s", got.Code)
		}
	}
	f.body = bytes.Replace(f.body, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1)
	f.render = bytes.Replace(f.render, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1)
	f.rehash()
	q, e := prepareAccept(t, f)
	s := reviewAssembleSign(t, reviewAssemblePre(f), 3)
	out := reviewAssembleYes(t, q, f, s)
	b, _ := out.Bytes()
	if len(f.body) != 2042 || len(f.render) != 4020 || len(e.SigningPreimage) != 2185 || len(b) != 2347 {
		t.Fatal("review true positive size neighbor")
	}
	reviewAssembleNo(t, p, reviewAssembleKey(3), s)
	f.argument("bound_room", strings.Repeat("q", 136), strings.Repeat("q", 137))
	prepareReject(t, f, "preparation_too_large")
}
