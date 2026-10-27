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

// Public test-only scalars D=1 (G) and D=N-1 (-G), not production keys or a
// provider fallback. Go's deterministic RFC6979 signer supplies genuine equation
// witnesses independently of record.VerifySignature. DER handling is test-only.
func assembleTestKey(other bool) *ecdsa.PrivateKey {
	c := elliptic.P256()
	d := big.NewInt(1)
	if other {
		d.Sub(c.Params().N, d)
	}
	x, y := c.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}
}
func assembleSign(t *testing.T, pre []byte, other bool) []byte {
	t.Helper()
	h := sha256.Sum256(pre)
	k := assembleTestKey(other)
	der, err := k.Sign(nil, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &pair)
	if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil {
		t.Fatal("test signature decode", err)
	}
	n := k.Curve.Params().N
	if pair.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		pair.S.Sub(n, pair.S)
	}
	if !ecdsa.Verify(&k.PublicKey, h[:], pair.R, pair.S) {
		t.Fatal("independent signature equation")
	}
	raw := make([]byte, 64)
	pair.R.FillBytes(raw[:32])
	pair.S.FillBytes(raw[32:])
	return raw
}

// Independently specified complete canonical wire oracle. It uses the literal
// normative domain and exact fixture body, never the candidate's serialization,
// record.ContentID/SigningPreimage, or a parsed candidate as its expected source.
func assembleExpected(f prepareFixture, sig []byte) []byte {
	id := prepareDigest(append([]byte("swarma-waggle operator-act/1\n"), f.body...))
	return []byte(`{"body":` + string(f.body) + `,"id":"` + id + `","signatures":[{"key":"` + f.enrollment["device"].(string) + `","role":"approver","sig":"` + base64.RawURLEncoding.EncodeToString(sig) + `"}],"version":"swarm-envelope/2"}`)
}
func assembleAccept(t *testing.T, p *verifier.OwnerActSigningPlan, f prepareFixture, sig []byte) *verifier.VerifiedOwnerActEnvelope {
	t.Helper()
	before, _ := p.Snapshot()
	input := bytes.Clone(sig)
	r, err := verifier.AssembleOwnerAct(p, f.enrollment["device"].(string), sig)
	if err != nil || r == nil {
		t.Fatalf("valid signed intent refused: %v", err)
	}
	wire, ok := r.Bytes()
	if !ok || !bytes.Equal(wire, assembleExpected(f, sig)) {
		t.Fatal("full canonical wire differs from independent literal expectation")
	}
	if len(wire) != before.PredictedEnvelopeBytes || len(wire) > 8192 {
		t.Fatal("exact predicted envelope size differs")
	}
	after, _ := p.Snapshot()
	if !reflect.DeepEqual(before, after) || !bytes.Equal(input, sig) {
		t.Fatal("assembly changed plan or signature input")
	}
	return r
}
func assembleReject(t *testing.T, p *verifier.OwnerActSigningPlan, key string, sig []byte) {
	t.Helper()
	// Each negative has an adjacent genuine positive and an older retained result
	// whose complete bytes must survive failure, rather than only checking error.
	control := prepareFixtureFor(t, "unbind")
	cp, _ := prepareAccept(t, control)
	good := assembleSign(t, control.preimage, false)
	old := assembleAccept(t, cp, control, good)
	oldExpected := bytes.Clone(assembleExpected(control, good))
	before, beforeOK := p.Snapshot()
	input := bytes.Clone(sig)
	r, err := verifier.AssembleOwnerAct(p, key, sig)
	var local *verifier.OwnerActAssemblyError
	if r != nil || !errors.As(err, &local) || local.Code != "assembly_invalid" || err.Error() != "assembly_invalid" {
		t.Fatalf("want assembly_invalid and nil whole output, got result=%v error=%v", r != nil, err)
	}
	after, afterOK := p.Snapshot()
	wire, ok := old.Bytes()
	if !reflect.DeepEqual(before, after) || beforeOK != afterOK || !bytes.Equal(input, sig) || !ok || !bytes.Equal(wire, oldExpected) {
		t.Fatal("failure mutated input, plan or another result")
	}
	assembleAccept(t, cp, control, good)
}

// Formal identity/normalisation: genuine signatures accept only the exact
// independently prepared Unicode/whitespace/control spelling. Labels are local
// review data, not signed replacements. Literal backslash escapes remain data;
// alternate noncanonical JSON escape spelling cannot replace the signed bytes.
func TestAssembleIdentityNormalization(t *testing.T) {
	for _, pair := range [][2]string{
		{"é", "e\u0301"}, {" owner", "owner"}, {"owner ", "owner"}, {"OWNER", "owner"},
		{"a\u00a0b", "a b"}, {"a\u200bb", "ab"}, {"a\u202eb", "ab"}, {"a\x00b", "ab"}, {"a\x7fb", "ab"},
		{"é", `\u00e9`}, {"a\tb", "a b"},
	} {
		t.Run(fmt.Sprintf("%x-vs-%x", pair[0], pair[1]), func(t *testing.T) {
			f, g := prepareFixtureFor(t, "unbind"), prepareFixtureFor(t, "unbind")
			f.owner(pair[0])
			g.owner(pair[1])
			f.enrollment["installation"] = "local" + pair[0]
			p, d := prepareAccept(t, f)
			q, e := prepareAccept(t, g)
			prepareExactData(t, f, d)
			prepareExactData(t, g, e)
			s, other := assembleSign(t, f.preimage, false), assembleSign(t, g.preimage, false)
			assembleAccept(t, p, f, s)
			assembleAccept(t, q, g, other)
			if d.ContentID == e.ContentID || bytes.Equal(f.preimage, g.preimage) {
				t.Fatal("raw identity pair collapsed")
			}
			assembleReject(t, p, prepareKey, other)
			assembleReject(t, q, prepareKey, s)
			// A rewrite after mapping changes only the raw message, leaving the
			// original arguments digest. This narrower witness is not a second
			// fully remapped plan; its signature must also be refused.
			for _, raw := range []struct {
				original, replacement string
				plan                  *verifier.OwnerActSigningPlan
				pre                   []byte
			}{
				{pair[0], pair[1], p, f.preimage}, {pair[1], pair[0], q, g.preimage},
			} {
				changed := bytes.Replace(raw.pre, []byte(prepareJSON(raw.original)), []byte(prepareJSON(raw.replacement)), 1)
				if bytes.Equal(changed, raw.pre) {
					t.Fatal("normalisation witness not applied")
				}
				assembleReject(t, raw.plan, prepareKey, assembleSign(t, changed, false))
			}
		})
	}
	f := prepareFixtureFor(t, "unbind")
	p, _ := prepareAccept(t, f)
	assembleAccept(t, p, f, assembleSign(t, f.preimage, false))
	// Equivalent JSON value received as an alternate literal escape still names
	// different raw message bytes. The old canonical parser refuses it pre-plan.
	changed := bytes.Replace(f.preimage, []byte(`"owner":"owner"`), []byte(`"owner":"\u006fwner"`), 1)
	assembleReject(t, p, prepareKey, assembleSign(t, changed, false))
	f.body = bytes.Replace(f.body, []byte(`"owner":"owner"`), []byte(`"owner":"\u006fwner"`), 1)
	prepareReject(t, f, "preparation_invalid")
}

// Formal identity/line-ending rewrite: exact CR/LF/CRLF/NEL/LS/PS owners have
// genuine original signatures and distinct transformed signatures. Complete
// canonical body/A/preimage/wire are checked. A's printable-ASCII schema cannot
// admit EOL literals; those are explicitly inherited pre-plan refusals.
func TestAssembleIdentityLineEndings(t *testing.T) {
	for _, line := range []string{"\r", "\n", "\r\n", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprintf("%x", line), func(t *testing.T) {
			f, g := prepareFixtureFor(t, "unbind"), prepareFixtureFor(t, "unbind")
			f.owner("a" + line + "b")
			f.enrollment["installation"] = "local" + line + "name"
			rewrite := "\n"
			if line == "\n" {
				rewrite = "\r"
			}
			g.owner("a" + rewrite + "b")
			p, d := prepareAccept(t, f)
			q, e := prepareAccept(t, g)
			prepareExactData(t, f, d)
			prepareExactData(t, g, e)
			s, wrong := assembleSign(t, f.preimage, false), assembleSign(t, g.preimage, false)
			assembleAccept(t, p, f, s)
			assembleAccept(t, q, g, wrong)
			assembleReject(t, p, prepareKey, wrong)
			assembleReject(t, q, prepareKey, s)
			// Catch EOL rewriting of the raw message AFTER hashes were bound,
			// independently of a fully remapped second plan's changed digest.
			changed := bytes.Replace(f.preimage, []byte(prepareJSON("a"+line+"b")), []byte(prepareJSON("a"+rewrite+"b")), 1)
			if bytes.Equal(changed, f.preimage) {
				t.Fatal("line rewrite witness not applied")
			}
			assembleReject(t, p, prepareKey, assembleSign(t, changed, false))
			// Rewriting the raw domain delimiter is distinct from scalar escaping.
			pre := bytes.Replace(f.preimage, []byte("/1\n"), []byte("/1"+line), 1)
			if !bytes.Equal(pre, f.preimage) {
				assembleReject(t, p, prepareKey, assembleSign(t, pre, false))
			}
			a := prepareFixtureFor(t, "unbind")
			a.argument("source_room", "room", "r"+line+"m")
			prepareReject(t, a, "preparation_invalid")
		})
	}
}

// Formal identity/trailing bytes: the NEW API rejects genuine signatures over
// original preimage plus trailers or dropped bytes; inherited strict body/A
// framing refusals happen before a plan. Escaped literal trailers remain valid.
func TestAssembleIdentityTrailingBytes(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	f.owner("owner\x00\n ")
	p, d := prepareAccept(t, f)
	prepareExactData(t, f, d)
	assembleAccept(t, p, f, assembleSign(t, f.preimage, false))
	for _, tail := range []string{"\n", "\r", "\r\n", "\x00", " ", "\t", "{}", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprintf("%x", tail), func(t *testing.T) {
			assembleReject(t, p, prepareKey, assembleSign(t, append(bytes.Clone(f.preimage), tail...), false))
			for _, which := range []string{"body", "arguments"} {
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
	for _, pre := range [][]byte{f.preimage[:len(f.preimage)-1], f.preimage[1:], bytes.TrimSuffix(f.preimage, []byte(`"}`))} {
		if bytes.Equal(pre, f.preimage) {
			t.Fatal("dropped-byte witness not applied")
		}
		assembleReject(t, p, prepareKey, assembleSign(t, pre, false))
	}
	// Whitespace within an opaque body scalar cannot be trimmed before hashing.
	g := prepareFixtureFor(t, "unbind")
	g.owner(strings.TrimSpace(" owner "))
	q, _ := prepareAccept(t, g)
	assembleAccept(t, q, g, assembleSign(t, g.preimage, false))
	assembleReject(t, p, prepareKey, assembleSign(t, g.preimage, false))
}
