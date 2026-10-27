package verifier_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Fixture-only literal layout oracle, independent of encoding/binary and the
// production parser. There is deliberately no product request encoder.
func frameU32(n uint32) []byte { return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)} }
func frameIDs() (correlation, selector [32]byte) {
	for i := range correlation {
		correlation[i], selector[i] = byte(i), byte(255-i)
	}
	selector[7] = 0
	return
}
func frameRequest(body, arguments []byte, correlation, selector [32]byte) []byte {
	b := append([]byte("SEACT001"), correlation[:]...)
	b = append(b, selector[:]...)
	b = append(b, frameU32(uint32(len(body)))...)
	b = append(b, frameU32(uint32(len(arguments)))...)
	b = append(b, body...)
	return append(b, arguments...)
}
func frameAccept(t *testing.T, raw, body, arguments []byte, correlation, selector [32]byte) verifier.OwnerActRequestFrame {
	t.Helper()
	before := bytes.Clone(raw)
	r, err := verifier.ParseOwnerActRequestFrame(raw)
	if err != nil || r.Correlation != correlation || r.EnrollmentSelector != selector || !bytes.Equal(r.Body, body) || !bytes.Equal(r.Arguments, arguments) {
		t.Fatalf("exact detached frame differs; error=%v", err)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("parse changed input")
	}
	return r
}
func frameReject(t *testing.T, raw []byte) {
	t.Helper()
	before := bytes.Clone(raw)
	r, err := verifier.ParseOwnerActRequestFrame(raw)
	var local *verifier.OwnerActFrameError
	if !errors.As(err, &local) || err.Error() != "frame_invalid" || !reflect.DeepEqual(r, verifier.OwnerActRequestFrame{}) {
		t.Fatalf("want fixed frame_invalid and entirely zero result; got error=%v result=%#v", err, r)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("refusal mutated input")
	}
	f := prepareFixtureFor(t, "unbind")
	c, s := frameIDs()
	frameAccept(t, frameRequest(f.body, f.args, c, s), f.body, f.args, c, s)
}
func frameSigned(t *testing.T, f prepareFixture) (*verifier.VerifiedOwnerActEnvelope, []byte) {
	t.Helper()
	p, _ := prepareAccept(t, f)
	sig := assembleSign(t, f.preimage, false)
	return assembleAccept(t, p, f, sig), assembleExpected(f, sig)
}
func frameExpectedResult(c [32]byte, status byte, envelope []byte) []byte {
	b := append([]byte("SEOUT001"), c[:]...)
	b = append(b, 0, 0, 0, status)
	b = append(b, frameU32(uint32(len(envelope)))...)
	return append(b, envelope...)
}
func frameResultAccept(t *testing.T, c [32]byte, status verifier.OwnerActResultStatus, r *verifier.VerifiedOwnerActEnvelope, envelope []byte) []byte {
	t.Helper()
	out, err := verifier.EncodeOwnerActResultFrame(c, status, r)
	if err != nil || !bytes.Equal(out, frameExpectedResult(c, byte(status), envelope)) {
		t.Fatalf("exact result layout differs: %v", err)
	}
	return out
}

// Formal identity / any normalisation: independently remapped valid owner
// spellings remain exact in BOTH new public directions. This is byte identity,
// not authentication of correlation or native origin. Alternate JSON spellings
// refuse separately; valid exact Unicode must not be rejected to pass negatives.
func TestOwnerActFrameIdentityNormalization(t *testing.T) {
	for i, owner := range []string{"owner", "OWNER", " owner ", "é", "e\u0301", "a\u00a0b", "a\u200bb", "a\x00b", `a\u0000b`, "\"\\"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			f.owner(owner)
			c, s := frameIDs()
			c[15], s[15] = byte(i), byte(255-i)
			raw := frameRequest(f.body, f.args, c, s)
			frameAccept(t, raw, f.body, f.args, c, s)
			r, wire := frameSigned(t, f)
			frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
		})
	}
	f := prepareFixtureFor(t, "unbind")
	c, s := frameIDs()
	for _, pair := range [][2]string{{`"owner":"owner"`, `"owner":"\u006fwner"`}, {`"owner":"owner"`, `"\u006fwner":"owner"`}} {
		b := bytes.Replace(f.body, []byte(pair[0]), []byte(pair[1]), 1)
		frameReject(t, frameRequest(b, f.args, c, s))
	}
	for _, a := range [][]byte{append([]byte(" "), f.args...), bytes.Replace(f.args, []byte("owner-acts/1"), []byte(`owner-acts\/1`), 1)} {
		frameReject(t, frameRequest(f.body, a, c, s))
	}
}

// Formal identity / any line-ending rewrite: canonical escaped CR/LF/CRLF and
// literal NEL/LS/PS inside admissible owners are preserved, including the genuine
// signed envelope. Syntax EOLs outside JSON and raw C0 inside it refuse instead.
func TestOwnerActFrameIdentityLineEndings(t *testing.T) {
	for i, line := range []string{"\r", "\n", "\r\n", "\n\r", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			f.owner("a" + line + "b")
			c, s := frameIDs()
			copy(c[:], []byte(line))
			copy(s[:], []byte(line))
			frameAccept(t, frameRequest(f.body, f.args, c, s), f.body, f.args, c, s)
			r, wire := frameSigned(t, f)
			frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
			frameReject(t, frameRequest(append([]byte(line), f.body...), f.args, c, s))
			frameReject(t, frameRequest(f.body, append(f.args, line...), c, s))
		})
	}
	f := prepareFixtureFor(t, "unbind")
	c, s := frameIDs()
	for _, line := range []string{"\r", "\n", "\r\n"} {
		b := bytes.Replace(f.body, []byte(`"owner":"owner"`), []byte("\"owner\":\"a"+line+"b\""), 1)
		frameReject(t, frameRequest(b, f.args, c, s))
	}
}

// Formal identity / trailing bytes: the WHOLE supplied frame must be consumed,
// independently of canonical subobject consumption. Suffixes and second frames
// are refused, while canonical escaped owner suffix data is preserved in both
// APIs. A complete slice says nothing about a pipe's actual EOF observation.
func TestOwnerActFrameIdentityTrailingBytes(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	f.owner("owner\x00\n ")
	c, s := frameIDs()
	raw := frameRequest(f.body, f.args, c, s)
	frameAccept(t, raw, f.body, f.args, c, s)
	r, wire := frameSigned(t, f)
	frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
	for _, tail := range [][]byte{{0}, {' '}, {'\n'}, {'\r', '\n'}, {0xff}, []byte("{}"), []byte("\u0085"), []byte("\u2028"), []byte("\u2029"), raw} {
		frameReject(t, append(bytes.Clone(raw), tail...))
		frameReject(t, frameRequest(append(bytes.Clone(f.body), tail...), f.args, c, s))
		frameReject(t, frameRequest(f.body, append(bytes.Clone(f.args), tail...), c, s))
	}
	frameReject(t, raw[:len(raw)-1])
}
