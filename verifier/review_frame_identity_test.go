package verifier_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Independent literal offsets and byte shifts implement the normative fixture
// layout only; no product encoder/decoder output supplies an expected field.
func reviewFramePut(dst []byte, n uint32) {
	dst[0], dst[1], dst[2], dst[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
}
func reviewFrameInput(body, args []byte, c, s [32]byte) []byte {
	out := make([]byte, 80+len(body)+len(args))
	copy(out[:8], "SEACT001")
	copy(out[8:40], c[:])
	copy(out[40:72], s[:])
	reviewFramePut(out[72:76], uint32(len(body)))
	reviewFramePut(out[76:80], uint32(len(args)))
	copy(out[80:], body)
	copy(out[80+len(body):], args)
	return out
}
func reviewFrameOutput(c [32]byte, status uint32, payload []byte) []byte {
	out := make([]byte, 48+len(payload))
	copy(out[:8], "SEOUT001")
	copy(out[8:40], c[:])
	reviewFramePut(out[40:44], status)
	reviewFramePut(out[44:48], uint32(len(payload)))
	copy(out[48:], payload)
	return out
}
func reviewFramePositive(t *testing.T, f prepareFixture, c, s [32]byte) (*verifier.VerifiedOwnerActEnvelope, []byte) {
	t.Helper()
	raw := reviewFrameInput(f.body, f.args, c, s)
	before := bytes.Clone(raw)
	got, e := verifier.ParseOwnerActRequestFrame(raw)
	if e != nil || got.Correlation != c || got.EnrollmentSelector != s || !bytes.Equal(got.Body, f.body) || !bytes.Equal(got.Arguments, f.args) || !bytes.Equal(raw, before) {
		t.Fatal("original request bytes/IDs changed or refused", e)
	}
	p, e := verifier.PrepareOwnerAct(f.body, f.args, f.context(t))
	if e != nil {
		t.Fatal("genuine fixture preparation", e)
	}
	sig := assembleSign(t, f.preimage, false)
	d, ok := p.Snapshot()
	if !ok {
		t.Fatal("fixture snapshot")
	}
	r, e := verifier.AssembleOwnerAct(p, d.Key, sig)
	if e != nil {
		t.Fatal("genuine fixture assembly", e)
	}
	wire := reviewNativeExpected(f, sig) // retained original literal full-wire oracle
	out, e := verifier.EncodeOwnerActResultFrame(c, verifier.OwnerActResultSuccess, r)
	if e != nil || !bytes.Equal(out, reviewFrameOutput(c, 0, wire)) {
		t.Fatal("original genuine signed bytes/result header changed", e)
	}
	again, _ := p.Snapshot()
	if !reflect.DeepEqual(d, again) {
		t.Fatal("frame operation changed prior plan")
	}
	return r, wire
}
func reviewFrameRefusals(t *testing.T, f prepareFixture, bad [][]byte) {
	t.Helper()
	var c, s [32]byte
	c[0] = 0xff
	s[31] = 0x80
	good := reviewFrameInput(f.body, f.args, c, s)
	prior, e := verifier.ParseOwnerActRequestFrame(good)
	if e != nil {
		t.Fatal(e)
	}
	r, wire := reviewFramePositive(t, f, c, s)
	for i, raw := range bad {
		before := bytes.Clone(raw)
		got, e := verifier.ParseOwnerActRequestFrame(raw)
		var local *verifier.OwnerActFrameError
		if !errors.As(e, &local) || e.Error() != "frame_invalid" || !reflect.DeepEqual(got, verifier.OwnerActRequestFrame{}) {
			t.Fatalf("case%d: exact refusal/whole-zero violated: %v", i, e)
		}
		if !bytes.Equal(raw, before) || !bytes.Equal(prior.Body, f.body) || !bytes.Equal(prior.Arguments, f.args) || prior.Correlation != c || prior.EnrollmentSelector != s {
			t.Fatal("refusal changed caller/prior request")
		}
		stored, ok := r.Bytes()
		if !ok || !bytes.Equal(stored, wire) {
			t.Fatal("refusal changed retained verified result")
		}
		next, e := verifier.ParseOwnerActRequestFrame(good)
		if e != nil || !bytes.Equal(next.Body, f.body) || !bytes.Equal(next.Arguments, f.args) {
			t.Fatal("adjacent valid input refused", e)
		}
	}
}

// Formal normalization: independently remapped NFC/NFD, controls and invisible
// owners each survive both public directions exactly. Alternate JSON spellings
// refuse; grammar-only ownership does not authenticate correlation or enrollment.
func TestReviewFrameIdentityNormalization(t *testing.T) {
	seen := map[string]bool{}
	owners := []string{"é", "e\u0301", "Å", "A\u030a", " owner ", "owner", "a\u00a0b", "a\u200bb", "a\u202eb", "a\x00b", "a\x7fb", "a\tb", "a\\u0000b", "\"\\", "a\u2060b"}
	for i, owner := range owners {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			f.owner(owner)
			var c, s [32]byte
			for j := range c {
				c[j] = byte(i*17 + j)
				s[j] = byte(255 - i - j)
			}
			_, wire := reviewFramePositive(t, f, c, s)
			if seen[string(wire)] {
				t.Fatal("distinct original owner bytes collapsed")
			}
			seen[string(wire)] = true
		})
	}
	f := prepareFixtureFor(t, "unbind")
	var c, s [32]byte
	badBody := bytes.Replace(f.body, []byte("\"owner\":\"owner\""), []byte("\"owner\":\"\\u006fwner\""), 1)
	if bytes.Equal(badBody, f.body) {
		t.Fatal("unapplied alternative spelling")
	}
	escapedKey := bytes.Replace(f.body, []byte("\"owner\":"), []byte("\"\\u006fwner\":"), 1)
	badArgs := bytes.Replace(f.args, []byte("owner-acts/1"), []byte("owner-acts\\/1"), 1)
	reviewFrameRefusals(t, f, [][]byte{reviewFrameInput(badBody, f.args, c, s), reviewFrameInput(escapedKey, f.args, c, s), reviewFrameInput(f.body, badArgs, c, s)})
}

// Formal line-ending family distinguishes valid escaped data from noncanonical
// framing syntax and raw C0 JSON. Every valid variant also encodes genuine wire.
func TestReviewFrameIdentityLineEndings(t *testing.T) {
	for _, line := range []string{"\r", "\n", "\r\n", "\n\r", "\u0085", "\u2028", "\u2029"} {
		f := prepareFixtureFor(t, "unbind")
		f.owner("before" + line + "after")
		var c, s [32]byte
		copy(c[:], line)
		copy(s[16:], line)
		reviewFramePositive(t, f, c, s)
		bad := [][]byte{reviewFrameInput(append([]byte(line), f.body...), f.args, c, s), reviewFrameInput(f.body, append(bytes.Clone(f.args), line...), c, s)}
		if line == "\r" || line == "\n" || line == "\r\n" {
			raw := bytes.Replace(f.body, []byte(prepareJSON("before"+line+"after")), []byte("\"before"+line+"after\""), 1)
			bad = append(bad, reviewFrameInput(raw, f.args, c, s))
		}
		reviewFrameRefusals(t, f, bad)
	}
}

// Formal trailers: whole-frame suffixes, second frames, truncated payload and
// inner-object suffixes with corrected lengths must all refuse without effects.
func TestReviewFrameIdentityTrailingBytes(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	f.owner("owner \x00\r\n")
	var c, s [32]byte
	raw := reviewFrameInput(f.body, f.args, c, s)
	var bad [][]byte
	for _, tail := range [][]byte{{0}, {0xff}, []byte(" "), []byte("\r"), []byte("\n"), []byte("\r\n"), []byte("\u0085"), []byte("\u2028"), []byte("\u2029"), []byte("{}"), raw} {
		bad = append(bad, append(bytes.Clone(raw), tail...), reviewFrameInput(append(bytes.Clone(f.body), tail...), f.args, c, s), reviewFrameInput(f.body, append(bytes.Clone(f.args), tail...), c, s))
	}
	bad = append(bad, bytes.Clone(raw[:79]), bytes.Clone(raw[:80+len(f.body)]), bytes.Clone(raw[:len(raw)-1]))
	reviewFrameRefusals(t, f, bad)
}
