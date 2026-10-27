package verifier_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// A cross-product oracle distinguishes success, all four empty error frames,
// and invalid status/envelope combinations. Refusal preserves prior immutable
// bytes, and every combination is followed by an independent valid control.
func TestReviewFrameHuntStatusMatrix(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	var c, s [32]byte
	for i := range c {
		c[i] = byte(255 - i)
		s[i] = byte(i * 7)
	}
	genuine, wire := reviewFramePositive(t, f, c, s)
	var zero, forged verifier.VerifiedOwnerActEnvelope
	if e := json.Unmarshal([]byte("{\"state\":{\"wire\":\"ignored\"}}"), &forged); e != nil {
		t.Fatal(e)
	}
	values := []*verifier.VerifiedOwnerActEnvelope{nil, &zero, &forged, genuine}
	for _, status := range []uint32{0, 1, 2, 3, 4, 5, 255, 256, 65536, 0x80000000, 0xffffffff} {
		for i, v := range values {
			t.Run(fmt.Sprintf("%d/%d", status, i), func(t *testing.T) {
				out, e := verifier.EncodeOwnerActResultFrame(c, verifier.OwnerActResultStatus(status), v)
				valid := status == 0 && i == 3 || status >= 1 && status <= 4 && i == 0
				if valid {
					var payload []byte
					if status == 0 {
						payload = wire
					}
					if e != nil || !bytes.Equal(out, reviewFrameOutput(c, status, payload)) {
						t.Fatal("exact result matrix mismatch", e)
					}
					clear(out)
				} else {
					var local *verifier.OwnerActFrameError
					if out != nil || !errors.As(e, &local) || e.Error() != "frame_invalid" {
						t.Fatal("invalid matrix cell admitted", status, i, e)
					}
				}
				stored, ok := genuine.Bytes()
				if !ok || !bytes.Equal(stored, wire) {
					t.Fatal("prior immutable result changed")
				}
				good, e := verifier.EncodeOwnerActResultFrame(c, 0, genuine)
				if e != nil || !bytes.Equal(good, reviewFrameOutput(c, 0, wire)) {
					t.Fatal("adjacent valid result failed", e)
				}
			})
		}
	}
}

// Grammar admission does not match body/A or protected owner selection.
// Pin context BEFORE constructing the received mismatch; prove the real next
// public preparation step refuses exactly, while unchanged input still works.
func TestReviewFrameHuntPreparationBoundary(t *testing.T) {
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		t.Run(op, func(t *testing.T) {
			f := prepareFixtureFor(t, op)
			context := f.context(t)
			var c, s [32]byte
			for _, change := range []string{"owner", "arguments"} {
				body, args := bytes.Clone(f.body), bytes.Clone(f.args)
				if change == "owner" {
					body = bytes.Replace(body, []byte("\"owner\":\"owner\""), []byte("\"owner\":\"other\""), 1)
				} else {
					args = bytes.Replace(args, []byte("\"source_room\":\"room\""), []byte("\"source_room\":\"other\""), 1)
				}
				if bytes.Equal(body, f.body) && bytes.Equal(args, f.args) {
					t.Fatal("unapplied mismatch")
				}
				raw := reviewFrameInput(body, args, c, s)
				got, e := verifier.ParseOwnerActRequestFrame(raw)
				if e != nil || !bytes.Equal(got.Body, body) || !bytes.Equal(got.Arguments, args) {
					t.Fatal("grammar wrongly enforces association", e)
				}
				p, e := verifier.PrepareOwnerAct(got.Body, got.Arguments, context)
				var local *verifier.OwnerActPreparationError
				if p != nil || !errors.As(e, &local) || local.Code != "preparation_mismatch" {
					t.Fatal("independent preparation mismatch lost", e)
				}
				p, e = verifier.PrepareOwnerAct(f.body, f.args, context)
				if p == nil || e != nil {
					t.Fatal("adjacent valid plan refused", e)
				}
				clear(raw)
				if !bytes.Equal(got.Body, body) || !bytes.Equal(got.Arguments, args) {
					t.Fatal("borrowed request buffers")
				}
				copyOf := got
				copyOf.Body[0] ^= 1
				if copyOf.Body[0] != got.Body[0] {
					t.Fatal("ordinary value-copy slice semantics unexpectedly changed")
				}
			}
		})
	}
}

// This independently varied public-constructor witness attains the schema
// bound derived in the review report. It is not alone a universal bound proof.
func TestReviewFrameHuntMaximumWitness(t *testing.T) {
	f := prepareFixtureFor(t, "mirror-enable")
	f.owner(strings.Repeat("\x01", 255))
	for _, b := range []*[]byte{&f.body, &f.render} {
		*b = bytes.Replace(*b, []byte("\"id\":\"identity\""), []byte("\"id\":\""+strings.Repeat("z", 63)+"\""), 1)
	}
	f.argument("source_room", "room", strings.Repeat("\\", 255))
	f.argument("source_recipient", "service", strings.Repeat("\\", 255))
	f.argument("owner_recipient", "owner", strings.Repeat("\\", 255))
	f.argument("bound_room", "bound", strings.Repeat("c", 136))
	var c, s [32]byte
	_, wire := reviewFramePositive(t, f, c, s)
	if len(f.body) != 2043 || len(f.args) != 2048 || len(reviewFrameInput(f.body, f.args, c, s)) != 4171 || len(wire) != 2348 || len(reviewFrameOutput(c, 0, wire)) != 2396 {
		t.Fatal("joint reachable maximum differs")
	}
	t.Logf("body=%d A=%d request=%d envelope=%d result=%d", len(f.body), len(f.args), 80+len(f.body)+len(f.args), len(wire), 48+len(wire))
	f.argument("bound_room", strings.Repeat("c", 136), strings.Repeat("c", 137))
	if len(f.args) != 2049 {
		t.Fatal("neighbor not applied")
	}
	got, e := verifier.ParseOwnerActRequestFrame(reviewFrameInput(f.body, f.args, c, s))
	var local *verifier.OwnerActFrameError
	if !errors.As(e, &local) || e.Error() != "frame_invalid" || got.Body != nil || got.Arguments != nil || got.Correlation != ([32]byte{}) || got.EnrollmentSelector != ([32]byte{}) {
		t.Fatal("2049 neighbor admitted", e)
	}
}
