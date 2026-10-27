package verifier_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Raw Unicode owner bytes are legitimate independent identities. A fully
// re-signed normalized spelling still cannot match another enrolled owner.
// Opaque room/recipient identifiers use the existing ASCII grammar, without
// case folding, decoding aliases, trimming or a second identity parser.
func TestOwnerActsIdentityNormalization(t *testing.T) {
	t.Run("actual-text-case", func(t *testing.T) {
		x := ownerActControl(t, "owner-dm.unbind")
		x.m.Render = bytes.Replace(x.m.Render, []byte("owner-a"), []byte("OWNER-A"), 1)
		x.check(t, "act_binding_mismatch")
	})
	for _, owner := range []string{"owner-a", "é", "e\u0301", "Оwner", "owner\u00a0a", "owner\u2028a"} {
		t.Run(fmt.Sprintf("literal-%x", owner), func(t *testing.T) { ownerActOwnerControl(t, "owner-dm.unbind", owner).check(t, "accept") })
	}
	for _, pair := range [][2]string{{"e\u0301", "é"}, {"é", "e\u0301"}, {"owner-a", "OWNER-A"}, {"owner-a", "owner-a "}, {"owner-a", "оwner-a"}} {
		t.Run(fmt.Sprintf("owner-%x-to-%x", pair[0], pair[1]), func(t *testing.T) {
			x := ownerActOwnerControl(t, "owner-dm.unbind", pair[0])
			x.in.Owner = pair[1]
			x.remap(t)
			x.check(t, "act_binding_mismatch")
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*ownerActFixture)
	}{
		{"source-room-case", func(x *ownerActFixture) { x.in.Arguments.SourceRoom = "!SOURCE:example.test" }},
		{"source-room-percent", func(x *ownerActFixture) { x.in.Arguments.SourceRoom = "!%73ource:example.test" }},
		{"source-recipient-case", func(x *ownerActFixture) { x.in.Arguments.SourceRecipient = "@Consumer:example.test" }},
		{"owner-recipient-case", func(x *ownerActFixture) { x.in.Arguments.OwnerRecipient = "@Owner:example.test" }},
		{"bound-room-case", func(x *ownerActFixture) { x.in.Arguments.BoundRoom = "!BOUND:example.test" }},
		{"epoch-other", func(x *ownerActFixture) { x.in.Epoch = "epoch:" + strings.Repeat("c", 32) }},
		{"identity-other", func(x *ownerActFixture) { x.in.Identity = "slot-2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			tc.change(x)
			x.remap(t)
			x.check(t, "act_binding_mismatch")
		})
	}
	for _, spelling := range []string{"owner-acts/2", "Owner-acts/1", "owner-acts/1 ", "owner-acts/01"} {
		t.Run(spelling, func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			x.m.Arguments = bytes.Replace(x.m.Arguments, []byte("owner-acts/1"), []byte(spelling), 1)
			x.check(t, "act_binding_mismatch")
		})
	}
}

// The one Render separator and all separately delivered text bytes are exact.
// JSON envelope whitespace remains transport syntax, not text normalization.
func TestOwnerActsIdentityLineEndings(t *testing.T) {
	for _, line := range []string{"\r", "\r\n", "\u0085", "\u2028", "\u2029", "\n\n", ""} {
		t.Run(fmt.Sprintf("separator-%x", line), func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			x.m.Render = bytes.Replace(x.m.Render, []byte("\n"), []byte(line), 1)
			x.check(t, "act_binding_mismatch")
		})
	}
	for _, line := range []string{"\n", "\r", "\r\n", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprintf("argument-layout-%x", line), func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			x.m.Arguments = append([]byte(line), x.m.Arguments...)
			x.check(t, "act_binding_mismatch")
		})
	}
	ownerActControl(t, "owner-dm.unbind").check(t, "accept")
}

// No trailing bytes can be dropped from A or actual text, even whitespace.
// Envelope trailing JSON whitespace is permitted until exact journal identity
// is present; the same content ID with different raw bytes then conflicts.
func TestOwnerActsIdentityTrailingBytes(t *testing.T) {
	for _, tail := range []string{" ", "\t", "\n", "\r\n", "\u0085", "\u2028", "\u2029", "\x00", "{}", "x"} {
		for _, which := range []string{"text", "arguments"} {
			t.Run(fmt.Sprintf("%s-%x", which, tail), func(t *testing.T) {
				x := ownerActControl(t, "owner-dm.unbind")
				if which == "text" {
					x.m.Render = append(x.m.Render, []byte(tail)...)
				} else {
					x.m.Arguments = append(x.m.Arguments, []byte(tail)...)
				}
				x.check(t, "act_binding_mismatch")
			})
		}
	}
	x := ownerActControl(t, "owner-dm.unbind")
	raw := targetWire(t, x.f.e)
	for _, tail := range []string{" ", "\n", "\r\n"} {
		got := verifier.New(x.c).VerifyOwnerAct(append(bytes.Clone(raw), []byte(tail)...), x.m.Arguments, x.m.Render, x.p)
		if got.Code != "accept" {
			t.Fatal("permitted envelope transport", got)
		}
	}
	x.c.IDJournal = evidence(t, map[string]any{x.m.ContentID: raw})
	got := verifier.New(x.c).VerifyOwnerAct(append(bytes.Clone(raw), ' '), x.m.Arguments, x.m.Render, x.p)
	assertOwnerActRefusal(t, got, "envelope_conflict")
	x.check(t, "accept")
}

// Canonical A is independent of permissible envelope transport spellings.
// Envelope escape/order changes keep the actual signed semantic preimage.
func TestOwnerActsIdentityCanonicalArguments(t *testing.T) {
	x := ownerActControl(t, "owner-dm.unbind")
	raw := targetWire(t, x.f.e)
	for _, wire := range [][]byte{append([]byte("\r\n"), raw...), bytes.Replace(raw, []byte(`"owner-a"`), []byte(`"owner-\u0061"`), 1), bytes.Replace(raw, []byte(`"target":{"id":"slot","kind":"owner-dm"}`), []byte(`"target":{"kind":"owner-dm","id":"slot"}`), 1)} {
		got := verifier.New(x.c).VerifyOwnerAct(wire, x.m.Arguments, x.m.Render, x.p)
		if got.Code != "accept" {
			t.Fatal(got)
		}
	}
	x.m.Arguments = bytes.Replace(x.m.Arguments, []byte(`"owner-acts/1"`), []byte(`"owner-acts\/1"`), 1)
	x.check(t, "act_binding_mismatch")
}
