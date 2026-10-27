package verifier_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

// Exact UTF-8 owner values remain valid even with control or trailing bytes;
// complete re-signing cannot make another owner equal the protected enrollment.
// Opaque printable ASCII values are not interpreted as carrier aliases here.
func TestReviewOwnerActLiteralIdentities(t *testing.T) {
	seen := map[string]bool{}
	for _, owner := range []string{"owner\r", "owner\n", "owner\r\n", "owner\u0085", "owner\u2028", "owner\u2029", "owner ", "owner\x00", "\ufeffowner", "é", "e\u0301"} {
		t.Run(fmt.Sprintf("owner-%x", owner), func(t *testing.T) {
			x := ownerActOwnerControl(t, "owner-dm.unbind", owner)
			x.check(t, "accept")
			if seen[x.m.ContentID] {
				t.Fatal("distinct owner bytes collapsed")
			}
			seen[x.m.ContentID] = true
			x.in.Owner = "owner"
			x.remap(t)
			x.check(t, "act_binding_mismatch")
		})
	}
	for _, opaque := range []string{"A", "a", `a"\/:>{}`, "!~", "%61"} {
		t.Run(fmt.Sprintf("opaque-%x", opaque), func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			x.in.Arguments.SourceRoom, x.in.Arguments.SourceRecipient = opaque, opaque
			x.in.Arguments.OwnerRecipient, x.in.Arguments.BoundRoom = opaque, opaque
			x.s["consumer_recipient"], x.s["owner_recipient"] = opaque, opaque
			x.delivery["room"], x.delivery["recipient"] = opaque, opaque
			x.binding["owner_recipient"], x.binding["bound_room"] = opaque, opaque
			x.remap(t)
			x.snapshots(t)
			x.check(t, "accept")
			x.in.Arguments.SourceRoom += "x"
			x.remap(t)
			x.check(t, "act_binding_mismatch")
		})
	}
}

// Envelope escapes are permitted transport; equivalent JSON spelling inside
// the actual delivered Render is different raw text and must not be rewritten.
func TestReviewOwnerActTextEncodingBoundary(t *testing.T) {
	x := ownerActOwnerControl(t, "owner-dm.unbind", "owner\n")
	x.check(t, "accept")
	raw := targetWire(t, x.f.e)
	needle := []byte(`owner\n`)
	if bytes.Count(raw, needle) != 1 || bytes.Count(x.m.Render, needle) != 1 {
		t.Fatal("literal escape fixture")
	}
	alternate := bytes.Replace(raw, needle, []byte(`owner\u000a`), 1)
	v := verifier.New(x.c)
	if r := v.VerifyOwnerAct(alternate, x.m.Arguments, x.m.Render, x.p); r.Code != "accept" || r.Plan.ActionID != x.in.ActionID {
		t.Fatal(r)
	}
	for _, spelling := range []string{`owner\u000a`, `owner\r\n`, "owner"} {
		text := bytes.Replace(x.m.Render, needle, []byte(spelling), 1)
		assertOwnerActRefusal(t, v.VerifyOwnerAct(raw, x.m.Arguments, text, x.p), "act_binding_mismatch")
	}
	for _, suffix := range []byte{0, 9, 10, 13, 32} {
		text := append(bytes.Clone(x.m.Render), suffix)
		assertOwnerActRefusal(t, v.VerifyOwnerAct(raw, x.m.Arguments, text, x.p), "act_binding_mismatch")
	}
	x.check(t, "accept")
}

// A fully signed canonical 2048-byte A and an 8192-byte envelope are accepted
// together. One extra byte refuses at the correct row without truncation.
// Render cannot independently reach4096 within these closed argument limits.
func TestReviewOwnerActIntakeBounds(t *testing.T) {
	x := ownerActOwnerControl(t, "owner-dm.unbind", strings.Repeat("\x00", 255))
	a, err := record.Parse(x.m.Arguments, 2048, 4)
	if err != nil {
		t.Fatal(err)
	}
	fields := []string{"source_room", "source_recipient", "owner_recipient", "bound_room"}
	m := a.(map[string]any)
	for _, name := range fields {
		m[name] = strings.Repeat("\\", 255)
	}
	for _, name := range fields {
		b, err := record.Canonical(m)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) <= 2048 {
			break
		}
		n := min(254, (len(b)-2048+1)/2)
		m[name] = strings.Repeat("\\", 255-n)
		if len(b)-2*n == 2047 {
			m[name] = m[name].(string) + "x"
		}
	}
	x.in.Arguments.SourceRoom = m["source_room"].(string)
	x.in.Arguments.SourceRecipient = m["source_recipient"].(string)
	x.in.Arguments.OwnerRecipient = m["owner_recipient"].(string)
	x.in.Arguments.BoundRoom = m["bound_room"].(string)
	x.s["consumer_recipient"], x.s["owner_recipient"] = m["source_recipient"], m["owner_recipient"]
	x.delivery["room"], x.delivery["recipient"] = m["source_room"], m["source_recipient"]
	x.binding["owner_recipient"], x.binding["bound_room"] = m["owner_recipient"], m["bound_room"]
	x.remap(t)
	x.snapshots(t)
	if len(x.m.Arguments) != 2048 || len(x.m.Render) > 4096 {
		t.Fatalf("A=%d Render=%d", len(x.m.Arguments), len(x.m.Render))
	}
	x.check(t, "accept")
	raw := targetWire(t, x.f.e)
	padded := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), 8192-len(raw))...)
	v := verifier.New(x.c)
	if r := v.VerifyOwnerAct(padded, x.m.Arguments, x.m.Render, x.p); r.Code != "accept" {
		t.Fatal(r)
	}
	assertOwnerActRefusal(t, v.VerifyOwnerAct(padded, append(bytes.Clone(x.m.Arguments), ' '), x.m.Render, x.p), "act_binding_mismatch")
	assertOwnerActRefusal(t, v.VerifyOwnerAct(append(padded, ' '), nil, nil, x.p), "envelope_too_large")
	t.Logf("valid A=%d, Render=%d, envelope=%d", len(x.m.Arguments), len(x.m.Render), len(padded))
}
