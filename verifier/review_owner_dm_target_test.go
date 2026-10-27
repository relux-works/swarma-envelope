package verifier_test

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

func reviewTargetEscaped(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, `\u%04x`, c)
	}
	return b.String()
}

// Envelope transport is not required to be canonical. Fully escaped permitted
// names/keys/kinds, reordered members and whitespace retain the signed decoded
// value, including a 63-byte name whose wire spelling is much longer. Invalid
// decoded neighbors and duplicate decoded aliases still refuse at intake/schema.
func TestReviewOwnerDMDecodedTransport(t *testing.T) {
	for _, name := range []string{"n0-", strings.Repeat("z", 63)} {
		f := targetControl(t, "operator-act/1")
		f.set(dmTarget(name))
		raw := f.signed(t)
		c := context(t, f.f)
		needle := []byte(`"target":{"id":"` + name + `","kind":"owner-dm"}`)
		if bytes.Count(raw, needle) != 1 {
			t.Fatal("target fixture")
		}
		replacement := []byte(`"\u0074arget" : { "\u006b\u0069\u006e\u0064" : "` + reviewTargetEscaped("owner-dm") + `", "\u0069\u0064" : "` + reviewTargetEscaped(name) + `" }`)
		alternate := bytes.Replace(raw, needle, replacement, 1)
		alternate = append(append([]byte("\t\r\n "), alternate...), []byte("\r\n\t ")...)
		targetResult(t, c, raw, f.kind, "accept", false)
		targetResult(t, c, alternate, f.kind, "accept", false)
		padded := append(bytes.Clone(alternate), bytes.Repeat([]byte(" "), 8192-len(alternate))...)
		targetResult(t, c, padded, f.kind, "accept", false)
		targetResult(t, c, append(padded, ' '), f.kind, "envelope_too_large", false)
		for _, bad := range []string{
			`{"kind":"owner-dm","id":"` + reviewTargetEscaped(name) + `\u0000"}`,
			`{"kind":"owner-dm","id":"` + reviewTargetEscaped(name) + `\u00a0"}`,
			`{"kind":"owner-dm","id":"` + name + `","\u0069d":"` + name + `"}`,
			`{"kind":"owner-dm","\u006bind":"owner-dm","id":"` + name + `"}`,
			`{"kind":"owner-dm","id":"\ud83d\ude00"}`,
			`{"kind":"owner-dm","id":"` + strings.Repeat(`\u007a`, 64) + `"}`,
		} {
			wire := bytes.Replace(raw, needle, []byte(`"target":`+bad), 1)
			targetResult(t, c, wire, f.kind, "envelope_malformed", false)
		}
		// E8 retains exact raw spelling despite canonical signature equivalence.
		c.IDJournal = evidence(t, map[string]any{f.e["id"].(string): alternate})
		targetResult(t, c, alternate, f.kind, "accept", false)
		targetResult(t, c, raw, f.kind, "envelope_conflict", false)
	}
}

// Interior positions of maximum-length names use the same closed alphabet;
// the test's independent regular expression is a grammar oracle, not production
// code or a Unicode-normalizing parser. Every case has a real signature.
func TestReviewOwnerDMInteriorAlphabet(t *testing.T) {
	grammar := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	f := targetControl(t, "operator-act/1")
	c := context(t, f.f)
	for _, at := range []int{1, 31, 61} {
		for _, value := range []string{"a", "z", "0", "9", "-", "A", "_", "/", " ", "\r", "\x7f", "é", "\u200b"} {
			t.Run(fmt.Sprintf("%d-%x", at, value), func(t *testing.T) {
				name := strings.Repeat("a", at) + value + strings.Repeat("a", 62-at)
				want := "envelope_malformed"
				if grammar.MatchString(name) {
					want = "accept"
				}
				f.set(dmTarget(name))
				targetResult(t, c, f.signed(t), f.kind, want, false)
			})
		}
	}
}

// A legal target substitution must still bind the id and complete raw signature
// domain. Strict low-S and public-key point validation remain reachable; invalid
// decoded names keep the earlier schema refusal. Synthetic public fixture keys
// only, with no enrollment or cryptographic-security qualification claim.
func TestReviewOwnerDMSignedBinding(t *testing.T) {
	f := targetControl(t, "operator-act/1")
	f.set(dmTarget("slot"))
	c := context(t, f.f)
	raw := f.signed(t)
	targetResult(t, c, raw, f.kind, "accept", false)
	f.set(dmTarget("other"))
	targetResult(t, c, targetWire(t, f.e), f.kind, "envelope_id_mismatch", false)
	id, err := record.ContentID(f.kind, f.body())
	if err != nil {
		t.Fatal(err)
	}
	f.e["id"] = id
	targetResult(t, c, targetWire(t, f.e), f.kind, "envelope_signature_invalid", false)
	targetResult(t, c, f.signed(t), f.kind, "accept", false)
	// Sign the real complete body under a different existing domain, then restore
	// only the operator content id. This must not validate as an operator signature.
	f.kind = "grant/1"
	f.signed(t)
	f.kind = "operator-act/1"
	f.e["id"] = id
	targetResult(t, c, targetWire(t, f.e), f.kind, "envelope_signature_invalid", false)
	for _, name := range []string{"slot", "Slot"} {
		f.set(dmTarget(name))
		f.signed(t)
		s := f.e["signatures"].([]any)[0].(map[string]any)
		encoded, err := base64.RawURLEncoding.DecodeString(s["sig"].(string))
		if err != nil {
			t.Fatal(err)
		}
		n := elliptic.P256().Params().N
		high := new(big.Int).Sub(n, new(big.Int).SetBytes(encoded[32:]))
		high.FillBytes(encoded[32:])
		s["sig"] = base64.RawURLEncoding.EncodeToString(encoded)
		want := "signature_high_s"
		if name == "Slot" {
			want = "envelope_malformed"
		}
		targetResult(t, c, targetWire(t, f.e), f.kind, want, false)
	}
	f.set(dmTarget("slot"))
	f.signed(t)
	s := f.e["signatures"].([]any)[0].(map[string]any)
	s["key"] = "p256:" + base64.RawURLEncoding.EncodeToString(append([]byte{3}, bytes.Repeat([]byte{255}, 32)...))
	targetResult(t, c, targetWire(t, f.e), f.kind, "envelope_signature_invalid", false)
	targetResult(t, c, raw, f.kind, "accept", false)
}

// Alternate valid transport spellings cannot convert E-only success into O1
// authority. Earlier signature failures retain precedence over unknown-operation
// refusals, even with absent binding facts and a reused verifier instance.
func TestReviewOwnerDMClosedOperationOrder(t *testing.T) {
	for _, op := range []string{"owner-dm.bind", "owner-dm.unbind", "owner-dm.mirror-enable", "launch.approve", "host.change", "unregistered.operation"} {
		t.Run(op, func(t *testing.T) {
			f := targetControl(t, "operator-act/1")
			f.set(dmTarget("slot"))
			f.body()["operation"] = op
			raw := f.signed(t)
			c := context(t, f.f)
			c.ActBinding = verifier.Evidence{}
			alternate := bytes.Replace(raw, []byte(`"id":"slot"`), []byte(`"id":"\u0073lot"`), 1)
			targetResult(t, c, alternate, f.kind, "accept", false)
			targetResult(t, c, alternate, f.kind, "act_operation_unknown", true)
			v := verifier.New(c)
			if r := v.VerifyEnvelope(raw, f.kind); r.Code != "accept" {
				t.Fatal(r)
			}
			if r := v.VerifyOperator(raw); r.Code != "act_operation_unknown" || len(r.Plan.IDs) != 0 {
				t.Fatal(r)
			}
			s := f.e["signatures"].([]any)[0].(map[string]any)
			b, err := base64.RawURLEncoding.DecodeString(s["sig"].(string))
			if err != nil {
				t.Fatal(err)
			}
			b[0] ^= 1
			s["sig"] = base64.RawURLEncoding.EncodeToString(b)
			targetResult(t, c, targetWire(t, f.e), f.kind, "envelope_signature_invalid", true)
			targetResult(t, c, raw, f.kind, "act_operation_unknown", true)
		})
	}
}
