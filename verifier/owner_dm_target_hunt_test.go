package verifier_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

// Reusing/mutating caller bytes between sequential calls cannot reuse an old
// verdict or let a returned plan alias the next result. Concurrent mutation
// during verification is outside this test and the caller ownership contract.
func TestOwnerDMTargetHuntInputReuse(t *testing.T) {
	f := targetControl(t, "operator-act/1")
	f.set(dmTarget("slot"))
	raw := f.signed(t)
	c := context(t, f.f)
	v := verifier.New(c)
	first := v.VerifyEnvelope(raw, f.kind)
	if first.Code != "accept" {
		t.Fatal(first)
	}
	pos := bytes.Index(raw, []byte(`"id":"slot"`))
	if pos < 0 {
		t.Fatal("mutation setup")
	}
	pos += len(`"id":"`)
	raw[pos] = 'S'
	targetResult(t, c, raw, f.kind, "envelope_malformed", false)
	if r := v.VerifyEnvelope(raw, f.kind); r.Code != "envelope_malformed" || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
		t.Fatal("reused verifier", r)
	}
	raw[pos] = 's'
	targetResult(t, c, raw, f.kind, "accept", false)
	first.Plan.IDs[0] = "changed returned plan"
	if r := v.VerifyEnvelope(raw, f.kind); r.Code != "accept" || r.Plan.IDs[0] != f.e["id"] {
		t.Fatal("plan alias", r)
	}
}

// E8 journals exact transport bytes even though E1 permits equivalent JSON
// spellings. An exact replay is the positive control for that conflict refusal.
func TestOwnerDMTargetHuntJournalSpelling(t *testing.T) {
	f := targetControl(t, "operator-act/1")
	f.set(dmTarget("slot"))
	raw := f.signed(t)
	c := context(t, f.f)
	c.IDJournal = evidence(t, map[string]any{f.e["id"].(string): raw})
	targetResult(t, c, raw, f.kind, "accept", false)
	other := bytes.Replace(raw, []byte(`"id":"slot"`), []byte(`"id":"\u0073lot"`), 1)
	targetResult(t, c, other, f.kind, "envelope_conflict", false)
}

// A mathematically valid Ed25519 signature cannot enter the P256-only operator
// profile. A proper P256 control admits; invalid NAME still wins at E2.
func TestOwnerDMTargetHuntAlgorithm(t *testing.T) {
	f := targetControl(t, "operator-act/1")
	f.set(dmTarget("slot"))
	c := context(t, f.f)
	targetResult(t, c, f.signed(t), f.kind, "accept", false)
	for _, name := range []string{"slot", "Slot"} {
		f.set(dmTarget(name))
		f.signed(t)
		seed := sha256.Sum256([]byte("waggle public test seed 0"))
		private := ed25519.NewKeyFromSeed(seed[:])
		key := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
		pre, err := record.SigningPreimage(f.kind, key, "approver", f.body())
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(private, pre)
		if err := record.VerifySignature(key, sig, pre); err != nil {
			t.Fatal("signature setup", err)
		}
		f.e["signatures"] = []any{map[string]any{"role": "approver", "key": key, "sig": base64.RawURLEncoding.EncodeToString(sig)}}
		want := "signature_profile_invalid"
		if name == "Slot" {
			want = "envelope_malformed"
		}
		targetResult(t, c, targetWire(t, f.e), f.kind, want, false)
	}
}

// now<W alone remains admissible when the entire uncertainty interval fits the
// signed window; a malformed target still fails before those sampled facts.
func TestOwnerDMTargetHuntWatermark(t *testing.T) {
	f := targetControl(t, "operator-act/1")
	f.set(dmTarget("slot"))
	raw := f.signed(t)
	c := context(t, f.f)
	c.Now = evidence(t, "2026-01-01T00:00:59Z")
	targetResult(t, c, raw, f.kind, "accept", false)
	f.set(dmTarget("Slot"))
	targetResult(t, c, f.signed(t), f.kind, "envelope_malformed", false)
}

// Credential subfields retain their old single-segment/255-byte rules, rather
// than inheriting owner-DM's first-character restriction or two-member shape.
func TestOwnerDMTargetHuntCredentialMembers(t *testing.T) {
	f := targetControl(t, "message/1")
	c := context(t, f.f)
	for _, tc := range []struct{ name, harness, profile, want string }{
		{"leading-hyphen", "-", "-a", "accept"},
		{"harness-slash", "a/b", "a", "envelope_malformed"},
		{"profile-pattern", "a", "a/*", "envelope_malformed"},
		{"empty-profile", "a", "", "envelope_malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.set(map[string]any{"kind": "credential", "id": "a/b", "harness": tc.harness, "profile": tc.profile})
			targetResult(t, c, f.signed(t), f.kind, tc.want, false)
		})
	}
}
