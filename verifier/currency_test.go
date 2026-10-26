package verifier_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/waggle/record"
	"github.com/relux-works/waggle/verifier"
)

type currencyFixture struct {
	c       verifier.Context
	cp, tip []byte
	root    string
}

func currencySigned(t *testing.T, b map[string]any, private ed25519.PrivateKey) ([]byte, string) {
	t.Helper()
	k := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	id, e := record.ContentID(b["type"].(string), b)
	if e != nil {
		t.Fatal(e)
	}
	pre, e := record.SigningPreimage(b["type"].(string), k, "author", b)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": b, "id": id, "signatures": []any{map[string]any{"role": "author", "key": k, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, pre))}}})
	if e != nil {
		t.Fatal(e)
	}
	return raw, id
}
func currencyBase(t *testing.T) currencyFixture {
	t.Helper()
	seed := sha256.Sum256([]byte("public currency fixture registry"))
	private := ed25519.NewKeyFromSeed(seed[:])
	root := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	seed = sha256.Sum256([]byte("public currency fixture attestation"))
	att := ed25519.NewKeyFromSeed(seed[:])
	service := "ed25519:" + base64.RawURLEncoding.EncodeToString(att.Public().(ed25519.PublicKey))
	snap, sid := currencySigned(t, map[string]any{"type": "revocation/1", "issuer": root, "issued_at": "2026-01-01T00:00:00Z", "complete": true, "entries": []any{}}, private)
	head := record.Digest([]byte("qualified complete prefix"))
	set := []any{map[string]any{"root_role": "registry-owner", "root_key_id": root, "snapshot_id": sid}}
	cp, cid := currencySigned(t, map[string]any{"type": "checkpoint/2", "registry": root, "owner": "owner-a", "seq": int64(1), "head": head, "at": "2026-01-01T00:01:00Z", "snapshots": set}, private)
	tip, _ := currencySigned(t, map[string]any{"type": "freshness/2", "registry": root, "owner": "owner-a", "publication_seq": int64(1), "prev": nil, "issued_at": "2026-01-01T00:03:00Z", "snapshots": set, "registry_seq": int64(1), "checkpoint_id": cid}, private)
	c := verifier.Context{RegistryCurrencyVersion: 2}
	c.AgentRevocationRoot = evidence(t, map[string]any{"key": root, "purpose": "registry-revocation", "attestation_root": service})
	c.ServiceRoot = evidence(t, map[string]any{"key": service, "purpose": int64(5)})
	c.RegistryOwner = evidence(t, "owner-a")
	c.Time = evidence(t, map[string]any{"trusted": true, "fresh": true, "authority_until": "2026-01-01T00:10:00Z"})
	c.Now = evidence(t, "2026-01-01T00:03:00Z")
	c.WatermarkAvailable = evidence(t, true)
	c.Watermark = c.Now
	c.WitnessReadAt = c.Now
	c.SignedSnapshots = evidence(t, map[string]any{root: map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": snap}})
	c.JournalWitness = evidence(t, map[string]any{"registry_id": root, "owner": "owner-a", "registry_seq": int64(1), "registry_head": head, "checkpoint_id": cid, "previous_checkpoint_id": nil})
	c.FreshnessAnchor = evidence(t, map[string]any{"registry_id": root, "owner": "owner-a", "publication_seq": int64(0), "freshness_id": nil, "issued_at": nil, "snapshots": set, "registry_seq": int64(1), "checkpoint_id": cid})
	c.SnapshotJournal = evidence(t, map[string]any{"anchor": map[string]any{"version": int64(2), "registry_id": root, "owner": "owner-a", "registry_seq": int64(1), "registry_head": head, "checkpoint_id": cid, "latest": []any{map[string]any{"root_role": "registry-owner", "root_key_id": root, "snapshot_id": sid, "record_seq": int64(1)}}}, "entries": []any{}})
	c.IDJournalAvailable = evidence(t, true)
	c.IDJournal = evidence(t, map[string]any{sid: snap, cid: cp})
	return currencyFixture{c, cp, tip, root}
}

// /2 is explicit; valid current witness currency can cover old content, while
// missing complete-prefix proof and a legacy candidate refuse with zero plans.
func TestCurrencyVersionAndIndex(t *testing.T) {
	f := currencyBase(t)
	r := verifier.New(f.c).VerifyFreshness([][]byte{f.tip}, f.cp, nil, nil)
	if r.Code != "accept" || r.FreshnessReceipt == nil || r.Plan.SnapshotJournal == nil {
		t.Fatal(r)
	}
	for _, tc := range []struct {
		name string
		edit func(*verifier.Context)
		code string
	}{
		{"missing-index", func(c *verifier.Context) { c.SnapshotJournal = verifier.Evidence{} }, "freshness_unavailable"},
		{"legacy-pin", func(c *verifier.Context) { c.RegistryCurrencyVersion = 1 }, "registry_currency_version_mismatch"},
		{"invalid-pin", func(c *verifier.Context) { c.RegistryCurrencyVersion = 3 }, "freshness_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.c
			tc.edit(&c)
			got := verifier.New(c).VerifyFreshness([][]byte{f.tip}, f.cp, nil, nil)
			if got.Code != tc.code || !reflect.DeepEqual(got.Plan, verifier.Plan{}) || got.FreshnessReceipt != nil {
				t.Fatal(got)
			}
		})
	}
}

// Nested output mutation cannot alter a minted receipt or subsequent calls.
// New fields must be omitted from /1 JSON instead of changing legacy digests.
func TestCurrencyDetachedAndLegacyJSON(t *testing.T) {
	f := currencyBase(t)
	r := verifier.New(f.c).VerifyFreshness([][]byte{f.tip}, f.cp, nil, nil)
	if r.Code != "accept" {
		t.Fatal(r)
	}
	a, ok := r.FreshnessReceipt.Audit()
	if !ok || len(a.Snapshots) != 1 {
		t.Fatal(a)
	}
	a.Snapshots[0].SnapshotID = "changed"
	r.Plan.SnapshotJournal.Latest[0].SnapshotID = new(string)
	again, _ := r.FreshnessReceipt.Audit()
	if again.Snapshots[0].SnapshotID == "changed" {
		t.Fatal("audit alias")
	}
	raw, e := json.Marshal(verifier.Plan{})
	if e != nil || string(raw) != "{}" {
		t.Fatal(string(raw), e)
	}
	legacy := verifier.FreshnessAudit{RegistryID: "r"}
	raw, e = json.Marshal(legacy)
	if e != nil {
		t.Fatal(e)
	}
	if string(raw) != `{"RegistryID":"r","Owner":"","SnapshotID":"","CheckpointID":"","FreshnessID":"","Reanchored":false,"OldFreshnessID":"","OldCheckpointID":""}` {
		t.Fatal("legacy audit bytes", string(raw))
	}
	raw, e = json.Marshal(verifier.Plan{Reanchor: &verifier.FreshnessReanchorPlan{Reanchored: true}})
	if e != nil || string(raw) != `{"reanchor":{"reanchored":true,"skipped_publications":0,"old_freshness_id":"","new_freshness_id":"","old_checkpoint_id":"","new_checkpoint_id":""}}` {
		t.Fatal("legacy plan bytes", string(raw), e)
	}
	fresh := verifier.New(f.c).VerifyFreshness([][]byte{f.tip}, f.cp, nil, nil)
	if fresh.Code != "accept" || *fresh.Plan.SnapshotJournal.Latest[0].SnapshotID != again.Snapshots[0].SnapshotID {
		t.Fatal("mutable index output", fresh)
	}

}

// Every named /2 corpus witness has an independently specified code and exact
// plan; negative witnesses carry accepted controls. This includes receipt use.
func TestCurrencyVectors(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		if strings.Contains(filepath.Base(p), "-CU-") {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		t.Fatal("missing /2 corpus")
	}
	runVectors(t, paths)
}

// Direct envelope admission shares the /2 receipt gate. The neighboring expired
// context must refuse with no plan; wrappers cannot be its only enforcement.
func TestCurrencyEnvelopeConsumers(t *testing.T) {
	for _, name := range []string{"message", "operator"} {
		t.Run(name, func(t *testing.T) {
			v := load(t, "../vectors/swarm-envelope-2/1-positive/P-CU-receipt-"+name+".json")
			c, r := receiptContext(t, v)
			if r.Code != "accept" {
				t.Fatal(r)
			}
			raw, e := b64(v.Input["consume"].(map[string]any)["input"].(map[string]any)["envelope"])
			if e != nil {
				t.Fatal(e)
			}
			kind := "message/1"
			if name == "operator" {
				kind = "operator-act/1"
			}
			if got := verifier.New(c).VerifyEnvelope(raw, kind); got.Code != "accept" {
				t.Fatal(got)
			}
			c.Now = evidence(t, "2026-01-01T00:02:00Z")
			c.Watermark = c.Now
			if got := verifier.New(c).VerifyEnvelope(raw, kind); got.Code != "freshness_receipt_expired" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
				t.Fatal(got)
			}
		})
	}
}

// Mutating returned recovery sets/index pointers cannot alter another result or
// the receipt. Concurrent /2 consumption and detached audit mutation share no writes.
func TestCurrencyDetachedRecoveryAndConcurrent(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-CU-reanchor-receipt.json")
	c, r := receiptContext(t, v)
	if r.Code != "accept" {
		t.Fatal(r)
	}
	before, _ := r.FreshnessReceipt.Audit()
	saved := append([]verifier.SnapshotBinding(nil), before.Snapshots...)
	r.Plan.Reanchor.OldSnapshots[0].SnapshotID = "changed"
	r.Plan.Reanchor.NewSnapshots[0].SnapshotID = "changed"
	*r.Plan.SnapshotJournal.Latest[0].SnapshotID = "changed"
	_, other := receiptContext(t, v)
	if other.Code != "accept" || other.Plan.Reanchor.NewSnapshots[0].SnapshotID == "changed" || *other.Plan.SnapshotJournal.Latest[0].SnapshotID == "changed" {
		t.Fatal(other)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				if got := consumeReceipt(t, v, c); got.Code != "accept" {
					t.Error(got)
				}
				a, ok := r.FreshnessReceipt.Audit()
				if !ok || !reflect.DeepEqual(a.Snapshots, saved) {
					t.Error(a)
				}
				a.Snapshots[0].SnapshotID = "changed"
			}
		}()
	}
	wg.Wait()
}

// Fixed regression witnesses distinguish profile, retained-state and wire
// refusals; each negative retains a valid neighbor. No live adapter is modeled.
func TestCurrencyRefusalRegressions(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		name := filepath.Base(p)
		if strings.Contains(name, "-CU-r1-") || name == "P-CU-genesis.json" || name == "P-CU-version0.json" || name == "P-CU-version1.json" || name == "P-CU-journal-same.json" || name == "P-CU-check-registry-owner.json" {
			paths = append(paths, p)
		}
	}
	if len(paths) <= 5 {
		t.Fatal("missing refusal regressions")
	}
	runVectors(t, paths)
}

// An over-limit input dominates an opposite-profile candidate at every current
// record position; each paired 8192-byte record must still accept at pins 0/1/2.
func TestCurrencyInputBounds(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		if strings.Contains(filepath.Base(p), "-CU-r2-") {
			paths = append(paths, p)
		}
	}
	if len(paths) != 30 {
		t.Fatalf("byte-bound regression count %d", len(paths))
	}
	runVectors(t, paths)
}

// Whole-call capacity wins over an opposite-profile candidate on all three
// entry points; capacity-only refusals and valid controls retain their behavior.
func TestCurrencyAggregateCapacity(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		name := filepath.Base(p)
		if strings.Contains(name, "-CU-r3-") || name == "P-CU-genesis.json" || name == "P-CU-reanchor-same.json" || name == "P-CU-journal-same.json" {
			paths = append(paths, p)
		}
	}
	if len(paths) != 9 {
		t.Fatalf("aggregate regression count %d", len(paths))
	}
	runVectors(t, paths)
}
