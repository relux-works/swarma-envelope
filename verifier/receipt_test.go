package verifier_test

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/waggle/verifier"
)

// The transport contains producer proofs, not serialized receipt authority.
// Only successful library F verification supplies the pointer used by consumers.
func receiptContext(t *testing.T, v vector) (verifier.Context, verifier.Result) {
	t.Helper()
	mint := v.Input["mint"].(map[string]any)
	mv := vector{Mode: mint["mode"].(string), Input: mint["input"].(map[string]any), Fixture: v.Fixture}
	c := context(t, v.Fixture)
	chain, cp, ids, keys := freshInputs(t, mv)
	var r verifier.Result
	if mv.Mode == "freshness-reanchor" {
		r = verifier.New(c).VerifyFreshnessReanchor(chain[0], cp, ids, keys)
	} else {
		r = verifier.New(c).VerifyFreshness(chain, cp, ids, keys)
	}
	if r.Code != "accept" {
		return c, r
	}
	raw, _ := b64(mv.Input["chain"].([]any)[len(chain)-1])
	var tip map[string]any
	if err := json.Unmarshal(raw, &tip); err != nil {
		t.Fatal(err)
	}
	tip = normalizeJSON(t, tip)
	b := tip["body"].(map[string]any)
	f := map[string]any{}
	for k, value := range v.Fixture {
		f[k] = value
	}
	f["freshness_anchor"] = map[string]any{"registry_id": b["registry"], "owner": b["owner"], "publication_seq": b["publication_seq"], "freshness_id": tip["id"], "issued_at": b["issued_at"], "snapshot": b["snapshot"], "registry_seq": b["registry_seq"], "checkpoint_id": b["checkpoint_id"]}
	use := v.Input["use"].(map[string]any)
	for k, value := range use {
		f[k] = value
	}
	consumer := context(t, f)
	if _, changed := use["revocations"]; !changed && v.Input["renew_evidence"] != true {
		consumer.SignedSnapshots = c.SignedSnapshots
	}
	if v.Input["attach"] == true {
		consumer.FreshnessReceipt = r.FreshnessReceipt
	}
	consumer.RequireFreshnessReceipt, _ = v.Input["require"].(bool)
	consumer.FreshnessMarginSeconds = v.Input["margin"].(int64)
	return consumer, r
}
func normalizeJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	var m map[string]any
	if e = d.Decode(&m); e != nil {
		t.Fatal(e)
	}
	return normalize(m).(map[string]any)
}
func consumeReceipt(t *testing.T, v vector, c verifier.Context) verifier.Result {
	t.Helper()
	op := v.Input["consume"].(map[string]any)
	in := op["input"].(map[string]any)
	lib := verifier.New(c)
	var err error
	switch op["mode"] {
	case "attestation", "device":
		a, e := lib.VerifyAttestation(in["key"].(string), in["reference"].(string), op["mode"] == "device")
		err = e
		if err != nil && a != (verifier.Attestation{}) {
			t.Fatal("refused identity", a)
		}
	case "revocation":
		stringsIn := func(x any) []string {
			var s []string
			for _, value := range x.([]any) {
				s = append(s, value.(string))
			}
			return s
		}
		state, e := lib.CheckRevocation(in["root"].(string), stringsIn(in["ids"]), stringsIn(in["keys"]))
		err = e
		if err != nil && state != verifier.Unavailable {
			t.Fatal("refused state", state, err)
		}
		if state == verifier.Revoked {
			return verifier.Result{Code: "revoked"}
		}
		if state == verifier.Unavailable && err == nil {
			return verifier.Result{Code: "key_binding_unavailable"}
		}
	case "grant":
		var chain [][]byte
		for _, value := range in["chain"].([]any) {
			raw, e := b64(value)
			if e != nil {
				t.Fatal(e)
			}
			chain = append(chain, raw)
		}
		return lib.Authorize(chain, evidence(t, v.Fixture["request"]))
	default:
		raw, e := b64(in["envelope"])
		if e != nil {
			t.Fatal(e)
		}
		if op["mode"] == "operator" {
			return lib.VerifyOperator(raw)
		}
		return lib.VerifyMessage(raw)
	}
	return verifier.Result{Code: code(err)}
}
func deriveReceipt(t *testing.T, v vector) expected {
	t.Helper()
	c, r := receiptContext(t, v)
	if r.Code == "accept" {
		r = consumeReceipt(t, v, c)
	}
	if r.Code != "accept" && (r.FreshnessReceipt != nil || !reflect.DeepEqual(r.Plan, verifier.Plan{})) {
		t.Fatal("refusal authority", r)
	}
	return freshExpected(t, r)
}

// Exact paired corpus verdicts cover binding, exclusive expiry, all consumers,
// no fallback, real recovery issuance and retained domain/effective-entry gates.
func TestFreshnessReceiptVectors(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		if strings.Contains(filepath.Base(p), "RC-") {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		t.Fatal("missing receipt corpus")
	}
	runVectors(t, paths)
}

// Safe Go allocation/copy/reflection/JSON cannot manufacture provenance;
// pointer aliases remain valid and audit values are detached, not authority.
func TestFreshnessReceiptProvenance(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-RC-current.json")
	c, r := receiptContext(t, v)
	original := r.FreshnessReceipt
	if original == nil {
		t.Fatal(r)
	}
	audit, ok := original.Audit()
	if !ok || audit.SnapshotID == "" || audit.Reanchored || audit.OldFreshnessID != "" || audit.OldCheckpointID != "" {
		t.Fatal(audit, ok)
	}
	audit.Owner = "changed"
	again, _ := original.Audit()
	if again.Owner == audit.Owner {
		t.Fatal("mutable audit")
	}
	copied := *original
	reflected := reflect.New(reflect.TypeOf(*original)).Interface().(*verifier.FreshnessReceipt)
	clone := reflect.New(reflect.TypeOf(*original))
	clone.Elem().Set(reflect.ValueOf(original).Elem())
	for name, pointer := range map[string]*verifier.FreshnessReceipt{"zero": {}, "copy": &copied, "reflection": reflected, "reflect-copy": clone.Interface().(*verifier.FreshnessReceipt)} {
		t.Run(name, func(t *testing.T) {
			bad := c
			bad.FreshnessReceipt = pointer
			got := consumeReceipt(t, v, bad)
			if got.Code != "freshness_receipt_invalid" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
				t.Fatal(got)
			}
			if _, ok := pointer.Audit(); ok {
				t.Fatal("forged audit")
			}
		})
	}
	if _, err := json.Marshal(original); err == nil {
		t.Fatal("serialized authority")
	}
	if err := json.Unmarshal([]byte(`{}`), original); err == nil {
		t.Fatal("decoded authority")
	}
	if _, err := verifier.Present(original); err == nil {
		t.Fatal("receipt accepted as evidence")
	}
	raw, err := json.Marshal(r)
	if err != nil || strings.Contains(string(raw), "Receipt") || strings.Contains(string(raw), "receipt") {
		t.Fatal(string(raw), err)
	}
	if got := consumeReceipt(t, v, c); got.Code != "accept" || got.FreshnessReceipt != nil {
		t.Fatal("alias or failed decode changed authority", got)
	}
}

// Sharing the original immutable pointer and Evidence across clock contexts is
// race-free; refusal, audit mutation and serialization attempts cannot renew it.
func TestFreshnessReceiptConcurrent(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-RC-current.json")
	c, r := receiptContext(t, v)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 12; j++ {
				if got := consumeReceipt(t, v, c); got.Code != "accept" {
					t.Error(got)
				}
				a, ok := r.FreshnessReceipt.Audit()
				a.Owner = "changed"
				if !ok {
					t.Error("lost provenance")
				}
				_, _ = json.Marshal(r.FreshnessReceipt)
			}
		}()
	}
	wg.Wait()
}

// Missing required receipts refuse, optional absence retains legacy own-age,
// and a legitimate pointer with the same immutable Evidence may be reused.
func TestFreshnessReceiptLegacy(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-RC-attestation.json")
	c, _ := receiptContext(t, v)
	c.FreshnessReceipt = nil
	c.RequireFreshnessReceipt = false
	c.FreshnessMarginSeconds = -1
	if got := consumeReceipt(t, v, c); got.Code != "key_binding_unavailable" {
		t.Fatal(got)
	}
	v = load(t, "../vectors/swarm-envelope-2/1-positive/P-RC-current.json")
	c, _ = receiptContext(t, v)
	c.FreshnessReceipt = nil
	c.RequireFreshnessReceipt = false
	if got := consumeReceipt(t, v, c); got.Code != "accept" {
		t.Fatal(got)
	}
}

// Producer refusals after valid wire/crypto cannot mint usable authority, and
// explicit recovery audits identify both endpoints without changing provenance.
func TestFreshnessReceiptIssuance(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-RC-reanchor.json")
	_, r := receiptContext(t, v)
	a, ok := r.FreshnessReceipt.Audit()
	if !ok || !a.Reanchored || a.OldFreshnessID == "" || a.OldCheckpointID == "" || a.FreshnessID == a.OldFreshnessID {
		t.Fatal(r, a, ok)
	}
	plan := r.Plan.Reanchor
	if plan == nil || a.OldFreshnessID != plan.OldFreshnessID || a.FreshnessID != plan.NewFreshnessID || a.OldCheckpointID != plan.OldCheckpointID || a.CheckpointID != plan.NewCheckpointID {
		t.Fatal("audit endpoints", a, plan)
	}

	mv := v.Input["mint"].(map[string]any)
	f := vector{Input: mv["input"].(map[string]any), Fixture: v.Fixture}
	chain, cp, _, keys := freshInputs(t, f)
	bad := verifier.New(context(t, f.Fixture)).VerifyFreshnessReanchor(chain[0], cp, []string{"invalid"}, keys)
	if bad.Code != "freshness_request_invalid" || bad.FreshnessReceipt != nil || !reflect.DeepEqual(bad.Plan, verifier.Plan{}) {
		t.Fatal(bad)
	}
	if _, err := json.Marshal(*r.FreshnessReceipt); err == nil {
		t.Fatal("value serialized")
	}
	var zero verifier.FreshnessReceipt
	if err := json.Unmarshal([]byte(`{}`), &zero); err == nil {
		t.Fatal("decoded zero")
	}
	if _, ok := zero.Audit(); ok {
		t.Fatal("decoded provenance")
	}
}

// The same immutable Evidence survives new clock/watermark Context values
// inside the fixed lifetime; a fresh Context does not renew exclusive expiry.
func TestFreshnessReceiptEvidenceReuse(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-RC-current.json")
	c, _ := receiptContext(t, v)
	later := c
	later.Now = evidence(t, "2026-01-01T00:03:59Z")
	later.Watermark = later.Now
	if got := consumeReceipt(t, v, later); got.Code != "accept" {
		t.Fatal(got)
	}
	expired := later
	expired.Now = evidence(t, "2026-01-01T00:04:00Z")
	expired.Watermark = expired.Now
	if got := consumeReceipt(t, v, expired); got.Code != "freshness_receipt_expired" {
		t.Fatal(got)
	}
	if _, ok := expired.FreshnessReceipt.Audit(); !ok {
		t.Fatal("audit must report origin even after expiry")
	}
	if got := consumeReceipt(t, v, c); got.Code != "accept" {
		t.Fatal("immutable reuse", got)
	}
}

// Rebuilding Evidence from the identical protected fixture bytes invalidates
// the receipt, even though own-age passes; the retained original still accepts.
func TestFreshnessReceiptEvidenceRebuild(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-RC-current.json")
	c, _ := receiptContext(t, v)
	if got := consumeReceipt(t, v, c); got.Code != "accept" {
		t.Fatal(got)
	}
	rebuilt := c
	rebuilt.SignedSnapshots = context(t, v.Fixture).SignedSnapshots
	if got := consumeReceipt(t, v, rebuilt); got.Code != "freshness_receipt_binding_mismatch" {
		t.Fatal(got)
	}
	if got := consumeReceipt(t, v, c); got.Code != "accept" {
		t.Fatal("mutated retained evidence", got)
	}
}

// Required R2 presence precedes all syntax: the combined regression and its
// unchanged/missing-only/malformed-only controls run in the exact corpus oracle.
// The remaining neighbors audit every required policy/witness/anchor member.
func TestFreshnessReceiptPresenceOrder(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		if strings.Contains(filepath.Base(p), "RC-R2-") {
			paths = append(paths, p)
		}
	}
	if len(paths) < 4 {
		t.Fatal("missing presence regression and controls")
	}
	runVectors(t, paths)
}
