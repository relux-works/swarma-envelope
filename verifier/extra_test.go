package verifier_test

import (
	"bytes"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

func messageControl(t *testing.T) (vector, []byte) {
	t.Helper()
	v := load(t, "../vectors/swarm-envelope-2/1-positive/PE1.json")
	b, e := b64(v.Input["envelope"])
	if e != nil {
		t.Fatal(e)
	}
	return v, b
}

// Zero-value evidence and explicitly null collections never create trusted
// empty stores. Each refusal has a zero plan; the intact context accepts.
func TestUnavailableSnapshots(t *testing.T) {
	v, raw := messageControl(t)
	base := context(t, v.Fixture)
	if r := verifier.New(base).VerifyMessage(raw); r.Code != "accept" {
		t.Fatal(r)
	}
	for _, tc := range []struct {
		name   string
		change func(*verifier.Context)
		code   string
	}{
		{"all-absent", func(c *verifier.Context) { *c = verifier.Context{} }, "signer_unavailable"},
		{"roles", func(c *verifier.Context) { c.RequiredRoles = verifier.Evidence{} }, "signer_unavailable"},
		{"admission", func(c *verifier.Context) { c.AdmittedKeys = verifier.Evidence{} }, "signer_unavailable"},
		{"time", func(c *verifier.Context) { c.Time = verifier.Evidence{} }, "time_unavailable"},
		{"watermark", func(c *verifier.Context) { c.WatermarkAvailable = verifier.Evidence{} }, "watermark_unavailable"},
		{"attestations", func(c *verifier.Context) { c.Attestations = verifier.Evidence{} }, "key_binding_unavailable"},
		{"journal", func(c *verifier.Context) { c.IDJournal = verifier.Evidence{} }, "id_journal_unavailable"},
		{"null-journal", func(c *verifier.Context) { c.IDJournal = evidence(t, nil) }, "id_journal_unavailable"},
		{"typed-nil-journal", func(c *verifier.Context) { var m map[string]any; c.IDJournal = evidence(t, m) }, "id_journal_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.change(&c)
			got := verifier.New(c).VerifyMessage(raw)
			if got.Code != tc.code || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
				t.Fatalf("got%+v want%s,emptyplan", got, tc.code)
			}
		})
	}
}

// Construction refuses unsupported and typed-nil interfaces without invoking
// callbacks. It deep-copies mutable data and bounds cycles and oversized facts.
func TestEvidenceBoundary(t *testing.T) {
	var absent any
	if e := evidence(t, absent); !e.IsAvailable() {
		t.Fatal("explicit null availability lost")
	}
	if (verifier.Evidence{}).IsAvailable() {
		t.Fatal("absent is available")
	}
	var callback *bytes.Buffer
	for _, bad := range []any{callback, func() { t.Fatal("callback invoked") }, make(chan int), bytes.Repeat([]byte{0}, (1<<20)+1)} {
		if e, err := verifier.Present(bad); err == nil || e.IsAvailable() {
			t.Fatal("unsupported/oversize evidence admitted")
		}
	}
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	if e, err := verifier.Present(cycle); err == nil || e.IsAvailable() {
		t.Fatal("cycle admitted")
	}
	v, raw := messageControl(t)
	c := context(t, v.Fixture)
	lib := verifier.New(c)
	v.Fixture["time"].(map[string]any)["trusted"] = false
	v.Fixture["delivery"].(map[string]any)["room"] = "other"
	r := lib.VerifyMessage(raw)
	if r.Code != "accept" {
		t.Fatal("caller mutation altered snapshot", r)
	}
	r.Plan.IDs[0] = "changed"
	if lib.VerifyMessage(raw).Plan.IDs[0] == "changed" {
		t.Fatal("returned plan aliases verifier state")
	}
}

// One verifier with fixed immutable facts can be used concurrently without
// sharing mutable output. This does not prove effect/Commit serialization.
func TestConcurrentVerifier(t *testing.T) {
	v, raw := messageControl(t)
	lib := verifier.New(context(t, v.Fixture))
	want := lib.VerifyMessage(raw)
	if want.Code != "accept" {
		t.Fatal(want)
	}
	var wg sync.WaitGroup
	fail := make(chan verifier.Result, 32)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 4; n++ {
				r := lib.VerifyMessage(raw)
				if !reflect.DeepEqual(r, want) {
					fail <- r
				}
			}
		}()
	}
	wg.Wait()
	close(fail)
	for r := range fail {
		t.Error(r)
	}
}

// Evidence-only exports preserve tri-state revocation and full attestation
// binding; invalid crypto is a definite error, not a fourth successful state.
func TestEvidenceExports(t *testing.T) {
	v, _ := messageControl(t)
	lib := verifier.New(context(t, v.Fixture))
	var root string
	for k := range v.Fixture["revocations"].(map[string]any) {
		root = k
		break
	}
	state, e := lib.CheckRevocation(root, nil, nil)
	if e != nil || state != verifier.NotRevoked {
		t.Fatal(state, e)
	}
	raw, e := b64(v.Input["envelope"])
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := record.Parse(raw, 65536, 16)
	if e != nil {
		t.Fatal(e)
	}
	body := parsed.(map[string]any)["body"].(map[string]any)
	a, e := lib.VerifyAttestation(body["author"].(string), body["author_attestation"].(string), false)
	if e != nil || a.ID != body["author_attestation"] || a.Key != body["author"] {
		t.Fatal(a, e)
	}
	state, e = verifier.New(verifier.Context{}).CheckRevocation(root, nil, nil)
	if e != nil || state != verifier.Unavailable {
		t.Fatal(state, e)
	}
	if a, e = verifier.New(verifier.Context{}).VerifyAttestation("", "", false); e == nil || a != (verifier.Attestation{}) {
		t.Fatal("absent attestation admitted")
	}
	c := context(t, v.Fixture)
	c.SignedSnapshots = evidence(t, []any{})
	state, e = verifier.New(c).CheckRevocation(root, nil, nil)
	if state != verifier.Unavailable || e == nil || code(e) != "key_binding_invalid" {
		t.Fatal(state, e)
	}
}

// The adapter exposes only two wire refusal classes; fine errors remain audit
// data. Missing verifier/state cannot become a successful operator record.
func TestOperatorRecordMapping(t *testing.T) {
	for _, c := range []string{"", "signer_unavailable", "key_binding_unavailable", "time_unavailable", "watermark_unavailable", "revocation_unavailable", "id_journal_unavailable", "replay_unavailable", "state_unavailable"} {
		if got := verifier.OperatorRecordCode(c); got != "operator_record_unavailable" {
			t.Error(c, got)
		}
	}
	for _, c := range []string{"envelope_malformed", "signature_high_s", "expired", "revoked", "act_replay", "act_binding_mismatch", "grant_not_narrowing", "unknown"} {
		if got := verifier.OperatorRecordCode(c); got != "operator_record_invalid" {
			t.Error(c, got)
		}
	}
	if verifier.OperatorRecordCode("accept") != "accept" {
		t.Fatal("positive mapping")
	}
}

// A real signed revoked snapshot reaches the exported Revoked state; a wrong
// exact author reference refuses and returns no partially verified identity.
func TestEvidenceExportRevoked(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/0-negative/W-revoked-reference.json")
	lib := verifier.New(context(t, v.Fixture))
	raw, e := b64(v.Input["envelope"])
	if e != nil {
		t.Fatal(e)
	}
	p, e := record.Parse(raw, 65536, 16)
	if e != nil {
		t.Fatal(e)
	}
	body := p.(map[string]any)["body"].(map[string]any)
	id := body["author_attestation"].(string)
	key := body["author"].(string)
	root := v.Fixture["agent_revocation_root"].(map[string]any)["key"].(string)
	state, e := lib.CheckRevocation(root, []string{id}, []string{key})
	if e != nil || state != verifier.Revoked {
		t.Fatal(state, e)
	}
	a, e := lib.VerifyAttestation(key, id, false)
	if e == nil || code(e) != "revoked" || a != (verifier.Attestation{}) {
		t.Fatal(a, e)
	}
}

// Container, name and scalar overhead must all count toward the snapshot
// budget: the exact boundary accepts, and the one-byte neighbor refuses.
func TestEvidenceExactBudget(t *testing.T) {
	key := strings.Repeat("x", (1<<20)-32)
	if _, e := verifier.Present(map[string]any{key: true}); e != nil {
		t.Fatal(e)
	}
	if e, err := verifier.Present(map[string]any{key + "x": true}); err == nil || e.IsAvailable() {
		t.Fatal("over-budget scalar admitted")
	}
}

// A protected argument tree unsupported by CCJ-1 is a binding failure at O1,
// not an envelope parse error or panic. The unchanged concrete binding accepts.
func TestActBindingInvalidCCJ(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/PO1.json")
	raw, e := b64(v.Input["envelope"])
	if e != nil {
		t.Fatal(e)
	}
	if r := verifier.New(context(t, v.Fixture)).VerifyOperator(raw); r.Code != "accept" {
		t.Fatal(r)
	}
	v.Fixture["binding"].(map[string]any)["arguments"] = map[string]any{"registration_number": float64(1), "mode": "operator"}
	r := verifier.New(context(t, v.Fixture)).VerifyOperator(raw)
	if r.Code != "act_binding_mismatch" || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
		t.Fatal(r)
	}
}
