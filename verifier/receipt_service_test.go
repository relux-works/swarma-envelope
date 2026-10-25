package verifier_test

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/waggle/verifier"
)

// A service call validates R1-R3 without renewing grant-root age; time precedes
// R, R precedes validity, and effective revocation and exact identity still hold.
func TestFreshnessReceiptService(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		if strings.Contains(filepath.Base(p), "RC-service") {
			paths = append(paths, p)
		}
	}
	if len(paths) != 12 {
		t.Fatalf("service receipt cases %d", len(paths))
	}
	runVectors(t, paths)
}

// A current service identity cannot hide a zero, copied or allocated receipt.
// Original-pointer and optional-absence controls remain accepting.
func TestFreshnessReceiptServiceProvenance(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-RC-service.json")
	c, minted := receiptContext(t, v)
	if minted.Code != "accept" {
		t.Fatal(minted)
	}
	copy := *minted.FreshnessReceipt
	allocated := reflect.New(reflect.TypeOf(copy)).Interface().(*verifier.FreshnessReceipt)
	for name, pointer := range map[string]*verifier.FreshnessReceipt{"zero": {}, "copy": &copy, "reflection": allocated} {
		t.Run(name, func(t *testing.T) {
			bad := c
			bad.RequireFreshnessReceipt = false
			bad.FreshnessReceipt = pointer
			if got := consumeReceipt(t, v, bad); got.Code != "freshness_receipt_invalid" {
				t.Fatal(got)
			}
		})
	}
	if got := consumeReceipt(t, v, c); got.Code != "accept" {
		t.Fatal(got)
	}
	c.FreshnessReceipt, c.RequireFreshnessReceipt = nil, false
	if got := consumeReceipt(t, v, c); got.Code != "accept" {
		t.Fatal(got)
	}
}

// Full F producers ignore receipt-consumption fields and independently mint;
// journal verification ignores them and preserves its own signed-snapshot age.
// Compare exact legacy verdict/plan controls, including a journal refusal.
func TestFreshnessReceiptOutsideMode(t *testing.T) {
	for _, id := range []string{"P-RC-attestation", "P-RC-reanchor"} {
		t.Run(id, func(t *testing.T) {
			v := load(t, "../vectors/swarm-envelope-2/1-positive/"+id+".json")
			mint := v.Input["mint"].(map[string]any)
			mv := vector{Input: mint["input"].(map[string]any), Fixture: v.Fixture}
			chain, cp, ids, keys := freshInputs(t, mv)
			invoke := func(c verifier.Context) verifier.Result {
				if mint["mode"] == "freshness-reanchor" {
					return verifier.New(c).VerifyFreshnessReanchor(chain[0], cp, ids, keys)
				}
				return verifier.New(c).VerifyFreshness(chain, cp, ids, keys)
			}
			c := context(t, v.Fixture)
			baseline := invoke(c)
			if baseline.Code != "accept" {
				t.Fatal(baseline)
			}
			for _, pointer := range []*verifier.FreshnessReceipt{nil, {}} {
				c.FreshnessReceipt, c.RequireFreshnessReceipt, c.FreshnessMarginSeconds = pointer, true, 61
				got := invoke(c)
				if got.Code != baseline.Code || !reflect.DeepEqual(got.Plan, baseline.Plan) || got.FreshnessReceipt == nil || got.FreshnessReceipt == pointer {
					t.Fatal("producer consumed prior receipt", got)
				}
				if _, ok := got.FreshnessReceipt.Audit(); !ok {
					t.Fatal("producer did not mint", got)
				}
			}
		})
	}
	for _, tc := range []struct{ id, code string }{{"P-JRN-genesis", "accept"}, {"N-JRN-snapshot-stale", "journal_unavailable"}} {
		t.Run(tc.id, func(t *testing.T) {
			dir := "0-negative"
			if tc.code == "accept" {
				dir = "1-positive"
			}
			v := load(t, "../vectors/swarm-envelope-2/"+dir+"/"+tc.id+".json")
			var entries [][]byte
			for _, value := range v.Input["entries"].([]any) {
				raw, err := b64(value)
				if err != nil {
					t.Fatal(err)
				}
				entries = append(entries, raw)
			}
			cp, err := b64(v.Input["checkpoint"])
			if err != nil {
				t.Fatal(err)
			}
			c := context(t, v.Fixture)
			baseline := verifier.New(c).VerifyJournal(entries, cp, nil)
			if baseline.Code != tc.code {
				t.Fatal(baseline)
			}
			for _, pointer := range []*verifier.FreshnessReceipt{nil, {}} {
				c.FreshnessReceipt, c.RequireFreshnessReceipt, c.FreshnessMarginSeconds = pointer, true, 61
				if got := verifier.New(c).VerifyJournal(entries, cp, nil); !reflect.DeepEqual(got, baseline) {
					t.Fatal("journal consumed receipt", got)
				}
			}
		})
	}
}
