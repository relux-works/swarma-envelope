package verifier_test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/waggle/verifier"
)

func freshInputs(t *testing.T, v vector) ([][]byte, []byte, []string, []string) {
	t.Helper()
	var chain [][]byte
	for _, value := range v.Input["chain"].([]any) {
		raw, err := b64(value)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, raw)
	}
	cp, err := b64(v.Input["checkpoint"])
	if err != nil {
		t.Fatal(err)
	}
	stringsIn := func(value any) []string {
		var out []string
		for _, v := range value.([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	return chain, cp, stringsIn(v.Input["ids"]), stringsIn(v.Input["keys"])
}
func freshExpected(t *testing.T, r verifier.Result) expected {
	t.Helper()
	raw, err := json.Marshal(r.Plan)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err = d.Decode(&p); err != nil {
		t.Fatal(err)
	}
	return expected{r.Code, normalize(p).(map[string]any)}
}

// The new public API permits an old base only with the full current freshness
// proof. Legacy CheckRevocation still returns unavailable for this same base;
// VerifyJournal also keeps its own checkpoint age; a refused proof has no plan and does not mutate an immutable valid context.
func TestFreshnessAPI(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-FR-old-snapshot.json")
	chain, cp, ids, keys := freshInputs(t, v)
	good := verifier.New(context(t, v.Fixture))
	root := v.Fixture["agent_revocation_root"].(map[string]any)["key"].(string)
	state, err := good.CheckRevocation(root, ids, keys)
	if err != nil || state != verifier.Unavailable {
		t.Fatal("legacy age weakened", state, err)
	}
	if r := good.VerifyJournal(nil, cp, nil); r.Code != "journal_unavailable" || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
		t.Fatal("legacy journal age weakened", r)
	}
	if got := freshExpected(t, good.VerifyFreshness(chain, cp, ids, keys)); !reflect.DeepEqual(got, v.Expected) {
		t.Fatal("exact public API", got, v.Expected)
	}
	v.Fixture["journal_witness"] = true
	bad := verifier.New(context(t, v.Fixture)).VerifyFreshness(chain, cp, ids, keys)
	if bad.Code != "freshness_witness_invalid" || !reflect.DeepEqual(bad.Plan, verifier.Plan{}) {
		t.Fatal("refusal leaked plan", bad)
	}
	if got := freshExpected(t, good.VerifyFreshness(chain, cp, ids, keys)); !reflect.DeepEqual(got, v.Expected) {
		t.Fatal("immutable verifier changed", got)
	}
}

// Named freshness refusals and exact accepted plans, including historical
// proof/count/genesis boundaries, are grounded in the specification fixtures.
func TestFreshnessVectors(t *testing.T) {
	all := namedPaths(t, "../vectors")
	selected := map[string]bool{}
	for _, p := range all {
		n := filepath.Base(p)
		if strings.HasPrefix(n, "N-FR-") || strings.HasPrefix(n, "P-FR-") || strings.HasPrefix(n, "N-ORD-FR-") {
			selected[n] = true
			v := load(t, p)
			if v.Positive != "" {
				selected[v.Positive+".json"] = true
			}
		}
	}
	var paths []string
	for _, p := range all {
		if selected[filepath.Base(p)] {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		t.Fatal("missing freshness corpus")
	}
	runVectors(t, paths)
}

// Byte/depth/count refusals occur before unavailable policy. The valid count
// neighbor is independently covered by P-FR-count64 and N-FR-count65.
func TestFreshnessBounds(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-FR-old-snapshot.json")
	chain, cp, ids, keys := freshInputs(t, v)
	if r := verifier.New(context(t, v.Fixture)).VerifyFreshness(chain, cp, ids, keys); r.Code != "accept" {
		t.Fatal("control", r)
	}
	bad := verifier.New(verifier.Context{})
	for _, tc := range []struct {
		name  string
		chain [][]byte
		cp    []byte
	}{
		{"count", make([][]byte, 65), cp}, {"record-bytes", [][]byte{make([]byte, 8193)}, cp}, {"checkpoint-bytes", chain, make([]byte, 8193)}, {"depth", [][]byte{[]byte(strings.Repeat("[", 17) + strings.Repeat("]", 17))}, cp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bad.VerifyFreshness(tc.chain, tc.cp, ids, keys)
			if r.Code != "freshness_malformed" || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
				t.Fatal(r)
			}
		})
	}
}

// Concurrent calls share only immutable facts and each returns the exact
// independently specified plan. This does not qualify external transactions.
func TestFreshnessConcurrent(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-FR-old-snapshot.json")
	chain, cp, ids, keys := freshInputs(t, v)
	lib := verifier.New(context(t, v.Fixture))
	results := make(chan verifier.Result, 16)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				results <- lib.VerifyFreshness(chain, cp, ids, keys)
			}
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		if got := freshExpected(t, r); !reflect.DeepEqual(got, v.Expected) {
			t.Fatal(got, v.Expected)
		}
	}
}

// Genesis has no predecessor time; the epoch is valid. A real epoch-zero
// predecessor instead requires strict increase, with exact retransmission kept.
// Every case checks the exact code/plan, including the epoch-zero watermark.
func TestFreshnessEpochBoundary(t *testing.T) {
	var paths []string
	for _, id := range []string{"N-FR-epoch-equal", "P-FR-genesis-epoch", "P-FR-genesis-epoch-plus-one", "P-FR-epoch-retransmit", "P-FR-epoch-advance"} {
		dir := "1-positive"
		if strings.HasPrefix(id, "N-") {
			dir = "0-negative"
		}
		paths = append(paths, "../vectors/swarm-envelope-2/"+dir+"/"+id+".json")
	}
	runVectors(t, paths)
}
