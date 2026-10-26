package verifier_test

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Recovery fixtures assert exact audit plans and refusals with zero plans.
// Each negative has a valid neighbor; default gap rejection remains independent
// of the explicitly requested recovery result on the identical signed input.
func TestFreshnessReanchorVectors(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		if strings.Contains(filepath.Base(p), "FR-RA-") {
			paths = append(paths, p)
		}
	}
	if len(paths) != 29 {
		t.Fatalf("recovery fixture count %d", len(paths))
	}
	runVectors(t, paths)
}

// The sibling accepts one tip without its predecessors only on explicit call.
// Normal admission keeps the gap refusal; adjacent recovery audits zero skips,
// while normal bounded-chain plans have no recovery marker. A refused request
// cannot mutate an already constructed immutable verifier's later result.
func TestFreshnessReanchorAPI(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-FR-RA-same.json")
	chain, cp, ids, keys := freshInputs(t, v)
	lib := verifier.New(context(t, v.Fixture))
	if got := lib.VerifyFreshness(chain, cp, ids, keys); got.Code != "freshness_gap" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
		t.Fatal("default recovered", got)
	}
	good := lib.VerifyFreshnessReanchor(chain[0], cp, ids, keys)
	if got := freshExpected(t, good); !reflect.DeepEqual(got, v.Expected) {
		t.Fatal(got, v.Expected)
	}
	if got := lib.VerifyFreshnessReanchor(chain[0], cp, []string{"invalid"}, keys); got.Code != "freshness_request_invalid" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
		t.Fatal(got)
	}
	if got := lib.VerifyFreshnessReanchor(chain[0], cp, ids, keys); !reflect.DeepEqual(got, good) {
		t.Fatal("mutated context", got)
	}
	for _, id := range []string{"P-FR-old-snapshot", "P-FR-chain", "P-FR-count64"} {
		v = load(t, "../vectors/swarm-envelope-2/1-positive/"+id+".json")
		chain, cp, ids, keys = freshInputs(t, v)
		got := verifier.New(context(t, v.Fixture)).VerifyFreshness(chain, cp, ids, keys)
		if got.Code != "accept" || got.Plan.Reanchor != nil {
			t.Fatal(id, got)
		}
	}
}

// Single-tip recovery inherits the raw byte/depth bounds before missing policy;
// an empty raw tip is malformed, never an absent-chain automatic bootstrap.
func TestFreshnessReanchorBounds(t *testing.T) {
	lib := verifier.New(verifier.Context{})
	for _, raw := range [][]byte{nil, make([]byte, 8193), []byte(strings.Repeat("[", 17) + strings.Repeat("]", 17))} {
		if got := lib.VerifyFreshnessReanchor(raw, nil, nil, nil); got.Code != "freshness_malformed" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
			t.Fatal(got)
		}
	}
}

// Without attaching a receipt, optional-absence legacy admission still checks
// snapshot own-age: the old base refuses, while the genuinely current signed
// snapshot at the age boundary permits the same valid agent identity.
func TestFreshnessCompositionBoundary(t *testing.T) {
	for _, tc := range []struct {
		id     string
		accept bool
	}{{"P-FR-old-snapshot", false}, {"P-FR-changed", true}} {
		t.Run(tc.id, func(t *testing.T) {
			v := load(t, "../vectors/swarm-envelope-2/1-positive/"+tc.id+".json")
			chain, cp, ids, keys := freshInputs(t, v)
			lib := verifier.New(context(t, v.Fixture))
			if got := lib.VerifyFreshness(chain, cp, ids, keys); got.Code != "accept" {
				t.Fatal("freshness control", got)
			}
			refs := v.Fixture["agent_attestation_ids"].(map[string]any)
			for key, ref := range refs {
				a, err := lib.VerifyAttestation(key, ref.(string), false)
				if tc.accept {
					if err != nil || a.Key != key || a.ID != ref {
						t.Fatal("current snapshot control", a, err)
					}
				} else if code(err) != "key_binding_unavailable" || a != (verifier.Attestation{}) {
					t.Fatal("old snapshot composed", a, err)
				}
			}
			if len(refs) == 0 {
				t.Fatal("missing identity control")
			}
		})
	}
}
