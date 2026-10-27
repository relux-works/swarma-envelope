package verifier_test

import (
	"reflect"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// These controls pin the existing O1–O5 order before sharing its private tail.
// They exercise legacy authority, not the proposed owner-acts authority route.
func TestOwnerActPipelineLegacyOrder(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		widen      bool
		change     func(*testing.T, targetFixture, *verifier.Context)
	}{
		{"narrowing", "accept", false, nil},
		{"binding-before-authority", "act_binding_mismatch", false, func(t *testing.T, f targetFixture, c *verifier.Context) {
			c.ActBinding = verifier.Evidence{}
			c.SignerFacts = verifier.Evidence{}
		}},
		{"authority-unavailable", "key_binding_unavailable", false, func(t *testing.T, f targetFixture, c *verifier.Context) { c.SignerFacts = verifier.Evidence{} }},
		{"authority-denied", "key_binding_invalid", false, func(t *testing.T, f targetFixture, c *verifier.Context) {
			c.SignerFacts = evidence(t, map[string]any{"current": false})
		}},
		{"roles-before-authority", "key_binding_invalid", false, func(t *testing.T, f targetFixture, c *verifier.Context) {
			c.GrantRoot = c.OperatorRoot
			c.SignerFacts = verifier.Evidence{}
		}},
		{"attestation-unavailable", "key_binding_unavailable", false, func(t *testing.T, f targetFixture, c *verifier.Context) { c.DeviceAttestations = verifier.Evidence{} }},
		{"revocation-before-replay", "revocation_unavailable", false, func(t *testing.T, f targetFixture, c *verifier.Context) {
			c.SignedSnapshots = verifier.Evidence{}
			c.ReplayAvailable = evidence(t, false)
		}},
		{"replay-unavailable", "replay_unavailable", false, func(t *testing.T, f targetFixture, c *verifier.Context) { c.ReplayAvailable = evidence(t, false) }},
		{"replayed", "act_replay", false, func(t *testing.T, f targetFixture, c *verifier.Context) {
			c.UsedActions = evidence(t, []any{f.body()["action_id"]})
		}},
		{"confirmation-before-presence-replay", "act_confirmation_required", true, func(t *testing.T, f targetFixture, c *verifier.Context) {
			f.body()["confirmed"] = false
			c.SignerFacts = evidence(t, map[string]any{"current": true, "presence": false, "presence_current": false})
			c.ReplayAvailable = evidence(t, false)
		}},
		{"presence-before-replay", "act_presence_required", true, func(t *testing.T, f targetFixture, c *verifier.Context) {
			c.SignerFacts = evidence(t, map[string]any{"current": true, "presence": false, "presence_current": false})
			c.ReplayAvailable = evidence(t, false)
		}},
		{"replay-before-activation", "replay_unavailable", true, func(t *testing.T, f targetFixture, c *verifier.Context) { c.ReplayAvailable = evidence(t, false) }},
		{"widening-closed", "act_a3_inactive", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := targetControl(t, "operator-act/1")
			if tc.widen {
				f.body()["operation"] = "grant.issue"
				f.body()["target"] = map[string]any{"kind": "account", "id": "account-a"}
				f.body()["confirmed"] = true
				binding := f.f["binding"].(map[string]any)
				binding["operation"] = f.body()["operation"]
				binding["target"] = f.body()["target"]
			}
			c := context(t, f.f)
			if tc.widen {
				c.SignerFacts = evidence(t, map[string]any{"current": true, "presence": true, "presence_current": true})
			}
			if tc.change != nil {
				tc.change(t, f, &c)
			}
			raw := f.signed(t)
			r := targetResult(t, c, raw, f.kind, tc.want, true)
			if tc.want == "accept" {
				// Plans own their slices; a caller cannot poison a reused verifier.
				r.Plan.IDs[0] = "changed"
				again := targetResult(t, c, raw, f.kind, "accept", true)
				if reflect.DeepEqual(r.Plan.IDs, again.Plan.IDs) {
					t.Fatal("candidate plan alias")
				}
			}
		})
	}
}
