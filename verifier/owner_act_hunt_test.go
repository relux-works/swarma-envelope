package verifier_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

// Free-hunt cases follow the formal identity sweep. Protected lookup denial
// differs from unavailable provenance even with a current signed attestation.
func TestOwnerActsHuntAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*ownerActFixture)
	}{
		{"withdrawn", "key_binding_invalid", func(x *ownerActFixture) { x.authority["admitted"] = false }},
		{"malformed-result", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["admitted"] = "true" }},
		{"foreign-owner", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["owner"] = "foreign" }},
		{"foreign-installation", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["aud"] = "owner-acts:" + strings.Repeat("c", 32) }},
		{"foreign-epoch", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["epoch"] = "epoch:" + strings.Repeat("c", 32) }},
		{"foreign-device", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["device"] = "other" }},
		{"foreign-profile", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["profile"] = "other/1" }},
		{"foreign-operation", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["operation"] = "owner-dm.bind" }},
		{"foreign-target", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["target"] = dmTarget("other") }},
		{"foreign-generation", "key_binding_unavailable", func(x *ownerActFixture) { x.authority["generation"] = int64(2) }},
		{"head-policy-fork", "key_binding_unavailable", func(x *ownerActFixture) { x.head["policy_id"] = record.Digest([]byte("fork")) }},
		{"below-floor", "key_binding_unavailable", func(x *ownerActFixture) { x.floor["revision"] = int64(2) }},
		{"instance-fence", "key_binding_unavailable", func(x *ownerActFixture) { x.instance["instance_fence"] = "old" }},
		{"source-pin", "key_binding_unavailable", func(x *ownerActFixture) {
			x.profiles["profiles"].(map[string]any)["owner-acts/1"] = record.Digest([]byte("other source"))
		}},
		{"lineage-gap", "key_binding_unavailable", func(x *ownerActFixture) { x.lineage["policies"].([]any)[0].(map[string]any)["revision"] = int64(2) }},
		{"lineage-fork", "key_binding_unavailable", func(x *ownerActFixture) {
			x.lineage["policies"].([]any)[0].(map[string]any)["policy_id"] = record.Digest([]byte("fork"))
		}},
		{"known-role-hidden", "key_binding_invalid", func(x *ownerActFixture) { x.roots["roles"].(map[string]any)["operator_root"] = nil }},
		{"known-commit-hidden", "key_binding_invalid", func(x *ownerActFixture) {
			x.roots["roles"].(map[string]any)["commit_signing_key"] = x.f.f["operator_root"]
		}},
		{"revision-reuse", "act_binding_mismatch", func(x *ownerActFixture) { x.authority["revision"] = int64(2) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			tc.change(x)
			x.snapshots(t)
			x.check(t, tc.want)
		})
	}
	for _, name := range []string{"Selection", "Binding", "Delivery", "Authority", "ActiveHead", "RestoreFloor", "Lineage", "Instance", "RootCatalog", "ProfileCatalog"} {
		t.Run("missing-"+name, func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			switch name {
			case "Selection":
				x.p.Selection = verifier.Evidence{}
			case "Binding":
				x.p.Binding = verifier.Evidence{}
			case "Delivery":
				x.p.Delivery = verifier.Evidence{}
			case "Authority":
				x.p.Authority = verifier.Evidence{}
			case "ActiveHead":
				x.p.ActiveHead = verifier.Evidence{}
			case "RestoreFloor":
				x.p.RestoreFloor = verifier.Evidence{}
			case "Lineage":
				x.p.Lineage = verifier.Evidence{}
			case "Instance":
				x.p.Instance = verifier.Evidence{}
			case "RootCatalog":
				x.p.RootCatalog = verifier.Evidence{}
			case "ProfileCatalog":
				x.p.ProfileCatalog = verifier.Evidence{}
			}
			x.check(t, "key_binding_unavailable")
		})
	}
	// The generic legacy boolean cannot withdraw or grant this exact policy row.
	x := ownerActControl(t, "owner-dm.unbind")
	x.c.SignerFacts = evidence(t, map[string]any{"current": false})
	x.check(t, "accept")
	x.authority["admitted"] = false
	x.snapshots(t)
	x.c.SignerFacts = evidence(t, map[string]any{"current": true})
	x.check(t, "key_binding_invalid")
}

// Every declared protected object member is required independently; a missing
// field or wrong outer container cannot silently default during profile intake.
func TestOwnerActsHuntProtectedAvailability(t *testing.T) {
	objects := func(x *ownerActFixture) map[string]map[string]any {
		return map[string]map[string]any{"selection": x.s, "binding": x.binding, "delivery": x.delivery, "authority": x.authority, "head": x.head, "floor": x.floor, "instance": x.instance, "roots": x.roots, "profiles": x.profiles, "lineage": x.lineage, "audience": x.room}
	}
	control := ownerActControl(t, "owner-dm.mirror-enable")
	for name, object := range objects(control) {
		for field := range object {
			t.Run(name+"/missing-"+field, func(t *testing.T) {
				x := ownerActControl(t, "owner-dm.mirror-enable")
				delete(objects(x)[name], field)
				x.snapshots(t)
				x.check(t, "key_binding_unavailable")
			})
		}
	}
	// Mirror-specific source availability stays distinct from malformed A.
	x := ownerActControl(t, "owner-dm.mirror-enable")
	x.p.RoomAudience = verifier.Evidence{}
	x.check(t, "key_binding_unavailable")
	ownerActControl(t, "owner-dm.unbind").check(t, "accept")
}

// Every independently supplied head/floor/instance tuple member participates
// in exact provenance binding, rather than only its revision or one digest.
func TestOwnerActsHuntProvenanceSubstitutions(t *testing.T) {
	for _, name := range []string{"head", "floor", "instance"} {
		control := ownerActControl(t, "owner-dm.unbind")
		selectObject := func(x *ownerActFixture) map[string]any {
			switch name {
			case "head":
				return x.head
			case "floor":
				return x.floor
			default:
				return x.instance
			}
		}
		for field, value := range selectObject(control) {
			t.Run(name+"/"+field, func(t *testing.T) {
				x := ownerActControl(t, "owner-dm.unbind")
				var replacement any = "foreign"
				if _, ok := value.(int64); ok {
					replacement = int64(2)
				}
				selectObject(x)[field] = replacement
				x.snapshots(t)
				x.check(t, "key_binding_unavailable")
			})
		}
	}
	for _, name := range []string{"version", "id", "audience", "journal"} {
		t.Run("earlier-"+name, func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			x.m.Render = append(x.m.Render, ' ')
			want := ""
			switch name {
			case "version":
				x.f.e["version"] = "swarm-envelope/3"
				want = "envelope_version_unsupported"
			case "id":
				x.f.e["id"] = record.Digest([]byte("other"))
				want = "envelope_id_mismatch"
			case "audience":
				x.c.Audience = evidence(t, "other")
				want = "audience_mismatch"
			case "journal":
				x.c.IDJournalAvailable = evidence(t, false)
				want = "id_journal_unavailable"
			}
			x.check(t, want)
		})
	}
}

// State and delivery facts are independently protected; replacing a valid
// signature and canonical A does not supply current binding or room policy.
func TestOwnerActsHuntBindingAndAudience(t *testing.T) {
	for _, tc := range []struct {
		name, op, want string
		change         func(*ownerActFixture)
	}{
		{"pending-unbind", "owner-dm.unbind", "accept", func(x *ownerActFixture) { x.binding["state"] = "pending" }},
		{"unbound-unbind", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["state"] = "unbound" }},
		{"unknown-effect", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["unknown_effect"] = true }},
		{"reused-generation", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["generation"] = int64(2) }},
		{"reused-binding", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["revision"] = int64(2) }},
		{"other-room", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["bound_room"] = "!other:example.test" }},
		{"other-owner-recipient", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["owner_recipient"] = "@other:example.test" }},
		{"edited", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.delivery["edited"] = true }},
		{"replaced", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.delivery["replaced"] = true }},
		{"moved", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.delivery["moved"] = true }},
		{"other-source", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.delivery["room"] = "!other:example.test" }},
		{"other-consumer", "owner-dm.unbind", "act_binding_mismatch", func(x *ownerActFixture) { x.s["consumer_recipient"] = "@other:example.test" }},
		{"pending-bind", "owner-dm.bind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["state"] = "pending" }},
		{"chosen-future-room", "owner-dm.bind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["bound_room"] = "!future:example.test" }},
		{"bind-mirror", "owner-dm.bind", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["mirror"] = true }},
		{"mirror-pending", "owner-dm.mirror-enable", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["state"] = "pending" }},
		{"mirror-enabled", "owner-dm.mirror-enable", "act_binding_mismatch", func(x *ownerActFixture) { x.binding["mirror"] = true }},
		{"third-principal", "owner-dm.mirror-enable", "act_binding_mismatch", func(x *ownerActFixture) {
			x.room["principals"] = append(x.room["principals"].([]any), "@extra:example.test")
		}},
		{"public-room", "owner-dm.mirror-enable", "act_binding_mismatch", func(x *ownerActFixture) { x.room["private"] = false }},
		{"public-join", "owner-dm.mirror-enable", "act_binding_mismatch", func(x *ownerActFixture) { x.room["invite_only"] = false }},
		{"audience-revision", "owner-dm.mirror-enable", "act_binding_mismatch", func(x *ownerActFixture) { x.room["revision"] = int64(2) }},
		{"audience-digest", "owner-dm.mirror-enable", "act_binding_mismatch", func(x *ownerActFixture) { x.room["digest"] = record.Digest([]byte("other audience")) }},
		{"audience-service", "owner-dm.mirror-enable", "act_binding_mismatch", func(x *ownerActFixture) { x.room["service"] = "@other:example.test" }},
		{"protected-mode", "owner-dm.unbind", "act_a3_inactive", func(x *ownerActFixture) { x.s["candidate_enabled"] = false }},
		{"protected-critical", "owner-dm.unbind", "act_a3_inactive", func(x *ownerActFixture) { x.s["critical"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) { x := ownerActControl(t, tc.op); tc.change(x); x.snapshots(t); x.check(t, tc.want) })
	}
}

// Mandatory /2 receipt checks stay after common time and before validity/O1.
// No absent flag, old version or forged/copied pointer opens a fallback.
func TestOwnerActsHuntCurrency(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*testing.T, *ownerActFixture)
	}{
		{"missing-with-false-flag", "freshness_receipt_unavailable", func(t *testing.T, x *ownerActFixture) {
			x.c.FreshnessReceipt = nil
			x.c.RequireFreshnessReceipt = false
		}},
		{"pin-zero", "freshness_receipt_binding_mismatch", func(t *testing.T, x *ownerActFixture) { x.c.RegistryCurrencyVersion = 0 }},
		{"pin-one", "freshness_receipt_binding_mismatch", func(t *testing.T, x *ownerActFixture) { x.c.RegistryCurrencyVersion = 1 }},
		{"forged", "freshness_receipt_invalid", func(t *testing.T, x *ownerActFixture) { x.c.FreshnessReceipt = &verifier.FreshnessReceipt{} }},
		{"copied", "freshness_receipt_invalid", func(t *testing.T, x *ownerActFixture) { copy := *x.c.FreshnessReceipt; x.c.FreshnessReceipt = &copy }},
		{"exclusive-expiry", "freshness_receipt_expired", func(t *testing.T, x *ownerActFixture) {
			x.c.Now = evidence(t, "2026-01-01T00:02:00Z")
			x.c.Watermark = x.c.Now
		}},
		{"new-read-no-extension", "freshness_receipt_expired", func(t *testing.T, x *ownerActFixture) {
			x.c.Now = evidence(t, "2026-01-01T00:02:00Z")
			x.c.Watermark = x.c.Now
			x.c.WitnessReadAt = x.c.Now
		}},
		{"rebuilt-originals", "freshness_receipt_binding_mismatch", func(t *testing.T, x *ownerActFixture) { x.c.SignedSnapshots = context(t, x.f.f).SignedSnapshots }},
		{"rebuilt-journal", "freshness_receipt_binding_mismatch", func(t *testing.T, x *ownerActFixture) { x.c.SnapshotJournal = context(t, x.f.f).SnapshotJournal }},
		{"missing-originals", "freshness_receipt_unavailable", func(t *testing.T, x *ownerActFixture) { x.c.SignedSnapshots = verifier.Evidence{} }},
		{"missing-journal", "freshness_receipt_unavailable", func(t *testing.T, x *ownerActFixture) { x.c.SnapshotJournal = verifier.Evidence{} }},
		{"future-read", "freshness_receipt_invalid", func(t *testing.T, x *ownerActFixture) { x.c.WitnessReadAt = evidence(t, "2026-01-01T00:01:01Z") }},
		{"missing-time-before-receipt", "time_unavailable", func(t *testing.T, x *ownerActFixture) { x.c.Time = verifier.Evidence{}; x.c.FreshnessReceipt = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) { x := ownerActControl(t, "owner-dm.unbind"); tc.change(t, x); x.check(t, tc.want) })
	}
	// now<W is valid when both endpoints remain within all windows.
	x := ownerActControl(t, "owner-dm.unbind")
	x.c.Now = evidence(t, "2026-01-01T00:01:01Z")
	x.c.Watermark = evidence(t, "2026-01-01T00:01:02Z")
	r := verifier.New(x.c).VerifyOwnerAct(targetWire(t, x.f.e), x.m.Arguments, x.m.Render, x.p)
	if r.Code != "accept" || r.Plan.Watermark != "2026-01-01T00:01:02Z" {
		t.Fatal(r)
	}
}

// Complete coverage is independently mandatory even with a fresh operator
// snapshot and an authentic receipt covering the registry. Missing retained
// originals and stale authenticated reads fail at actual shared minting.
func TestOwnerActsHuntCoverageAndOriginals(t *testing.T) {
	x := ownerActVectorControl(t, "owner-dm.unbind", "owner-a", "../vectors/swarm-envelope-2/0-negative/N-CU-coverage-operator-required.json")
	x.c.RequireFreshnessReceipt = false
	x.check(t, "freshness_receipt_unavailable")
	ownerActControl(t, "owner-dm.unbind").check(t, "accept")
	for _, name := range []string{"N-CU-missing-original", "N-CU-stale-witness"} {
		t.Run(name, func(t *testing.T) {
			v := load(t, "../vectors/swarm-envelope-2/0-negative/"+name+".json")
			chain, cp, ids, keys := freshInputs(t, v)
			r := verifier.New(context(t, v.Fixture)).VerifyFreshness(chain, cp, ids, keys)
			assertOwnerActRefusal(t, r, "freshness_unavailable")
		})
	}
}

// Compound failures retain E-before-O1, O1-before-O2 and O3/O4-before-O5.
func TestOwnerActsHuntGateOrder(t *testing.T) {
	for _, op := range []string{"owner-dm.bind", "owner-dm.mirror-enable"} {
		for _, tc := range []struct {
			name, want string
			change     func(*testing.T, *ownerActFixture)
		}{
			{"confirmation", "act_confirmation_required", func(t *testing.T, x *ownerActFixture) {
				x.in.Confirmed = false
				x.remap(t)
				x.c.ReplayAvailable = evidence(t, false)
			}},
			{"presence", "act_presence_required", func(t *testing.T, x *ownerActFixture) {
				x.c.SignerFacts = evidence(t, map[string]any{"presence": false, "presence_current": true})
				x.c.ReplayAvailable = evidence(t, false)
			}},
			{"replay", "replay_unavailable", func(t *testing.T, x *ownerActFixture) { x.c.ReplayAvailable = evidence(t, false) }},
			{"used", "act_replay", func(t *testing.T, x *ownerActFixture) { x.c.UsedActions = evidence(t, []any{x.in.ActionID}) }},
		} {
			t.Run(op+"/"+tc.name, func(t *testing.T) { x := ownerActControl(t, op); tc.change(t, x); x.check(t, tc.want) })
		}
	}
	for _, op := range []string{"launch.approve", "host.change", "unknown.operation", "revoke", "grant.issue"} {
		t.Run(op, func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			x.f.body()["operation"] = op
			x.f.signed(t)
			x.p.Selection = verifier.Evidence{}
			x.check(t, "act_operation_unknown")
		})
	}
	x := ownerActControl(t, "owner-dm.unbind")
	x.m.Render = append(x.m.Render, ' ')
	x.p.ActiveHead = verifier.Evidence{}
	x.check(t, "act_binding_mismatch")
	sig := x.f.e["signatures"].([]any)[0].(map[string]any)
	wire, _ := base64.RawURLEncoding.DecodeString(sig["sig"].(string))
	wire[0] ^= 1
	sig["sig"] = base64.RawURLEncoding.EncodeToString(wire)
	x.check(t, "envelope_signature_invalid")
	// Existing APIs do not turn new syntax into operator authority.
	x = ownerActControl(t, "owner-dm.unbind")
	assertOwnerActRefusal(t, verifier.New(x.c).VerifyOperator(targetWire(t, x.f.e)), "act_operation_unknown")
}

// Immutable snapshots retain their values after safe later caller mutation;
// candidate output mutation and repeated calls reserve nothing or share plans.
func TestOwnerActsHuntReuseAndBounds(t *testing.T) {
	x := ownerActControl(t, "owner-dm.unbind")
	x.s["owner"] = "later caller mutation"
	x.authority["admitted"] = false
	x.head["revision"] = int64(99)
	x.binding["state"] = "unbound"
	x.check(t, "accept")
	r := x.check(t, "accept")
	r.Plan.IDs[0] = "changed"
	x.check(t, "accept")
	v := verifier.New(x.c)
	raw := targetWire(t, x.f.e)
	for i := 0; i < 2; i++ {
		got := v.VerifyOwnerAct(raw, x.m.Arguments, x.m.Render, x.p)
		if got.Code != "accept" || got.Plan.IDs[0] != x.m.ContentID {
			t.Fatal(got)
		}
	}
	for _, tc := range []struct {
		name    string
		a, text []byte
		want    string
	}{
		{"missing-text", x.m.Arguments, nil, "key_binding_unavailable"},
		{"empty-text", x.m.Arguments, []byte{}, "act_binding_mismatch"},
		{"invalid-UTF8", x.m.Arguments, []byte{255}, "act_binding_mismatch"},
		{"long-text", x.m.Arguments, bytes.Repeat([]byte("x"), 4097), "act_binding_mismatch"},
		{"long-A", bytes.Repeat([]byte("x"), 2049), x.m.Render, "act_binding_mismatch"},
		{"duplicate-A", bytes.Replace(x.m.Arguments, []byte(`"profile":`), []byte(`"profile":"owner-acts/1","profile":`), 1), x.m.Render, "act_binding_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) { assertOwnerActRefusal(t, v.VerifyOwnerAct(raw, tc.a, tc.text, x.p), tc.want) })
	}
	oversize := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), 8193-len(raw))...)
	assertOwnerActRefusal(t, v.VerifyOwnerAct(oversize, bytes.Repeat([]byte("x"), 2049), nil, x.p), "envelope_too_large")
}
