package verifier_test

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

type ownerActFixture struct {
	c                                                                                      verifier.Context
	p                                                                                      verifier.OwnerActContext
	f                                                                                      targetFixture
	m                                                                                      owneracts.Mapping
	in                                                                                     owneracts.MappingInput
	s, binding, delivery, authority, head, floor, instance, roots, profiles, lineage, room map[string]any
}

func assertOwnerActRefusal(t *testing.T, r verifier.Result, want string) {
	t.Helper()
	if r.Code != want || !reflect.DeepEqual(r.Plan, verifier.Plan{}) || r.FreshnessReceipt != nil {
		t.Fatalf("got %+v, want %s and zero output", r, want)
	}
}

// This fixture uses only published synthetic keys and the existing full /2
// minting path. The protected facts are explicit pure-function premises, not
// evidence of a qualified source, storage floor, carrier or effect boundary.
func ownerActControl(t *testing.T, op string) *ownerActFixture {
	t.Helper()
	return ownerActOwnerControl(t, op, "owner-a")
}

func ownerActOwnerControl(t *testing.T, op, owner string) *ownerActFixture {
	t.Helper()
	return ownerActVectorControl(t, op, owner, "../vectors/swarm-envelope-2/1-positive/P-CU-receipt-operator.json")
}

func ownerActVectorControl(t *testing.T, op, owner, path string) *ownerActFixture {
	t.Helper()
	v := load(t, path)
	return ownerActFrom(t, op, owner, v)
}

func ownerActFrom(t *testing.T, op, owner string, v vector) *ownerActFixture {
	t.Helper()
	if owner != "owner-a" {
		v.Fixture["operator_owner"] = owner
		for device, wire := range v.Fixture["operator_attestations"].(map[string]any) {
			raw, err := b64(wire)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := record.Parse(raw, 8192, 16)
			if err != nil {
				t.Fatal(err)
			}
			a := targetFixture{kind: "attestation/1", e: parsed.(map[string]any)}
			a.body()["binding"].(map[string]any)["owner"] = owner
			v.Fixture["operator_attestations"].(map[string]any)[device] = base64.RawURLEncoding.EncodeToString(a.signed(t))
		}
	}
	c, r := receiptContext(t, v)
	if r.Code != "accept" || r.FreshnessReceipt == nil {
		t.Fatal("genuine /2 mint", r)
	}
	audit, ok := r.FreshnessReceipt.Audit()
	if !ok || audit.RegistryCurrencyVersion != 2 || len(audit.Snapshots) < 1 {
		t.Fatal("/2 covered operator control", audit)
	}
	raw, err := b64(v.Input["consume"].(map[string]any)["input"].(map[string]any)["envelope"])
	if err != nil {
		t.Fatal(err)
	}
	e, err := record.Parse(raw, 8192, 16)
	if err != nil {
		t.Fatal(err)
	}
	f := targetFixture{kind: "operator-act/1", e: e.(map[string]any), f: v.Fixture}
	b := f.body()
	b["owner"] = owner
	device := f.e["signatures"].([]any)[0].(map[string]any)["key"].(string)
	aud := "owner-acts:" + strings.Repeat("a", 32)
	epoch := "epoch:" + strings.Repeat("b", 32)
	pin := record.Digest([]byte("explicit synthetic protected profile source identity"))
	rootID := record.Digest([]byte("explicit synthetic protected complete root catalog identity"))
	profileID := record.Digest([]byte("explicit synthetic protected complete profile catalog identity"))
	policyID := record.Digest([]byte("explicit synthetic protected selected policy identity"))
	x := &ownerActFixture{c: c, f: f}
	x.s = map[string]any{"aud": aud, "owner": b["owner"], "epoch": epoch, "device": device, "owner_recipient": "@owner:example.test", "consumer_recipient": "@consumer:example.test", "profile_pin": pin, "candidate_enabled": true, "critical": false, "presence_required": false}
	x.binding = map[string]any{"identity": "slot", "generation": int64(1), "revision": int64(1), "state": "active", "bound_room": "!bound:example.test", "owner_recipient": x.s["owner_recipient"], "mirror": false, "unknown_effect": false}
	x.delivery = map[string]any{"room": "!source:example.test", "recipient": "@consumer:example.test", "edited": false, "replaced": false, "moved": false}
	x.authority = map[string]any{"aud": aud, "owner": b["owner"], "epoch": epoch, "revision": int64(1), "policy_id": policyID, "previous": nil, "root_catalog_id": rootID, "profile_catalog_id": profileID, "instance_fence": "synthetic-instance-1", "device": device, "profile": "owner-acts/1", "operation": op, "target": dmTarget("slot"), "generation": int64(1), "admitted": true}
	x.head = map[string]any{}
	for _, n := range strings.Fields("aud owner epoch revision policy_id previous root_catalog_id profile_catalog_id instance_fence") {
		x.head[n] = x.authority[n]
	}
	x.floor = map[string]any{}
	for n, value := range x.head {
		x.floor[n] = value
	}
	x.instance = map[string]any{"aud": aud, "owner": b["owner"], "epoch": epoch, "instance_fence": x.head["instance_fence"], "profile_pin": pin}
	roles := map[string]any{}
	for _, n := range strings.Fields("service_root agent_revocation_root operator_root root commit_signing_key enrollment_publisher service_authority service_attestations") {
		roles[n] = v.Fixture[n]
	}
	x.roots = map[string]any{"id": rootID, "roles": roles}
	x.profiles = map[string]any{"id": profileID, "profiles": map[string]any{"owner-acts/1": pin}}
	x.lineage = map[string]any{"aud": aud, "owner": b["owner"], "epoch": epoch, "policies": []any{map[string]any{"revision": int64(1), "policy_id": policyID, "previous": nil}}}
	x.room = map[string]any{"room": x.binding["bound_room"], "owner": x.s["owner_recipient"], "service": x.delivery["recipient"], "revision": int64(1), "private": true, "invite_only": true, "principals": []any{x.s["owner_recipient"], x.delivery["recipient"]}}
	x.room["digest"] = record.Digest(targetWire(t, map[string]any{"room": x.room["room"], "owner": x.room["owner"], "service": x.room["service"]}))
	a := owneracts.ArgumentInput{SourceRoom: x.delivery["room"].(string), SourceRecipient: x.delivery["recipient"].(string), AuthorityRevision: 1, IdentityGeneration: 1, BindingRevision: 1, OwnerRecipient: x.s["owner_recipient"].(string), BoundRoom: x.binding["bound_room"].(string)}
	if op == "owner-dm.bind" {
		x.binding["state"], x.binding["bound_room"] = "unbound", ""
		a.BoundRoom = ""
	}
	if op == "owner-dm.mirror-enable" {
		x.binding["state"] = "joined"
		a.Mirror = true
		a.AudienceRevision = 1
		a.AudienceDigest = x.room["digest"].(string)
	}
	x.in = owneracts.MappingInput{Operation: op, Identity: "slot", Owner: b["owner"].(string), Epoch: epoch, Audience: aud, ActionID: b["action_id"].(string), Nonce: b["nonce"].(string), IssuedAt: b["iat"].(string), ExpiresAt: b["exp"].(string), Confirmed: op != "owner-dm.unbind", Key: device, Arguments: a}
	x.remap(t)
	x.c.Audience = evidence(t, aud)
	x.snapshots(t)
	return x
}

func (x *ownerActFixture) remap(t *testing.T) {
	t.Helper()
	m, err := owneracts.Map(x.in)
	if err != nil {
		t.Fatal(err)
	}
	x.m = m
	b, err := record.Parse(m.Body, 8192, 16)
	if err != nil {
		t.Fatal(err)
	}
	x.f.e["body"] = b
	x.f.signed(t)
}
func (x *ownerActFixture) snapshots(t *testing.T) {
	t.Helper()
	x.p = verifier.OwnerActContext{Selection: evidence(t, x.s), Binding: evidence(t, x.binding), Delivery: evidence(t, x.delivery), Authority: evidence(t, x.authority), ActiveHead: evidence(t, x.head), RestoreFloor: evidence(t, x.floor), Lineage: evidence(t, x.lineage), Instance: evidence(t, x.instance), RootCatalog: evidence(t, x.roots), ProfileCatalog: evidence(t, x.profiles), RoomAudience: evidence(t, x.room)}
}
func (x *ownerActFixture) check(t *testing.T, want string) verifier.Result {
	t.Helper()
	raw := targetWire(t, x.f.e)
	before := bytes.Clone(raw)
	a := bytes.Clone(x.m.Arguments)
	text := bytes.Clone(x.m.Render)
	r := verifier.New(x.c).VerifyOwnerAct(raw, x.m.Arguments, x.m.Render, x.p)
	if r.Code != want {
		t.Fatalf("got %s want %s: %+v", r.Code, want, r)
	}
	if !bytes.Equal(raw, before) || !bytes.Equal(a, x.m.Arguments) || !bytes.Equal(text, x.m.Render) {
		t.Fatal("caller bytes mutated")
	}
	if want != "accept" {
		if !reflect.DeepEqual(r.Plan, verifier.Plan{}) || r.FreshnessReceipt != nil {
			t.Fatal("refusal leaked output", r)
		}
	} else {
		wantPlan := verifier.Plan{IDs: []string{x.m.ContentID}, Watermark: "2026-01-01T00:01:00Z", ActionID: x.in.ActionID}
		if !reflect.DeepEqual(r.Plan, wantPlan) || r.FreshnessReceipt != nil {
			t.Fatal("candidate output", r)
		}
	}
	return r
}

// A real signed narrowing act with original /2 evidence reaches the full path;
// the two fixed widening operations reach the independent closed O5 gate.
func TestOwnerActsSignedControls(t *testing.T) {
	for _, op := range []string{"owner-dm.unbind", "owner-dm.bind", "owner-dm.mirror-enable"} {
		t.Run(op, func(t *testing.T) {
			x := ownerActControl(t, op)
			want := "act_a3_inactive"
			if op == "owner-dm.unbind" {
				want = "accept"
			}
			x.check(t, want)
		})
	}
}

// A linked policy replacement changes every independently retained selection
// tuple and signed authority revision; preserving only the old tuple refuses.
func TestOwnerActsPolicySuccessor(t *testing.T) {
	x := ownerActControl(t, "owner-dm.unbind")
	old := x.authority["policy_id"]
	newID := record.Digest([]byte("explicit synthetic protected successor policy identity"))
	for _, m := range []map[string]any{x.authority, x.head, x.floor} {
		m["revision"], m["policy_id"], m["previous"] = int64(2), newID, old
	}
	x.lineage["policies"] = append(x.lineage["policies"].([]any), map[string]any{"revision": int64(2), "policy_id": newID, "previous": old})
	x.in.Arguments.AuthorityRevision = 2
	x.remap(t)
	x.snapshots(t)
	x.check(t, "accept")
	x.floor["policy_id"] = old
	x.snapshots(t)
	x.check(t, "key_binding_unavailable")
}

// Wrong supported outer Go values refuse as unavailable, with no panic. This
// is an in-process source boundary, not another raw policy document parser.
func TestOwnerActsMalformedSources(t *testing.T) {
	for _, name := range []string{"Selection", "Binding", "Delivery", "Authority", "ActiveHead", "RestoreFloor", "Lineage", "Instance", "RootCatalog", "ProfileCatalog", "RoomAudience"} {
		t.Run(name, func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.mirror-enable")
			reflect.ValueOf(&x.p).Elem().FieldByName(name).Set(reflect.ValueOf(evidence(t, []any{})))
			x.check(t, "key_binding_unavailable")
		})
	}
	// A protected presence restriction strengthens otherwise narrowing unbind.
	x := ownerActControl(t, "owner-dm.unbind")
	x.s["presence_required"] = true
	x.snapshots(t)
	x.c.SignerFacts = evidence(t, map[string]any{"presence": false, "presence_current": false})
	x.check(t, "act_confirmation_required")
	x.in.Confirmed = true
	x.remap(t)
	x.check(t, "act_presence_required")
	x.c.SignerFacts = evidence(t, map[string]any{"presence": true, "presence_current": true})
	x.check(t, "accept")
}
