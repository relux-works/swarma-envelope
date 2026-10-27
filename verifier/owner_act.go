package verifier

import (
	"bytes"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/owneracts"
	"github.com/relux-works/swarma-envelope/record"
)

// OwnerActContext contains independently protected, immutable in-process
// snapshots. These values are not a policy document, provisioning protocol or
// proof of qualified storage. Their sources must authenticate exact scope,
// complete catalogs, active selection, lineage and serving-instance continuity.
// Selection, Binding and Delivery supply O1 facts; Authority, ActiveHead,
// RestoreFloor, Instance and both catalogs supply independent O2 provenance.
// RoomAudience is required only for mirror-enable. Missing snapshots do not
// default to an empty set, a current flag or received argument values.
type OwnerActContext struct {
	Selection      Evidence
	Binding        Evidence
	Delivery       Evidence
	Authority      Evidence
	ActiveHead     Evidence
	RestoreFloor   Evidence
	Lineage        Evidence
	Instance       Evidence
	RootCatalog    Evidence
	ProfileCatalog Evidence
	RoomAudience   Evidence
}

// VerifyOwnerAct verifies a prospective owner-acts/1 candidate using the common
// envelope and operator pipelines. Arguments and deliveredText are separately
// received bytes, not reconstructed hints. Every call requires a genuine /2
// receipt regardless of Context.RequireFreshnessReceipt. No call reserves an
// action, signs, changes authority or permits an effect.
func (v Verifier) VerifyOwnerAct(raw, arguments, deliveredText []byte, c OwnerActContext) Result {
	// Inspect all byte bounds before any input decoding/copying; later-input
	// refusals remain at O1 after the envelope's existing earlier failures.
	argumentsBounded := len(arguments) <= 2048
	textBounded := len(deliveredText) <= 4096
	return decide(func() Plan {
		context := v.context
		context.RequireFreshnessReceipt = true
		f := New(context).consumerFacts()
		f["_ownerActs"] = true
		e := envelope(raw, "operator-act/1", f)
		b := obj(e["body"])
		op := str(b["operation"])
		widen := op == "owner-dm.bind" || op == "owner-dm.mirror-enable"
		need(widen || op == "owner-dm.unbind", "act_operation_unknown")
		need(deliveredText != nil, "key_binding_unavailable")
		need(argumentsBounded && textBounded && utf8.Valid(deliveredText), "act_binding_mismatch")
		_, err := owneracts.Parse(op, arguments)
		need(err == nil, "act_binding_mismatch")
		s := ownerSource(c.Selection, "aud owner epoch device owner_recipient consumer_recipient profile_pin candidate_enabled critical presence_required")
		for _, name := range []string{"aud", "owner", "epoch", "device", "owner_recipient", "consumer_recipient", "profile_pin"} {
			need(isString(s[name]) && str(s[name]) != "", "key_binding_unavailable")
		}
		for _, name := range []string{"candidate_enabled", "critical", "presence_required"} {
			need(isBool(s[name]), "key_binding_unavailable")
		}
		need(record.IsContentID(str(s["profile_pin"])), "key_binding_unavailable")
		binding := ownerSource(c.Binding, "identity generation revision state bound_room owner_recipient mirror unknown_effect")
		delivery := ownerSource(c.Delivery, "room recipient edited replaced moved")
		authority := ownerSource(c.Authority, "aud owner epoch revision policy_id previous root_catalog_id profile_catalog_id instance_fence device profile operation target generation admitted")
		for _, name := range []string{"edited", "replaced", "moved"} {
			need(isBool(delivery[name]), "key_binding_unavailable")
			need(delivery[name] == false, "act_binding_mismatch")
		}
		need(isBool(binding["unknown_effect"]) && isBool(binding["mirror"]) && isString(binding["state"]), "key_binding_unavailable")
		need(target(map[string]any{"kind": "owner-dm", "id": binding["identity"]}, false, true), "key_binding_unavailable")
		need(ascii(delivery["room"]) && ascii(delivery["recipient"]) && ascii(s["owner_recipient"]) && ascii(s["consumer_recipient"]), "key_binding_unavailable")
		need(isInt(authority["revision"]) && num(authority["revision"]) >= 1 && num(authority["revision"]) <= 9007199254740990 && isInt(binding["generation"]) && num(binding["generation"]) >= 1 && num(binding["generation"]) <= 9007199254740990 && isInt(binding["revision"]) && num(binding["revision"]) >= 0 && num(binding["revision"]) <= 9007199254740990, "key_binding_unavailable")
		need(binding["unknown_effect"] == false, "act_binding_mismatch")
		need(equal(b["aud"], s["aud"]) && equal(b["owner"], s["owner"]) && equal(b["epoch"], s["epoch"]), "act_binding_mismatch")
		signer := obj(array(e["signatures"])[0])["key"]
		need(equal(signer, s["device"]), "act_binding_mismatch")
		need(equal(b["target"], map[string]any{"kind": "owner-dm", "id": binding["identity"]}), "act_binding_mismatch")
		a := owneracts.ArgumentInput{
			SourceRoom: str(delivery["room"]), SourceRecipient: str(delivery["recipient"]),
			AuthorityRevision: num(authority["revision"]), IdentityGeneration: num(binding["generation"]),
			BindingRevision: num(binding["revision"]), OwnerRecipient: str(s["owner_recipient"]),
		}
		need(isInt(authority["revision"]) && isInt(binding["generation"]) && isInt(binding["revision"]), "key_binding_unavailable")
		need(isString(delivery["room"]) && isString(delivery["recipient"]) && isString(binding["bound_room"]) && isString(binding["owner_recipient"]), "key_binding_unavailable")
		need(equal(delivery["recipient"], s["consumer_recipient"]), "act_binding_mismatch")
		if op == "owner-dm.bind" {
			need(binding["state"] == "unbound" && binding["bound_room"] == "" && binding["mirror"] == false, "act_binding_mismatch")
		} else {
			need(equal(binding["owner_recipient"], s["owner_recipient"]), "act_binding_mismatch")
			a.BoundRoom = str(binding["bound_room"])
			need(binding["state"] == "active" || binding["state"] == "pending" || binding["state"] == "joined", "act_binding_mismatch")
		}
		if op == "owner-dm.mirror-enable" {
			need(binding["state"] == "joined" && binding["mirror"] == false, "act_binding_mismatch")
			room := ownerSource(c.RoomAudience, "room owner service revision digest private invite_only principals")
			need(isString(room["room"]) && isString(room["owner"]) && isString(room["service"]) && isInt(room["revision"]) && isString(room["digest"]) && isBool(room["private"]) && isBool(room["invite_only"]), "key_binding_unavailable")
			principals, ok := stringsArray(room["principals"])
			need(ok, "key_binding_unavailable")
			need(equal(room["room"], binding["bound_room"]) && equal(room["owner"], s["owner_recipient"]) && room["private"] == true && room["invite_only"] == true && room["owner"] != room["service"], "act_binding_mismatch")
			need(equal(room["service"], delivery["recipient"]) && room["digest"] == record.Digest(canonical(map[string]any{"room": room["room"], "owner": room["owner"], "service": room["service"]})), "act_binding_mismatch")
			need(len(principals) == 2 && includes(principals, room["owner"]) && includes(principals, room["service"]), "act_binding_mismatch")
			a.Mirror, a.AudienceRevision, a.AudienceDigest = true, num(room["revision"]), str(room["digest"])
		}
		mappedInput := owneracts.MappingInput{Operation: op, Identity: str(binding["identity"]), Owner: str(s["owner"]), Epoch: str(s["epoch"]), Audience: str(s["aud"]), Key: str(signer), ActionID: str(b["action_id"]), Nonce: str(b["nonce"]), IssuedAt: str(b["iat"]), ExpiresAt: str(b["exp"]), Confirmed: b["confirmed"] == true, Arguments: a}
		m, err := owneracts.Map(mappedInput)
		need(err == nil, "key_binding_unavailable")
		need(bytes.Equal(arguments, m.Arguments) && bytes.Equal(deliveredText, m.Render) && bytes.Equal(canonical(b), m.Body) && e["id"] == m.ContentID, "act_binding_mismatch")
		need(bytes.Equal(must(record.SigningPreimage("operator-act/1", str(signer), "approver", b)), m.SigningPreimage), "act_binding_mismatch")
		// The common continuation consumes this private marker at its O2 slot;
		// no received field or legacy caller can select this authority handler.
		f["_ownerActContext"], f["_ownerActSelection"], f["_ownerActBinding"] = c, s, binding
		f["_ownerActRestricted"] = s["candidate_enabled"] != true || s["critical"] == true
		f["_ownerActPresence"] = s["presence_required"] == true
		return operatorTail(e, f, widen)
	})
}

func ownerSource(e Evidence, names string) map[string]any {
	need(e.available, "key_binding_unavailable")
	return exact(e.value, names, "key_binding_unavailable")
}

// The protected authority adapter supplies an exact lookup result with
// provenance, not a raw policy document or a general current-device boolean.
func ownerAuthority(e map[string]any, f facts, c OwnerActContext) {
	s, binding := obj(f["_ownerActSelection"]), obj(f["_ownerActBinding"])
	b := obj(e["body"])
	const tuple = "aud owner epoch revision policy_id previous root_catalog_id profile_catalog_id instance_fence"
	a := ownerSource(c.Authority, tuple+" device profile operation target generation admitted")
	head := ownerSource(c.ActiveHead, tuple)
	floor := ownerSource(c.RestoreFloor, tuple)
	instance := ownerSource(c.Instance, "aud owner epoch instance_fence profile_pin")
	rootCatalog := ownerSource(c.RootCatalog, "id roles")
	profiles := ownerSource(c.ProfileCatalog, "id profiles")
	for _, value := range []any{a["policy_id"], a["root_catalog_id"], a["profile_catalog_id"], rootCatalog["id"], profiles["id"]} {
		need(isString(value) && record.IsContentID(str(value)), "key_binding_unavailable")
	}
	need(a["previous"] == nil || isString(a["previous"]) && record.IsContentID(str(a["previous"])), "key_binding_unavailable")
	need(isInt(a["revision"]) && num(a["revision"]) >= 1 && num(a["revision"]) <= 9007199254740990 && isString(a["instance_fence"]) && len(str(a["instance_fence"])) >= 1 && len(str(a["instance_fence"])) <= 255, "key_binding_unavailable")
	lineage := ownerSource(c.Lineage, "aud owner epoch policies")
	for _, name := range []string{"aud", "owner", "epoch"} {
		need(equal(lineage[name], a[name]), "key_binding_unavailable")
	}
	rows, ok := lineage["policies"].([]any)
	need(ok && len(rows) >= 1, "key_binding_unavailable")
	var previous any
	seenPolicies := map[string]bool{}
	for i, row := range rows {
		p := exact(row, "revision policy_id previous", "key_binding_unavailable")
		need(isInt(p["revision"]) && num(p["revision"]) == int64(i+1) && isString(p["policy_id"]) && record.IsContentID(str(p["policy_id"])) && equal(p["previous"], previous), "key_binding_unavailable")
		need(!seenPolicies[str(p["policy_id"])], "key_binding_unavailable")
		seenPolicies[str(p["policy_id"])] = true
		previous = p["policy_id"]
		if i == len(rows)-1 {
			need(equal(p["revision"], a["revision"]) && equal(p["policy_id"], a["policy_id"]) && equal(p["previous"], a["previous"]), "key_binding_unavailable")
		}
	}
	for _, other := range []map[string]any{head, floor} {
		for name := range head {
			need(equal(a[name], other[name]), "key_binding_unavailable")
		}
	}
	for _, name := range []string{"aud", "owner", "epoch"} {
		need(equal(a[name], s[name]) && equal(instance[name], s[name]), "key_binding_unavailable")
	}
	need(equal(instance["instance_fence"], a["instance_fence"]) && equal(instance["profile_pin"], s["profile_pin"]) && equal(rootCatalog["id"], a["root_catalog_id"]) && equal(profiles["id"], a["profile_catalog_id"]), "key_binding_unavailable")
	profileEntries := obj(profiles["profiles"])
	need(profileEntries != nil, "key_binding_unavailable")
	for name, pin := range profileEntries {
		need(name != "" && len(name) <= 255 && isString(pin) && record.IsContentID(str(pin)), "key_binding_unavailable")
	}
	need(equal(profileEntries["owner-acts/1"], s["profile_pin"]), "key_binding_unavailable")
	roles := exact(rootCatalog["roles"], "service_root agent_revocation_root operator_root root commit_signing_key enrollment_publisher service_authority service_attestations", "key_binding_unavailable")
	for name, pin := range roles {
		// Available full catalog plus omitted/mismatched known role is definite
		// invalidity; a missing complete catalog was unavailable above.
		need(equal(pin, f[name]), "key_binding_invalid")
	}
	distinct(f)
	need(isBool(a["admitted"]) && isInt(a["generation"]), "key_binding_unavailable")
	need(equal(a["device"], s["device"]) && a["profile"] == "owner-acts/1" && equal(a["operation"], b["operation"]) && equal(a["target"], b["target"]) && equal(a["generation"], binding["generation"]), "key_binding_unavailable")
	need(a["admitted"] == true, "key_binding_invalid")
}
