package main

import (
	"encoding/json"
	"strings"
)

type orderFault struct {
	name, code string
	apply      func(*Vector)
}
type orderGroup struct {
	name, source    string
	bounds, earlier []orderFault
}

func orderSubject(v *Vector) int {
	if v.Mode == "grant" {
		return 2
	}
	return 0
}
func orderEnvelope(v *Vector, change func(M)) {
	if v.Mode == "grant" {
		chain := v.Input["chain"].([]any)
		e := decode(chain[0].(string))
		change(e)
		chain[0] = wire(e)
		return
	}
	edit(v, change)
}

// Alter actual materialized evidence, retaining correct root signatures for
// body faults. Header-only faults retain the original body/signature witness.
func orderEvidence(v *Vector, device, outer bool, change func(M)) {
	collection, subject, root := "attestations", orderSubject(v), 5
	if device {
		collection, subject, root = "operator_attestations", 6, 4
	}
	records := v.Fixture[collection].(M)
	e := decode(records[keys[subject].ID].(string))
	if outer {
		change(e)
		records[keys[subject].ID] = b64(fixtureCCJ(e))
	} else {
		b := e["body"].(M)
		change(b)
		records[keys[subject].ID] = evidenceWireFor(b, keys[root], "attestation/1")
	}
}

func orderSnapshot(v *Vector, root int, outer bool, change func(M)) {
	record := v.Fixture["revocations"].(M)[keys[root].ID].(M)
	e := decode(record["snapshot"].(string))
	if outer {
		change(e)
		record["snapshot"] = b64(fixtureCCJ(e))
	} else {
		b := e["body"].(M)
		change(b)
		record["snapshot"] = evidenceWireFor(b, keys[root], "revocation/1")
	}
}
func snapshotOrderBounds(root int, code string) []orderFault {
	return []orderFault{
		{"issuer-key", code, func(v *Vector) { orderSnapshot(v, root, false, func(b M) { b["issuer"] = "ed25519:x" }) }},
		{"signature-key", code, func(v *Vector) {
			orderSnapshot(v, root, true, func(e M) { e["signatures"].([]any)[0].(M)["key"] = "ed25519:x" })
		}},
		{"content-id", code, func(v *Vector) { orderSnapshot(v, root, true, func(e M) { e["id"] = "sha256:x" }) }},
	}
}
func snapshotHeaderMissing(root int, code string) orderFault {
	return orderFault{"snapshot-header-missing", code, func(v *Vector) { orderSnapshot(v, root, true, func(e M) { delete(e, "version") }) }}
}

// Claims: each combined-invalid column retains its bound failure and an
// earlier independent failure. The expected first refusal comes from the
// specified pipeline, never from the oracle. Each operand also runs alone;
// accepted source controls prevent an always-refuse implementation. Identical
// refusal codes cannot reveal internal ordering and are documented as such.
func orderVectors() {
	sources := map[string]Vector{}
	for _, v := range cases {
		sources[v.ID] = v
	}
	invalidSig := orderFault{"E6-signature", "envelope_signature_invalid", func(v *Vector) {
		orderEnvelope(v, func(e M) {
			s := e["signatures"].([]any)[0].(M)
			raw := unb64(s["sig"].(string))
			raw[5] ^= 1
			s["sig"] = b64(raw)
		})
	}}
	audience := orderFault{"E7-audience", "audience_mismatch", func(v *Vector) { v.Fixture["audience"] = "different-service" }}
	expiry := orderFault{"T2-expiry", "expired", func(v *Vector) { v.Fixture["watermark"] = "2026-01-01T00:02:00Z" }}
	room := orderFault{"E7a-room", "message_room_mismatch", func(v *Vector) { v.Fixture["delivery"].(M)["room"] = "!different:test.invalid" }}
	text := orderFault{"E7b-text", "message_text_unavailable", func(v *Vector) { delete(v.Fixture["delivery"].(M), "text") }}
	bodyMissing := orderFault{"K1-body-missing", "key_binding_unavailable", func(v *Vector) { orderEvidence(v, false, false, func(b M) { delete(b, "roles") }) }}
	headerMissing := func(device bool) orderFault {
		return orderFault{"K1-header-missing", "key_binding_unavailable", func(v *Vector) { orderEvidence(v, device, true, func(e M) { delete(e, "version") }) }}
	}
	rootSignature := func(device bool) orderFault {
		return orderFault{"K1-root-signature", "key_binding_invalid", func(v *Vector) {
			orderEvidence(v, device, true, func(e M) {
				s := e["signatures"].([]any)[0].(M)
				raw := unb64(s["sig"].(string))
				raw[5] ^= 1
				s["sig"] = b64(raw)
			})
		}}
	}
	between := []orderFault{invalidSig, audience, expiry}
	for _, field := range []string{"owner", "epoch", "target"} {
		v := copyVector(sources["O16"])
		value := any(strings.Repeat("x", 256))
		if field == "target" {
			value = M{"kind": "registration", "id": true}
		}
		v.Fixture["binding"].(M)[field] = value
		add("N-O1-unknown-"+field, "Unknown signed operation precedes an independently invalid protected "+field+" binding.", "PO1", "act_operation_unknown", v)
	}
	groups := []orderGroup{}
	g := orderGroup{name: "E7", source: "PE1", earlier: []orderFault{
		{"E3-version", "envelope_version_unsupported", func(v *Vector) { edit(v, func(e M) { e["version"] = "swarm-envelope/3" }) }},
		{"E5-id", "envelope_id_mismatch", func(v *Vector) { edit(v, func(e M) { e["id"] = "sha256:" + strings.Repeat("0", 64) }) }}, invalidSig,
	}}
	for _, x := range []struct{ name, value string }{{"empty", ""}, {"overlong", strings.Repeat("x", 256)}, {"nonprintable", " "}} {
		g.bounds = append(g.bounds, orderFault{"audience-" + x.name, "audience_mismatch", func(v *Vector) { v.Fixture["audience"] = x.value }})
	}
	groups = append(groups, g)
	g = orderGroup{name: "E7a", source: "PE1", earlier: []orderFault{invalidSig, audience}}
	for _, field := range []string{"room", "to"} {
		for _, x := range []struct{ name, value string }{{"empty", ""}, {"overlong", strings.Repeat("x", 256)}, {"nonprintable", " "}} {
			g.bounds = append(g.bounds, orderFault{field + "-" + x.name, "message_context_unavailable", func(v *Vector) { v.Fixture["delivery"].(M)[field] = x.value }})
		}
	}
	groups = append(groups, g)
	g = orderGroup{name: "T1", source: "PE1", earlier: []orderFault{audience, room, text,
		{"T1-provider", "time_unavailable", func(v *Vector) { v.Fixture["time"].(M)["trusted"] = false }},
	}, bounds: []orderFault{
		{"now-invalid", "time_unavailable", func(v *Vector) { v.Fixture["now"] = "invalid" }},
		{"authority-invalid", "time_unavailable", func(v *Vector) { v.Fixture["time"].(M)["authority_until"] = 1 }},
		{"authority-expired", "time_unavailable", func(v *Vector) { v.Fixture["time"].(M)["authority_until"] = v.Fixture["now"] }},
		{"watermark-invalid", "watermark_unavailable", func(v *Vector) { v.Fixture["watermark"] = nil }},
	}}
	groups = append(groups, g)
	g = orderGroup{name: "K1-header", source: "PE1", earlier: append(append([]orderFault{}, between...), headerMissing(false)), bounds: []orderFault{
		{"protected-root-key", "key_binding_invalid", func(v *Vector) { v.Fixture["service_root"].(M)["key"] = "ed25519:x" }},
		{"issuer-key", "key_binding_invalid", func(v *Vector) { orderEvidence(v, false, false, func(b M) { b["issuer"] = "ed25519:x" }) }},
		{"signature-key", "key_binding_invalid", func(v *Vector) {
			orderEvidence(v, false, true, func(e M) { e["signatures"].([]any)[0].(M)["key"] = "ed25519:x" })
		}},
		{"content-id", "key_binding_invalid", func(v *Vector) { orderEvidence(v, false, true, func(e M) { e["id"] = "sha256:x" }) }},
	}}
	headerBounds := g.bounds
	groups = append(groups, g)
	g = orderGroup{name: "K1-subject", source: "PE1", earlier: append(append([]orderFault{}, between...), headerMissing(false), bodyMissing, rootSignature(false)), bounds: []orderFault{
		{"key-id", "key_binding_invalid", func(v *Vector) {
			orderEvidence(v, false, false, func(b M) { b["subject"].(M)["key_id"] = "ed25519:x" })
		}},
		{"public-bytes", "key_binding_invalid", func(v *Vector) {
			orderEvidence(v, false, false, func(b M) { b["subject"].(M)["public_bytes"] = b64(make([]byte, 31)) })
		}},
	}}
	subjectBounds := g.bounds
	groups = append(groups, g)
	g = orderGroup{name: "K1-principal", source: "PE1", earlier: append(append([]orderFault{}, between...), headerMissing(false), bodyMissing, rootSignature(false))}
	for _, side := range []string{"signed", "protected"} {
		for _, field := range []string{"owner", "path", "generation", "master_epoch", "registration_number", "uid"} {
			value := any(strings.Repeat("x", 256))
			if field == "registration_number" {
				value = 0
			}
			if field == "uid" {
				value = 4294967295
			}
			g.bounds = append(g.bounds, orderFault{side + "-" + field, "key_binding_invalid", func(v *Vector) {
				if side == "signed" {
					orderEvidence(v, false, false, func(b M) { b["binding"].(M)[field] = value })
				} else {
					v.Fixture["active_generations"].(M)[keys[orderSubject(v)].ID].(M)[field] = value
				}
			}})
		}
	}
	principalBounds := g.bounds
	groups = append(groups, g)
	g = orderGroup{name: "K1-owner", source: "PE5", earlier: append(append([]orderFault{}, between...), headerMissing(true), rootSignature(true)), bounds: []orderFault{
		{"signed-owner", "key_binding_invalid", func(v *Vector) {
			orderEvidence(v, true, false, func(b M) { b["binding"].(M)["owner"] = strings.Repeat("x", 256) })
		}},
		{"protected-owner", "key_binding_invalid", func(v *Vector) { v.Fixture["operator_owner"] = strings.Repeat("x", 256) }},
	}}
	ownerBounds := g.bounds
	groups = append(groups, g)
	g = orderGroup{name: "O1", source: "PO1", earlier: []orderFault{audience, expiry,
		{"E8-journal", "id_journal_unavailable", func(v *Vector) { v.Fixture["id_journal_available"] = false }},
		{"operation-unknown", "act_operation_unknown", func(v *Vector) { resign(v, 6, func(b M) { b["operation"] = "unknown.operation" }) }},
	}}
	for _, field := range []string{"owner", "epoch", "target", "operation", "arguments", "container"} {
		g.bounds = append(g.bounds, orderFault{field, "act_binding_mismatch", func(v *Vector) {
			value := any(strings.Repeat("x", 256))
			if field == "target" {
				value = M{"kind": "registration", "id": true}
			}
			if field == "arguments" {
				value = []any{}
			}
			if field == "container" {
				v.Fixture["binding"] = []any{}
				return
			}
			v.Fixture["binding"].(M)[field] = value
		}})
	}
	groups = append(groups, g)
	groups = append(groups, orderGroup{name: "O2", source: "PO1", bounds: ownerBounds, earlier: []orderFault{
		audience, expiry,
		{"E8-journal", "id_journal_unavailable", func(v *Vector) { v.Fixture["id_journal_available"] = false }},
		{"O1-operation", "act_operation_unknown", func(v *Vector) { resign(v, 6, func(b M) { b["operation"] = "unknown.operation" }) }},
		{"O1-binding", "act_binding_mismatch", func(v *Vector) { v.Fixture["binding"].(M)["epoch"] = "different-epoch" }},
		{"O2-current", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture["signer_facts"].(M), "current") }},
		headerMissing(true), rootSignature(true),
	}})
	groups = append(groups, orderGroup{name: "G2", source: "PG1", bounds: append(append(append([]orderFault{}, headerBounds...), subjectBounds...), principalBounds...), earlier: []orderFault{
		{"G1-request-shape", "grant_chain_malformed", func(v *Vector) { v.Fixture["request"].(M)["action"] = []any{} }},
		invalidSig,
		{"G2-leaf-issuer", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture["operator_attestations"].(M), keys[6].ID) }},
	}})
	g = orderGroup{name: "G8", source: "PG1", earlier: []orderFault{
		{"G1-request-shape", "grant_chain_malformed", func(v *Vector) { v.Fixture["request"].(M)["action"] = []any{} }},
		{"G3-parent", "grant_chain_broken", func(v *Vector) { link(v, 0, 1, func(b M) { b["parent"] = "sha256:" + strings.Repeat("0", 64) }) }},
		{"G7-snapshot", "revocation_unavailable", func(v *Vector) { v.Fixture["revocations"].(M)[keys[0].ID].(M)["availability"] = "unavailable" }},
	}, bounds: []orderFault{
		{"target-surrogate", "request_target_invalid", func(v *Vector) { v.Fixture["request"].(M)["target"].(M)["id"] = json.RawMessage(`"\ud800"`) }},
		{"target-overlong", "request_target_invalid", func(v *Vector) { v.Fixture["request"].(M)["target"].(M)["id"] = strings.Repeat("x", 256) }},
	}}
	groups = append(groups, g)
	groups = append(groups, orderGroup{name: "K1-snapshot", source: "PE1", bounds: snapshotOrderBounds(7, "key_binding_invalid"), earlier: []orderFault{
		expiry,
		{"attestation-missing", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture["attestations"].(M), keys[0].ID) }},
		snapshotHeaderMissing(7, "key_binding_unavailable"),
	}})
	groups = append(groups, orderGroup{name: "O2-snapshot", source: "PO1", bounds: snapshotOrderBounds(4, "revocation_invalid"), earlier: []orderFault{
		{"O1-operation", "act_operation_unknown", func(v *Vector) { resign(v, 6, func(b M) { b["operation"] = "unknown.operation" }) }},
		rootSignature(true), snapshotHeaderMissing(4, "revocation_unavailable"),
	}})
	groups = append(groups, orderGroup{name: "G7", source: "PG1", bounds: snapshotOrderBounds(0, "revocation_invalid"), earlier: []orderFault{
		{"G6-caveat-expired", "expired", func(v *Vector) {
			link(v, 0, 1, func(b M) { b["caveats"] = M{"lang": "caveats/v1", "not_before": b["iat"], "expires": v.Fixture["now"]} })
		}},
		snapshotHeaderMissing(0, "revocation_unavailable"),
	}})
	for _, g := range groups {
		for _, early := range g.earlier {
			v := copyVector(sources[g.source])
			early.apply(&v)
			add("U-"+g.name+"-early-"+early.name, "Order control: "+early.name+" fails alone before "+g.name+" bound checks.", g.source, early.code, v)
		}
		for _, bound := range g.bounds {
			v := copyVector(sources[g.source])
			bound.apply(&v)
			add("U-"+g.name+"-bound-"+bound.name, "Order control: "+g.name+" "+bound.name+" fails alone with the earlier stages valid.", g.source, bound.code, v)
			if g.name == "E7a" {
				v := copyVector(sources[g.source])
				bound.apply(&v)
				other := "room"
				if strings.HasPrefix(bound.name, "room-") {
					other = "to"
				}
				v.Fixture["delivery"].(M)[other] = "different-context"
				add("U-E7a-context-before-compare-"+bound.name, "Required bounded delivery context precedes exact comparison even when the other field mismatches.", g.source, bound.code, v)
			}
			for _, early := range g.earlier {
				v := copyVector(sources[g.source])
				bound.apply(&v)
				early.apply(&v)
				add("U-"+g.name+"-"+early.name+"-"+bound.name, "Order matrix: "+early.name+" precedes "+g.name+" "+bound.name+" even when both independently fail.", g.source, early.code, v)
			}
		}
	}
}
