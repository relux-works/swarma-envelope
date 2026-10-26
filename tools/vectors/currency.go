package main

import (
	"fmt"
	"strings"
)

// These projections specify fixture expectations independently of library code.
// Negative cases preserve real signatures unless signature failure is the claim.
func currencyProfile2(v Vector) bool {
	value := v.Fixture["registry_currency_version"]
	return value != nil && freshnessInteger(value) == 2
}
func currencySet(v Vector) []any {
	return decode(v.Input["checkpoint"].(string))["body"].(M)["snapshots"].([]any)
}
func currencyState(v Vector) M { return v.Fixture["snapshot_journal"].(M)["anchor"].(M) }
func currencyEntry(root string, seq int, prev any, op, kind, id string) M {
	b := M{"type": "journal-entry/1", "registry": root, "owner": "owner-a", "seq": seq, "prev": prev, "at": "2026-01-01T00:00:59Z", "op": op, "record_type": kind, "record": id}
	return M{"version": "swarm-envelope/2", "body": b, "id": digest(append([]byte(domain("journal-entry/1")+"\n"), canonical(b)...))}
}
func currencyBase2() Vector {
	v := reviewSource("PE1")
	v.Mode = "freshness"
	v.Fixture["registry_currency_version"] = 2
	v.Fixture["registry_owner"] = "owner-a"
	v.Fixture["witness_read_at"] = v.Fixture["now"]
	set, latest, entries := []any{}, []any{}, []any{}
	var prev any
	for i, role := range []string{"grant", "operator", "registry-owner"} {
		k := keys[[]int{0, 4, 7}[i]]
		raw := evidenceWire(M{"type": "revocation/1", "issuer": k.ID, "issued_at": "2025-12-31T23:00:00Z", "complete": true, "entries": []any{}}, k)
		id := decode(raw)["id"]
		v.Fixture["revocations"].(M)[k.ID] = M{"availability": "available", "max_age": 60, "rollback_safe": true, "snapshot": raw}
		v.Fixture["seen"].(M)[id.(string)] = raw
		set = append(set, M{"root_role": role, "root_key_id": k.ID, "snapshot_id": id})
		latest = append(latest, M{"root_role": role, "root_key_id": k.ID, "snapshot_id": nil, "record_seq": 0})
		e := currencyEntry(keys[7].ID, i+1, prev, "add", "revocation/1", id.(string))
		entries = append(entries, wire(e))
		prev = e["id"]
	}
	cp := envelope(M{"type": "checkpoint/2", "registry": keys[7].ID, "owner": "owner-a", "seq": 3, "head": prev, "at": "2026-01-01T00:00:59Z", "snapshots": set}, keys[7], "author")
	tip := envelope(M{"type": "freshness/2", "registry": keys[7].ID, "owner": "owner-a", "publication_seq": 1, "prev": nil, "issued_at": v.Fixture["now"], "snapshots": set, "registry_seq": 3, "checkpoint_id": cp["id"]}, keys[7], "author")
	v.Input = M{"chain": []any{wire(tip)}, "checkpoint": wire(cp), "ids": []any{}, "keys": []any{}}
	v.Fixture["snapshot_journal"] = M{"anchor": M{"version": 2, "registry_id": keys[7].ID, "owner": "owner-a", "registry_seq": 0, "registry_head": nil, "checkpoint_id": nil, "latest": latest}, "entries": entries}
	v.Fixture["journal_witness"] = M{"registry_id": keys[7].ID, "owner": "owner-a", "registry_seq": 3, "registry_head": prev, "checkpoint_id": cp["id"], "previous_checkpoint_id": nil}
	v.Fixture["freshness_anchor"] = M{"registry_id": keys[7].ID, "owner": "owner-a", "publication_seq": 0, "freshness_id": nil, "issued_at": nil, "snapshots": set, "registry_seq": 3, "checkpoint_id": cp["id"]}
	return v
}
func currencyRefresh(v *Vector, edit func(M)) {
	cp := decode(v.Input["checkpoint"].(string))
	b := cp["body"].(M)
	edit(b)
	cp = envelope(b, keys[7], "author")
	v.Input["checkpoint"] = wire(cp)
	w := v.Fixture["journal_witness"].(M)
	w["registry_seq"], w["registry_head"], w["checkpoint_id"] = b["seq"], b["head"], cp["id"]
	tip := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
	tip["registry_seq"], tip["checkpoint_id"], tip["snapshots"] = b["seq"], cp["id"], b["snapshots"]
	v.Input["chain"] = []any{wire(envelope(tip, keys[7], "author"))}
	a := v.Fixture["freshness_anchor"].(M)
	if freshnessInteger(a["publication_seq"]) == 0 {
		a["registry_seq"], a["checkpoint_id"], a["snapshots"] = b["seq"], cp["id"], b["snapshots"]
	}
}
func currencyTip(v *Vector, edit func(M)) {
	b := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
	edit(b)
	v.Input["chain"] = []any{wire(envelope(b, keys[7], "author"))}
}
func currencyAppend(v *Vector, op, kind, raw string) {
	cp := decode(v.Input["checkpoint"].(string))["body"].(M)
	id := decode(raw)["id"].(string)
	v.Fixture["seen"].(M)[id] = raw
	e := currencyEntry(keys[7].ID, int(freshnessInteger(cp["seq"]))+1, cp["head"], op, kind, id)
	proof := v.Fixture["snapshot_journal"].(M)
	proof["entries"] = append(proof["entries"].([]any), wire(e))
	currencyRefresh(v, func(b M) { b["seq"], b["head"] = e["body"].(M)["seq"], e["id"] })
}
func currencyNewGrant(v *Vector, selectNew bool) string {
	raw := evidenceWire(M{"type": "revocation/1", "issuer": keys[0].ID, "issued_at": "2026-01-01T00:00:10Z", "complete": true, "entries": []any{M{"kind": "key", "id": keys[2].ID, "from": "2026-01-01T00:01:10Z"}}}, keys[0])
	currencyAppend(v, "add", "revocation/1", raw)
	if selectNew {
		v.Fixture["revocations"].(M)[keys[0].ID].(M)["snapshot"] = raw
		currencyRefresh(v, func(b M) { b["snapshots"].([]any)[0].(M)["snapshot_id"] = decode(raw)["id"] })
	}
	return raw
}
func currencyDerived(v Vector) M {
	a := decode(wire(currencyState(v)))
	rows := a["latest"].([]any)
	for _, value := range currencyProofEntries(v) {
		e := decode(value.(string))
		b := e["body"].(M)
		if freshnessInteger(b["seq"]) <= freshnessInteger(a["registry_seq"]) {
			continue
		}
		if b["op"] != "add" || b["record_type"] != "revocation/1" {
			continue
		}
		raw := v.Fixture["seen"].(M)[b["record"].(string)].(string)
		issuer := decode(raw)["body"].(M)["issuer"]
		for _, value := range rows {
			r := value.(M)
			if r["root_key_id"] == issuer && r["snapshot_id"] != b["record"] {
				r["snapshot_id"], r["record_seq"] = b["record"], b["seq"]
			}
		}
	}
	cp := decode(v.Input["checkpoint"].(string))
	b := cp["body"].(M)
	a["registry_seq"], a["registry_head"], a["checkpoint_id"] = b["seq"], b["head"], cp["id"]
	return a
}
func currencyExpected(v Vector, p M) M {
	ids := []any{}
	seen := map[string]bool{}
	addID := func(value any) {
		if value == nil {
			return
		}
		id := value.(string)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, id := range p["ids"].([]any) {
		addID(id)
	}
	if v.Mode != "journal" {
		for _, row := range currencySet(v) {
			addID(row.(M)["snapshot_id"])
		}
	}
	a := currencyState(v)
	addID(a["checkpoint_id"])
	for _, row := range a["latest"].([]any) {
		addID(row.(M)["snapshot_id"])
	}
	for _, value := range currencyProofEntries(v) {
		e := decode(value.(string))
		addID(e["id"])
		b := e["body"].(M)
		if b["op"] == "add" && b["record_type"] == "revocation/1" {
			addID(b["record"])
		}
	}
	p["ids"], p["snapshot_journal"] = ids, currencyDerived(v)
	if v.Mode == "freshness-reanchor" {
		r := p["reanchor"].(M)
		old := v.Fixture["freshness_anchor"].(M)
		version := 2
		oldset := old["snapshots"]
		if _, ok := old["snapshot"]; ok {
			version = 1
			oldset = []any{M{"root_role": "registry-owner", "root_key_id": keys[7].ID, "snapshot_id": old["snapshot"]}}
		}
		r["old_snapshots"], r["new_snapshots"], r["old_registry_currency_version"], r["new_registry_currency_version"] = oldset, currencySet(v), version, 2
	}
	return p
}
func currencyRetain(v *Vector) {
	cp := decode(v.Input["checkpoint"].(string))
	v.Fixture["seen"].(M)[cp["id"].(string)] = wire(cp)
	state := currencyDerived(*v)
	proof := v.Fixture["snapshot_journal"].(M)
	proof["anchor"] = state
	proof["entries"] = []any{}
	tip := decode(v.Input["chain"].([]any)[0].(string))
	b := tip["body"].(M)
	v.Fixture["freshness_anchor"] = M{"registry_id": keys[7].ID, "owner": "owner-a", "publication_seq": b["publication_seq"], "freshness_id": tip["id"], "issued_at": b["issued_at"], "snapshots": b["snapshots"], "registry_seq": b["registry_seq"], "checkpoint_id": cp["id"]}
}
func currencyReceipt(v Vector, mode string, in M) Vector {
	v.Mode = "receipt"
	v.Input = M{"mint": M{"mode": "freshness", "input": v.Input}, "consume": M{"mode": mode, "input": in}, "use": M{}, "attach": true, "require": true, "margin": 0, "renew_evidence": false}
	return v
}
func currencyVectors() {

	add("P-CU-genesis", "All configured rows are qualified by the complete journal prefix, including genesis null head/checkpoint.", "", "accept", currencyBase2())
	for _, tc := range []struct {
		name, code string
		edit       func(*Vector)
	}{
		{"role", "freshness_malformed", func(v *Vector) {
			currencyRefresh(v, func(b M) { b["snapshots"].([]any)[0].(M)["root_role"] = "outside" })
		}},
		{"duplicate", "freshness_malformed", func(v *Vector) {
			currencyRefresh(v, func(b M) { a := b["snapshots"].([]any); b["snapshots"] = []any{a[0], a[0], a[2]} })
		}},
		{"unsorted", "freshness_malformed", func(v *Vector) {
			currencyRefresh(v, func(b M) { a := b["snapshots"].([]any); b["snapshots"] = []any{a[1], a[0], a[2]} })
		}},
		{"no-registry", "freshness_malformed", func(v *Vector) { currencyRefresh(v, func(b M) { b["snapshots"] = b["snapshots"].([]any)[:2] }) }},
		{"wrong-pin", "freshness_invalid", func(v *Vector) {
			currencyRefresh(v, func(b M) { b["snapshots"].([]any)[0].(M)["root_key_id"] = keys[1].ID })
		}},
		{"element-mismatch", "freshness_binding_mismatch", func(v *Vector) {
			currencyTip(v, func(b M) { b["snapshots"].([]any)[0].(M)["snapshot_id"] = digest([]byte("other grant snapshot")) })
		}},
		{"nonlatest", "freshness_binding_mismatch", func(v *Vector) { currencyNewGrant(v, false) }},
		{"regressing-readd", "freshness_state_invalid", func(v *Vector) {
			old := v.Fixture["revocations"].(M)[keys[0].ID].(M)["snapshot"].(string)
			currencyNewGrant(v, false)
			currencyAppend(v, "add", "revocation/1", old)
		}},
		{"missing-original", "freshness_unavailable", func(v *Vector) {
			id := currencySet(*v)[0].(M)["snapshot_id"].(string)
			delete(v.Fixture["seen"].(M), id)
		}},
		{"missing-middle", "freshness_state_invalid", func(v *Vector) {
			p := v.Fixture["snapshot_journal"].(M)
			a := p["entries"].([]any)
			p["entries"] = []any{a[0], a[2]}
		}},
		{"incomplete-index", "freshness_state_invalid", func(v *Vector) { a := currencyState(*v); a["latest"] = a["latest"].([]any)[1:] }},
		{"invalid-version", "freshness_invalid", func(v *Vector) { v.Fixture["registry_currency_version"] = 3 }},
		{"default-version", "registry_currency_version_mismatch", func(v *Vector) { v.Fixture["registry_currency_version"] = 0 }},
		{"legacy-version", "registry_currency_version_mismatch", func(v *Vector) { v.Fixture["registry_currency_version"] = 1 }},
		{"missing-index", "freshness_unavailable", func(v *Vector) { delete(v.Fixture, "snapshot_journal") }},
		{"stale-witness", "freshness_unavailable", func(v *Vector) { v.Fixture["witness_read_at"] = "2025-12-31T23:00:00Z" }},
	} {
		v := currencyBase2()
		tc.edit(&v)
		add("N-CU-"+tc.name, "The /2 contract rejects "+tc.name+" before authority and returns a zero plan.", "P-CU-genesis", tc.code, v)
	}
	for _, tc := range []struct {
		name string
		keep []int
	}{{"registry", []int{2}}, {"grant", []int{0, 2}}, {"operator", []int{1, 2}}} {
		v := currencyBase2()
		currencyRefresh(&v, func(b M) {
			a := b["snapshots"].([]any)
			s := []any{}
			for _, i := range tc.keep {
				s = append(s, a[i])
			}
			b["snapshots"] = s
		})
		add("P-CU-"+tc.name, "Optional coverage retains all configured index rows.", "", "accept", v)
	}
	v := currencyBase2()
	raw := v.Fixture["revocations"].(M)[keys[0].ID].(M)["snapshot"].(string)
	currencyAppend(&v, "add", "revocation/1", raw)
	add("P-CU-duplicate-current", "Re-adding current content keeps its original record_seq.", "", "accept", v)
	v = currencyBase2()
	currencyAppend(&v, "revoke", "revocation/1", raw)
	add("P-CU-revoke", "A revoke journal operation cannot reveal an earlier latest row.", "", "accept", v)
	v = currencyBase2()
	currencyNewGrant(&v, true)
	add("P-CU-latest", "A newer cumulative grant snapshot is selected from the exact witnessed prefix.", "", "accept", v)
	// Positive-head proof limits count the anchor: 63 new entries fit, 64 do not.
	for _, n := range []int{63, 64} {
		v := currencyBase2()
		entries := v.Fixture["snapshot_journal"].(M)["entries"].([]any)
		last := entries[len(entries)-1]
		currencyRetain(&v)
		v.Fixture["snapshot_journal"].(M)["entries"] = []any{last}
		for i := 0; i < n; i++ {
			cp := decode(v.Input["checkpoint"].(string))["body"].(M)
			e := currencyEntry(keys[7].ID, int(freshnessInteger(cp["seq"]))+1, cp["head"], "add", "attestation/1", digest([]byte(fmt.Sprint(i))))
			v.Fixture["snapshot_journal"].(M)["entries"] = append(v.Fixture["snapshot_journal"].(M)["entries"].([]any), wire(e))
			currencyRefresh(&v, func(b M) { b["seq"], b["head"] = e["body"].(M)["seq"], e["id"] })
		}
		currencyTip(&v, func(b M) { b["publication_seq"], b["prev"], b["issued_at"] = 2, nil, "2026-01-01T00:01:01Z" })
		v.Fixture["now"], v.Fixture["watermark"], v.Fixture["witness_read_at"] = "2026-01-01T00:01:01Z", "2026-01-01T00:01:01Z", "2026-01-01T00:01:01Z"
		if n == 63 {
			add("P-CU-63-new", "Anchor plus63 new journal entries fits the64-envelope proof.", "", "accept", v)
		} else {
			add("N-CU-64-new", "Anchor plus64 new entries exceeds the64-envelope proof.", "P-CU-63-new", "freshness_state_invalid", v)
		}
	}
	v = currencyBase2()
	currencyRetain(&v)
	add("P-CU-same-head-empty", "Empty proof requires an already-qualified complete index at this exact head.", "", "accept", v)
	// Received /1 cannot become current currency after the protected /2 pin.
	v = freshnessBase()
	v.Fixture["registry_currency_version"] = 2
	add("N-CU-downgrade", "Pinned /2 refuses a current /1 candidate.", "P-CU-genesis", "registry_currency_version_mismatch", v)
	// Every adopted consumer root is tested with required/optional coverage.
	for _, tc := range []struct {
		name, source, mode string
		in                 func(Vector) M
	}{
		{"agent", "PE1", "attestation", func(v Vector) M { b := body(v); return M{"key": b["author"], "reference": b["author_attestation"]} }},
		{"device", "PO1", "device", func(v Vector) M { return M{"key": keys[6].ID, "reference": ""} }},
		{"operator", "PO1", "operator", func(v Vector) M { return v.Input }},
		{"service", "P-SVC-chain", "service", func(v Vector) M { return M{"key": keys[3].ID} }},
		{"message", "PE1", "message", func(v Vector) M { return v.Input }},
		{"grant", "PG1", "grant", func(v Vector) M { return v.Input }},
	} {
		original := reviewSource(tc.source)
		v := currencyBase2()
		for _, name := range []string{"audience", "known_keys", "required_roles", "delivery", "binding", "request", "service_authority", "service_attestations", "attestations", "agent_attestation_ids", "operator_attestations", "active_generations", "signer_facts"} {
			if x, ok := original.Fixture[name]; ok {
				v.Fixture[name] = x
			} else {
				delete(v.Fixture, name)
			}
		}
		if tc.name == "service" {
			delete(v.Fixture, "enrollment_publisher")
		}
		v = currencyReceipt(v, tc.mode, tc.in(original))
		add("P-CU-receipt-"+tc.name, "Exact root coverage waives only its own-age on "+tc.name+".", "", "accept", v)
		for _, optional := range []bool{false, true} {
			v := currencyBase2()
			for _, name := range []string{"audience", "known_keys", "required_roles", "delivery", "binding", "request", "service_authority", "service_attestations", "attestations", "agent_attestation_ids", "operator_attestations", "active_generations", "signer_facts"} {
				if x, ok := original.Fixture[name]; ok {
					v.Fixture[name] = x
				} else {
					delete(v.Fixture, name)
				}
			}
			if tc.name == "service" {
				delete(v.Fixture, "enrollment_publisher")
			}
			missing := "grant"
			if tc.name == "device" || tc.name == "operator" {
				missing = "operator"
			}
			if tc.name == "agent" || tc.name == "message" {
				continue
			}
			currencyRefresh(&v, func(b M) {
				out := []any{}
				for _, x := range b["snapshots"].([]any) {
					if x.(M)["root_role"] != missing {
						out = append(out, x)
					}
				}
				b["snapshots"] = out
			})
			v = currencyReceipt(v, tc.mode, tc.in(original))
			v.Input["require"] = !optional
			code := "freshness_receipt_unavailable"
			suffix := "required"
			if optional {
				code = "key_binding_unavailable"
				if tc.name == "operator" || tc.name == "grant" {
					code = "revocation_unavailable"
				}
				suffix = "optional"
			}
			add("N-CU-coverage-"+tc.name+"-"+suffix, "Missing checked-root coverage does not waive age or retry without a supplied receipt.", "P-CU-receipt-"+tc.name, code, v)
		}
	}
	for _, role := range []string{"grant", "operator", "registry-owner"} {
		v := currencyBase2()
		root := keys[map[string]int{"grant": 0, "operator": 4, "registry-owner": 7}[role]].ID
		v = currencyReceipt(v, "revocation", M{"root": root, "ids": []any{}, "keys": []any{}})
		add("P-CU-check-"+role, "Explicit CheckRevocation uses only the covered root.", "", "accept", v)
	}
	for _, tc := range []struct {
		name, code string
		edit       func(*Vector)
	}{
		{"rebuilt-snapshots", "freshness_receipt_binding_mismatch", func(v *Vector) { v.Input["renew_evidence"] = true }},
		{"rebuilt-journal", "freshness_receipt_binding_mismatch", func(v *Vector) { v.Input["renew_journal_evidence"] = true }},
		{"expired", "freshness_receipt_expired", func(v *Vector) {
			v.Input["use"].(M)["now"] = "2026-01-01T00:02:00Z"
			v.Input["use"].(M)["watermark"] = "2026-01-01T00:02:00Z"
		}},
		{"later-read", "freshness_receipt_expired", func(v *Vector) {
			for _, n := range []string{"now", "watermark", "witness_read_at"} {
				v.Input["use"].(M)[n] = "2026-01-01T00:02:00Z"
			}
		}},
		{"minimum-age", "freshness_receipt_expired", func(v *Vector) {
			v.Fixture["revocations"].(M)[keys[0].ID].(M)["max_age"] = 10
			v.Input["use"].(M)["now"] = "2026-01-01T00:01:10Z"
			v.Input["use"].(M)["watermark"] = "2026-01-01T00:01:10Z"
		}},
		{"changed-pin", "freshness_receipt_binding_mismatch", func(v *Vector) { v.Input["use"].(M)["root"] = keys[1].ID }},
	} {
		v := currencyReceipt(currencyBase2(), "revocation", M{"root": keys[7].ID, "ids": []any{}, "keys": []any{}})
		tc.edit(&v)
		add("N-CU-receipt-"+tc.name, "Receipt premise/lifetime refuses "+tc.name+" without partial plans.", "P-CU-check-registry-owner", tc.code, v)
	}
	currencyExtendedVectors()
	currencyDeepVectors()
	currencyBoundaryVectors()
	currencyRefusalVectors()
	currencyBoundVectors()
}

func currencyUpgrade() Vector {
	v := currencyBase2()
	entries := v.Fixture["snapshot_journal"].(M)["entries"].([]any)
	last := entries[len(entries)-1]
	currencyRetain(&v)
	oldcp := decode(v.Input["checkpoint"].(string))["body"].(M)
	oldcp["type"] = "checkpoint/1"
	oldcp["snapshot"] = oldcp["snapshots"].([]any)[2].(M)["snapshot_id"]
	delete(oldcp, "snapshots")
	prior := envelope(oldcp, keys[7], "author")
	v.Fixture["seen"].(M)[prior["id"].(string)] = wire(prior)
	a := currencyState(v)
	a["checkpoint_id"] = prior["id"]
	v.Fixture["snapshot_journal"].(M)["entries"] = []any{last}
	old := envelope(M{"type": "freshness/1", "registry": keys[7].ID, "owner": "owner-a", "publication_seq": 7, "prev": nil, "issued_at": "2026-01-01T00:00:59Z", "snapshot": oldcp["snapshot"], "registry_seq": 3, "checkpoint_id": prior["id"]}, keys[7], "author")
	v.Fixture["freshness_anchor"] = freshnessFact(old)
	v.Fixture["seen"].(M)[old["id"].(string)] = wire(old)
	currencyNewGrant(&v, true)
	currencyTip(&v, func(b M) { b["publication_seq"] = 8; b["prev"] = nil })
	v.Fixture["journal_witness"].(M)["previous_checkpoint_id"] = prior["id"]
	return v
}
func currencyExtendedVectors() {
	v := currencyUpgrade()
	add("P-CU-upgrade", "Explicit /2 pin preserves the exact archival /1 predecessor and fully qualified historical domain rows.", "", "accept", v)
	for _, tc := range []struct {
		name, code string
		edit       func(*Vector)
	}{
		{"upgrade-incomplete", "freshness_state_invalid", func(v *Vector) { a := currencyState(*v); a["latest"] = a["latest"].([]any)[1:] }},
		{"upgrade-prior-missing", "freshness_unavailable", func(v *Vector) { delete(v.Fixture["seen"].(M), currencyState(*v)["checkpoint_id"].(string)) }},
		{"upgrade-prior-corrupt", "freshness_state_invalid", func(v *Vector) {
			v.Fixture["seen"].(M)[currencyState(*v)["checkpoint_id"].(string)] = b64([]byte("bad retained checkpoint"))
		}},
		{"upgrade-gap", "freshness_gap", func(v *Vector) { currencyTip(v, func(b M) { b["publication_seq"] = 10 }) }},
	} {
		v := currencyUpgrade()
		tc.edit(&v)
		add("N-CU-"+tc.name, "An upgrade cannot bypass retained provenance or qualified complete-prefix state.", "P-CU-upgrade", tc.code, v)
	}
	v = currencyUpgrade()
	v.Mode = "freshness-reanchor"
	currencyTip(&v, func(b M) { b["publication_seq"] = 10 })
	add("P-CU-upgrade-reanchor", "Explicit recovery skips legacy publication positions while deriving every journal position.", "", "accept", v)
	v = currencyBase2()
	currencyRetain(&v)
	v.Mode = "freshness-reanchor"
	currencyTip(&v, func(b M) { b["publication_seq"], b["issued_at"], b["prev"] = 3, "2026-01-01T00:01:01Z", nil })
	v.Fixture["now"], v.Fixture["watermark"], v.Fixture["witness_read_at"] = "2026-01-01T00:01:01Z", "2026-01-01T00:01:01Z", "2026-01-01T00:01:01Z"
	add("P-CU-reanchor-same", "Same-head recovery preserves the complete set and exact checkpoint.", "", "accept", v)
	v = currencyUpgrade()
	v.Mode = "freshness-reanchor"
	currencyTip(&v, func(b M) { b["publication_seq"] = 10 })
	rc := currencyReceipt(v, "revocation", M{"root": keys[0].ID, "ids": []any{}, "keys": []any{}})
	rc.Input["mint"].(M)["mode"] = "freshness-reanchor"
	add("P-CU-reanchor-receipt", "A receipt after recovery binds the newly selected grant snapshot.", "", "accept", rc)
	rc = copyVector(rc)
	rc.Input["use"].(M)["now"], rc.Input["use"].(M)["watermark"] = "2026-01-01T00:01:10Z", "2026-01-01T00:01:10Z"
	rc.Input["consume"].(M)["input"].(M)["keys"] = []any{keys[2].ID}
	add("N-CU-effective-during-receipt", "A future-effective grant revocation takes effect during a still-current receipt.", "P-CU-reanchor-receipt", "revoked", rc)
	// A journal admission uses the retained old witness and the same complete index.
	v = currencyUpgrade()
	proof := v.Fixture["snapshot_journal"].(M)
	a := proof["anchor"].(M)
	v.Mode = "journal"
	v.Input = M{"entries": proof["entries"], "checkpoint": v.Input["checkpoint"]}
	v.Fixture["journal_witness"] = M{"registry_id": keys[7].ID, "owner": "owner-a", "registry_seq": a["registry_seq"], "registry_head": a["registry_head"], "checkpoint_id": a["checkpoint_id"], "previous_checkpoint_id": nil}
	add("P-CU-journal-upgrade", "Ordinary journal verification accepts old content but a current /2 checkpoint and exact /1 predecessor.", "", "accept", v)
	stale := copyVector(v)
	stale.Fixture["now"], stale.Fixture["watermark"] = "2026-01-01T00:03:00Z", "2026-01-01T00:03:00Z"
	add("N-CU-journal-stale", "Stale intermediate checkpoints cannot serve as a historical catch-up API.", "P-CU-journal-upgrade", "journal_unavailable", stale)
	v = currencyBase2()
	currencyRetain(&v)
	v.Mode = "journal"
	v.Input = M{"entries": []any{}, "checkpoint": v.Input["checkpoint"]}
	add("P-CU-journal-same", "An already-qualified same-head index permits an empty journal suffix.", "", "accept", v)
	for _, pin := range []int{0, 1} {
		v := freshnessBase()
		v.Fixture["registry_currency_version"] = pin
		add(fmt.Sprintf("P-CU-version%d", pin), "Legacy explicit/default version keeps the /1 contract.", "", "accept", v)
	}
	v = currencyBase2()
	delete(v.Fixture, "registry_currency_version")
	add("N-CU-absent-pin", "An absent version retains legacy mode and cannot admit a /2 candidate.", "P-CU-genesis", "registry_currency_version_mismatch", v)
	for _, tc := range []struct {
		name, code string
		edit       func(*Vector)
	}{
		{"empty-list", "freshness_malformed", func(v *Vector) { currencyRefresh(v, func(b M) { b["snapshots"] = []any{} }) }},
		{"extra-member", "freshness_malformed", func(v *Vector) { currencyRefresh(v, func(b M) { b["snapshots"].([]any)[0].(M)["extra"] = true }) }},
		{"duplicate-key", "freshness_malformed", func(v *Vector) {
			currencyRefresh(v, func(b M) { b["snapshots"].([]any)[0].(M)["root_key_id"] = keys[4].ID })
		}},
		{"aggregate-capacity", "freshness_malformed", func(v *Vector) {
			// Individually bounded Evidence values can still exceed the whole-call cap.
			for _, name := range []string{"seen", "revocations"} {
				m := v.Fixture[name].(M)
				for i := 0; i < 110; i++ {
					m[fmt.Sprintf("capacity-%d", i)] = strings.Repeat("x", 8100)
				}
			}
			p := v.Fixture["snapshot_journal"].(M)
			p["padding"] = strings.Repeat("x", 600000)
		}},
	} {
		v := currencyBase2()
		tc.edit(&v)
		add("N-CU-"+tc.name, "The whole /2 proof refuses "+tc.name+" without advancing state.", "P-CU-genesis", tc.code, v)
	}
	// Optional coverage has a valid own-age neighbor in the SAME invocation.
	for _, role := range []string{"grant", "operator"} {
		v := currencyBase2()
		k := keys[map[string]int{"grant": 0, "operator": 4}[role]]
		currencyRefresh(&v, func(b M) {
			out := []any{}
			for _, x := range b["snapshots"].([]any) {
				if x.(M)["root_role"] != role {
					out = append(out, x)
				}
			}
			b["snapshots"] = out
		})
		v.Fixture["revocations"].(M)[k.ID].(M)["snapshot"] = evidenceWire(M{"type": "revocation/1", "issuer": k.ID, "issued_at": v.Fixture["now"], "complete": true, "entries": []any{}}, k)
		v = currencyReceipt(v, "revocation", M{"root": k.ID, "ids": []any{}, "keys": []any{}})
		v.Input["require"] = false
		add("P-CU-optional-current-"+role, "An optional receipt missing the root leaves its valid own-age check active.", "", "accept", v)
		req := copyVector(v)
		req.Input["require"] = true
		add("N-CU-required-current-"+role, "Required root coverage refuses even when own-age would pass.", "P-CU-optional-current-"+role, "freshness_receipt_unavailable", req)
		invalid := copyVector(v)
		invalid.Input["margin"] = 61
		add("N-CU-optional-invalid-"+role, "An invalid optional receipt never retries without receipt authority.", "P-CU-optional-current-"+role, "freshness_receipt_invalid", invalid)
	}
}

func currencyProofEntries(v Vector) []any {
	if v.Mode == "journal" {
		return v.Input["entries"].([]any)
	}
	return v.Fixture["snapshot_journal"].(M)["entries"].([]any)
}
func currencyDeepVectors() {
	for _, name := range []string{"clearing", "postponed", "equal-time", "earlier-effective"} {
		v := currencyBase2()
		currencyNewGrant(&v, true)
		entries := []any{M{"kind": "key", "id": keys[2].ID, "from": "2026-01-01T00:01:10Z"}}
		at := "2026-01-01T00:00:20Z"
		if name == "clearing" {
			entries = []any{}
		}
		if name == "postponed" {
			entries[0].(M)["from"] = "2026-01-01T00:01:20Z"
		}
		if name == "equal-time" {
			at = "2026-01-01T00:00:10Z"
			entries[0].(M)["from"] = "2026-01-01T00:01:00Z"
		}
		if name == "earlier-effective" {
			entries[0].(M)["from"] = "2026-01-01T00:01:00Z"
		}
		raw := evidenceWire(M{"type": "revocation/1", "issuer": keys[0].ID, "issued_at": at, "complete": true, "entries": entries}, keys[0])
		currencyAppend(&v, "add", "revocation/1", raw)
		v.Fixture["revocations"].(M)[keys[0].ID].(M)["snapshot"] = raw
		currencyRefresh(&v, func(b M) { b["snapshots"].([]any)[0].(M)["snapshot_id"] = decode(raw)["id"] })
		if name == "earlier-effective" {
			add("P-CU-cumulative-earlier", "A later issuance may strengthen an existing effective time.", "", "accept", v)
		} else {
			add("N-CU-cumulative-"+name, "A journal update cannot clear/postpone or conflict with prior cumulative content.", "P-CU-latest", "freshness_state_invalid", v)
		}
	}
	v := currencyBase2()
	currencyRefresh(&v, func(b M) { b["snapshots"] = b["snapshots"].([]any)[2:] })
	a := currencyState(v)
	a["latest"] = a["latest"].([]any)[2:]
	delete(v.Fixture, "root")
	delete(v.Fixture, "operator_root")
	add("P-CU-registry-only-pins", "Unused optional roots need not be configured; future pin changes require prefix requalification.", "", "accept", v)
	for _, name := range []string{"before-expiry", "later-read", "omitted-minimum", "changed-bytes", "changed-index", "proof-presence", "proof-malformed"} {
		v := currencyBase2()
		if name == "omitted-minimum" {
			currencyRefresh(&v, func(b M) { b["snapshots"] = b["snapshots"].([]any)[2:] })
			v.Fixture["revocations"].(M)[keys[0].ID].(M)["max_age"] = 1
		}
		v = currencyReceipt(v, "revocation", M{"root": keys[7].ID, "ids": []any{}, "keys": []any{}})
		use := v.Input["use"].(M)
		code, pair := "accept", ""
		switch name {
		case "before-expiry":
			use["now"], use["watermark"] = "2026-01-01T00:01:59Z", "2026-01-01T00:01:59Z"
		case "later-read":
			for _, k := range []string{"now", "watermark", "witness_read_at"} {
				use[k] = "2026-01-01T00:01:05Z"
			}
		case "omitted-minimum":
			use["now"], use["watermark"] = "2026-01-01T00:01:20Z", "2026-01-01T00:01:20Z"
		case "changed-bytes":
			rows := decode(wire(v.Fixture["revocations"].(M)))
			row := rows[keys[7].ID].(M)
			row["snapshot"] = b64(append(unb64(row["snapshot"].(string)), ' '))
			use["revocations"] = rows
			code = "freshness_receipt_binding_mismatch"
		case "changed-index":
			p := decode(wire(v.Fixture["snapshot_journal"].(M)))
			p["anchor"].(M)["owner"] = "owner-b"
			use["snapshot_journal"] = p
			code = "freshness_receipt_binding_mismatch"
		case "proof-presence":
			p := decode(wire(v.Fixture["snapshot_journal"].(M)))
			delete(p["anchor"].(M), "registry_seq")
			use["snapshot_journal"], use["witness_read_at"] = p, true
			code = "freshness_receipt_unavailable"
		case "proof-malformed":
			p := decode(wire(v.Fixture["snapshot_journal"].(M)))
			p["anchor"].(M)["registry_seq"] = true
			use["snapshot_journal"] = p
			code = "freshness_receipt_invalid"
		}
		id := "P-CU-" + name
		if code != "accept" {
			id = "N-CU-" + name
			pair = "P-CU-check-registry-owner"
		}
		add(id, "Receipt use preserves fixed lifetime, exact immutable premises and ordered missing-first validation.", pair, code, v)
	}
}

// Neighboring recovery and argument-source controls pin the index boundary.
func currencyBoundaryVectors() {
	v := currencyUpgrade()
	currencyTip(&v, func(b M) { b["snapshots"].([]any)[0].(M)["snapshot_id"] = digest([]byte("other grant snapshot")) })
	add("N-CU-element-advanced", "An advancing head still requires every tip/checkpoint list element to match.", "P-CU-upgrade", "freshness_binding_mismatch", v)
	v = currencyBase2()
	currencyRetain(&v)
	currencyTip(&v, func(b M) {
		b["publication_seq"], b["issued_at"], b["prev"] = 2, "2026-01-01T00:01:01Z", v.Fixture["freshness_anchor"].(M)["freshness_id"]
		b["snapshots"] = b["snapshots"].([]any)[2:]
	})
	v.Fixture["now"], v.Fixture["watermark"], v.Fixture["witness_read_at"] = "2026-01-01T00:01:01Z", "2026-01-01T00:01:01Z", "2026-01-01T00:01:01Z"
	add("N-CU-same-head-set", "A publication cannot independently change checkpoint coverage.", "P-CU-same-head-empty", "freshness_binding_mismatch", v)
	v = reviewSource("P-CU-reanchor-same")
	v.Input["chain"] = []any{v.Input["chain"].([]any)[0]}
	v.Fixture["freshness_anchor"].(M)["snapshots"] = v.Fixture["freshness_anchor"].(M)["snapshots"].([]any)[2:]
	add("N-CU-reanchor-set", "Same-head recovery cannot change retained coverage.", "P-CU-reanchor-same", "freshness_binding_mismatch", v)
	v = currencyUpgrade()
	v.Mode = "freshness-reanchor"
	currencyTip(&v, func(b M) { b["publication_seq"] = 10 })
	proof := v.Fixture["snapshot_journal"].(M)
	proof["entries"] = proof["entries"].([]any)[1:]
	add("N-CU-reanchor-journal-gap", "Recovery skips publication positions only, never a journal anchor.", "P-CU-upgrade-reanchor", "freshness_state_invalid", v)
	v = reviewSource("P-CU-journal-upgrade")
	v.Fixture["snapshot_journal"].(M)["entries"] = []any{}
	add("P-CU-journal-argument", "The explicit journal method argument supplies its suffix; the context suffix belongs to freshness calls.", "", "accept", v)
	v = reviewSource("P-CU-check-registry-owner")
	v.Input["use"].(M)["registry_currency_version"] = 1
	add("N-CU-receipt-version", "Receipt use cannot roll back the protected profile.", "P-CU-check-registry-owner", "freshness_receipt_binding_mismatch", v)
}
