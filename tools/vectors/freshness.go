package main

import (
	"fmt"
	"time"
)

// Freshness fixtures use real registry signatures and independently computed
// hash links. Negative cases preserve an accepted control, never mock authority.
func freshnessBase() Vector {
	v := journalBase()
	v.Mode = "freshness"
	cp := decode(v.Input["checkpoint"].(string))
	cb := cp["body"].(M)
	first := M{"type": "freshness/1", "registry": keys[7].ID, "owner": "owner-a", "publication_seq": 1, "prev": nil, "issued_at": "2026-01-01T00:01:00Z", "snapshot": cb["snapshot"], "registry_seq": cb["seq"], "checkpoint_id": cp["id"]}
	anchor := envelope(first, keys[7], "author")
	v.Fixture["freshness_anchor"] = freshnessFact(anchor)
	v.Fixture["journal_witness"] = M{"registry_id": keys[7].ID, "owner": "owner-a", "registry_seq": cb["seq"], "registry_head": cb["head"], "checkpoint_id": cp["id"], "previous_checkpoint_id": v.Fixture["journal_witness"].(M)["checkpoint_id"]}
	next := decode(wire(first))
	next["publication_seq"], next["prev"], next["issued_at"] = 2, anchor["id"], "2026-01-01T00:03:00Z"
	v.Input = M{"chain": []any{wire(envelope(next, keys[7], "author"))}, "checkpoint": wire(cp), "ids": []any{}, "keys": []any{keys[2].ID}}
	v.Fixture["now"], v.Fixture["watermark"], v.Fixture["witness_read_at"] = next["issued_at"], next["issued_at"], next["issued_at"]
	return v
}
func freshnessFact(e M) M {
	b := e["body"].(M)
	return M{"registry_id": b["registry"], "owner": b["owner"], "publication_seq": b["publication_seq"], "freshness_id": e["id"], "issued_at": b["issued_at"], "snapshot": b["snapshot"], "registry_seq": b["registry_seq"], "checkpoint_id": b["checkpoint_id"]}
}
func freshnessEdit(v *Vector, edit func(M)) {
	chain := v.Input["chain"].([]any)
	b := decode(chain[len(chain)-1].(string))["body"].(M)
	edit(b)
	chain[len(chain)-1] = wire(envelope(b, keys[7], "author"))
}
func freshnessAnchorTime(v *Vector, at string) {
	b := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
	b["publication_seq"], b["prev"], b["issued_at"] = 1, nil, at
	e := envelope(b, keys[7], "author")
	v.Fixture["freshness_anchor"] = freshnessFact(e)
	freshnessEdit(v, func(b M) { b["prev"] = e["id"] })
}
func freshnessChanged(v *Vector, entries []any) {
	row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
	b := decode(row["snapshot"].(string))["body"].(M)
	b["issued_at"], b["entries"] = "2026-01-01T00:02:00Z", entries
	row["snapshot"] = evidenceWire(b, keys[7])
	snapshot := decode(row["snapshot"].(string))["id"]
	previous := decode(v.Input["checkpoint"].(string))["id"]
	journalCheckpoint(v, func(b M) {
		b["seq"], b["head"], b["at"], b["snapshot"] = 3, digest([]byte("new registry head")), "2026-01-01T00:02:00Z", snapshot
	})
	cp := decode(v.Input["checkpoint"].(string))
	cb := cp["body"].(M)
	v.Fixture["journal_witness"] = M{"registry_id": keys[7].ID, "owner": "owner-a", "registry_seq": cb["seq"], "registry_head": cb["head"], "checkpoint_id": cp["id"], "previous_checkpoint_id": previous}
	freshnessEdit(v, func(b M) {
		b["snapshot"], b["registry_seq"], b["checkpoint_id"], b["prev"] = snapshot, cb["seq"], cp["id"], nil
	})
}
func freshnessVectors() {
	for _, tc := range []struct {
		id, claim, code string
		edit            func(*Vector)
	}{
		{"missing", "Absent freshness is never an implicit age extension.", "freshness_unavailable", func(v *Vector) { v.Input["chain"] = []any{} }},
		{"stale", "A valid signature cannot extend freshness beyond protected max age.", "freshness_unavailable", func(v *Vector) { freshnessEdit(v, func(b M) { b["issued_at"] = "2026-01-01T00:01:59Z" }) }},
		{"future", "Future-issued freshness cannot bypass min(now,W).", "freshness_unavailable", func(v *Vector) { freshnessEdit(v, func(b M) { b["issued_at"] = "2026-01-01T00:03:01Z" }) }},
		{"snapshot-binding", "Freshness cannot extend a snapshot other than checkpoint.snapshot.", "freshness_binding_mismatch", func(v *Vector) { freshnessEdit(v, func(b M) { b["snapshot"] = digest([]byte("other snapshot")) }) }},
		{"checkpoint-binding", "Freshness names the exact signed checkpoint content id.", "freshness_binding_mismatch", func(v *Vector) {
			freshnessEdit(v, func(b M) { b["checkpoint_id"] = digest([]byte("other checkpoint")) })
		}},
		{"registry-seq-binding", "Freshness registry sequence must equal its named checkpoint.", "freshness_binding_mismatch", func(v *Vector) { freshnessEdit(v, func(b M) { b["registry_seq"] = 3 }) }},
		{"changed-snapshot", "An old freshness cannot extend changed snapshot/checkpoint bytes.", "freshness_binding_mismatch", func(v *Vector) {
			old := v.Input["chain"].([]any)[0]
			freshnessChanged(v, []any{})
			v.Input["chain"] = []any{old}
		}},
		{"rollback", "An earlier publication sequence cannot replace accepted state.", "freshness_rollback", func(v *Vector) {
			e := decode(v.Input["chain"].([]any)[0].(string))
			v.Fixture["freshness_anchor"] = freshnessFact(e)
			freshnessEdit(v, func(b M) { b["publication_seq"], b["prev"] = 1, nil })
		}},
		{"fork", "A same-sequence different signed binding is a fork.", "freshness_fork", func(v *Vector) {
			e := decode(v.Input["chain"].([]any)[0].(string))
			b := e["body"].(M)
			b["issued_at"] = "2026-01-01T00:02:59Z"
			v.Fixture["freshness_anchor"] = freshnessFact(envelope(b, keys[7], "author"))
		}},
		{"time-equal", "Publication issued_at must strictly increase despite a fresh tip.", "freshness_time_invalid", func(v *Vector) { freshnessAnchorTime(v, "2026-01-01T00:03:00Z") }},
		{"time-backward", "Publication time cannot move backward.", "freshness_time_invalid", func(v *Vector) {
			freshnessAnchorTime(v, "2026-01-01T00:03:01Z")
			v.Fixture["watermark"] = "2026-01-01T00:03:01Z"
		}},
		{"gap", "A signed publication cannot skip a sequence position.", "freshness_gap", func(v *Vector) { freshnessEdit(v, func(b M) { b["publication_seq"] = 3 }) }},
		{"prev", "A signed publication must bind its immediately preceding content id.", "freshness_gap", func(v *Vector) { freshnessEdit(v, func(b M) { b["prev"] = digest([]byte("wrong previous")) }) }},
		{"prev-null", "A continuing same-head freshness chain cannot omit its predecessor.", "freshness_gap", func(v *Vector) { freshnessEdit(v, func(b M) { b["prev"] = nil }) }},
		{"head-prev", "The first publication after a checkpoint head change must use null predecessor.", "freshness_gap", func(v *Vector) {
			freshnessChanged(v, []any{})
			freshnessEdit(v, func(b M) { b["prev"] = v.Fixture["freshness_anchor"].(M)["freshness_id"] })
		}},
		{"head-gap", "A checkpoint change cannot hide a missing global publication position.", "freshness_gap", func(v *Vector) {
			freshnessChanged(v, []any{})
			freshnessEdit(v, func(b M) { b["publication_seq"] = 3 })
		}},
		{"witness-missing", "Missing authenticated witness head refuses.", "freshness_unavailable", func(v *Vector) { delete(v.Fixture, "journal_witness") }},
		{"witness-malformed", "The witness fact stays the exact six-field interface.", "freshness_witness_invalid", func(v *Vector) { v.Fixture["journal_witness"].(M)["at"] = v.Fixture["now"] }},
		{"witness-older", "A witness older than the named checkpoint is unavailable evidence.", "freshness_unavailable", func(v *Vector) {
			w := v.Fixture["journal_witness"].(M)
			w["registry_seq"], w["checkpoint_id"], w["previous_checkpoint_id"] = 1, w["previous_checkpoint_id"], nil
		}},
		{"witness-newer", "A candidate behind the fresh witness head is rollback.", "freshness_rollback", func(v *Vector) { v.Fixture["journal_witness"].(M)["registry_seq"] = 3 }},
		{"witness-fork", "Same witnessed registry sequence with another checkpoint id is a fork.", "freshness_fork", func(v *Vector) {
			v.Fixture["journal_witness"].(M)["checkpoint_id"] = digest([]byte("other witnessed checkpoint"))
		}},
		{"witness-head", "Checkpoint head must equal the fresh authenticated witness head.", "freshness_fork", func(v *Vector) {
			v.Fixture["journal_witness"].(M)["registry_head"] = digest([]byte("other witnessed entry"))
		}},
		{"read-missing", "A verified old head fact is not a fresh authenticated read.", "freshness_unavailable", func(v *Vector) { delete(v.Fixture, "witness_read_at") }},
		{"read-malformed", "Read freshness comes from a typed protected timestamp.", "freshness_witness_invalid", func(v *Vector) { v.Fixture["witness_read_at"] = true }},
		{"read-stale", "A stale authenticated witness read cannot renew a snapshot.", "freshness_unavailable", func(v *Vector) { v.Fixture["witness_read_at"] = "2026-01-01T00:01:59Z" }},
		{"read-before-issue", "The authenticated read must follow the current freshness issuance.", "freshness_unavailable", func(v *Vector) { v.Fixture["witness_read_at"] = "2026-01-01T00:02:59Z" }},
		{"read-future", "Future witness read times refuse.", "freshness_unavailable", func(v *Vector) { v.Fixture["witness_read_at"] = "2026-01-01T00:03:01Z" }},
		{"anchor-missing", "Missing publication history never defaults to genesis.", "freshness_unavailable", func(v *Vector) { delete(v.Fixture, "freshness_anchor") }},
		{"anchor-malformed", "Malformed accepted publication state refuses.", "freshness_state_invalid", func(v *Vector) { v.Fixture["freshness_anchor"].(M)["publication_seq"] = false }},
		{"anchor-owner", "An anchor for another owner cannot order publications here.", "freshness_state_invalid", func(v *Vector) { v.Fixture["freshness_anchor"].(M)["owner"] = "other-owner" }},
		{"snapshot-incomplete", "Freshness cannot certify an incomplete cumulative snapshot.", "freshness_unavailable", func(v *Vector) {
			row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			b := decode(row["snapshot"].(string))["body"].(M)
			b["complete"] = false
			row["snapshot"] = evidenceWire(b, keys[7])
		}},
		{"snapshot-discontinuous", "Freshness cannot waive snapshot rollback continuity.", "freshness_unavailable", func(v *Vector) { v.Fixture["revocations"].(M)[keys[7].ID].(M)["rollback_safe"] = false }},
		{"snapshot-signature", "Freshness never substitutes for snapshot root crypto.", "freshness_snapshot_invalid", func(v *Vector) {
			row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			e := decode(row["snapshot"].(string))
			e["signatures"].([]any)[0].(M)["sig"] = b64(make([]byte, 64))
			row["snapshot"] = wire(e)
		}},
		{"signature", "Freshness root signature math is mandatory.", "freshness_signature_invalid", func(v *Vector) {
			c := v.Input["chain"].([]any)
			e := decode(c[0].(string))
			e["signatures"].([]any)[0].(M)["sig"] = b64(make([]byte, 64))
			c[0] = wire(e)
		}},
		{"role", "Exactly one registry author signature is required.", "freshness_signature_invalid", func(v *Vector) {
			c := v.Input["chain"].([]any)
			b := decode(c[0].(string))["body"].(M)
			c[0] = wire(envelope(b, keys[7], "approver"))
		}},
		{"id", "An incorrect freshness content id refuses before proof use.", "freshness_signature_invalid", func(v *Vector) {
			c := v.Input["chain"].([]any)
			e := decode(c[0].(string))
			e["id"] = digest([]byte("wrong id"))
			c[0] = wire(e)
		}},
		{"extra", "Freshness body is closed; no optional members.", "freshness_malformed", func(v *Vector) { freshnessEdit(v, func(b M) { b["extra"] = true }) }},
		{"seq-type", "Boolean publication_seq is not a safe integer.", "freshness_malformed", func(v *Vector) { freshnessEdit(v, func(b M) { b["publication_seq"] = true }) }},
		{"checkpoint-snapshot", "Even current freshness and snapshot IDs cannot override a different checkpoint.snapshot.", "freshness_binding_mismatch", func(v *Vector) {
			row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			old := row["snapshot"]
			oldID := decode(old.(string))["id"]
			freshnessChanged(v, []any{})
			row["snapshot"] = old
			freshnessEdit(v, func(b M) { b["snapshot"] = oldID })
		}},
		{"checkpoint-signature", "The named checkpoint still requires actual registry signature verification.", "checkpoint_invalid", func(v *Vector) { badCheckpoint(v) }},
		{"role-overlap", "A configured commit signer cannot also be the registry freshness root.", "freshness_invalid", func(v *Vector) { v.Fixture["commit_signing_key"] = keys[7].ID }},
		{"request", "Malformed revocation query refuses after complete proof admission.", "freshness_request_invalid", func(v *Vector) { v.Input["ids"] = []any{"not-a-content-id"} }},
	} {
		v := freshnessBase()
		tc.edit(&v)
		add("N-FR-"+tc.id, tc.claim, "P-FR-old-snapshot", tc.code, v)
	}
	for _, tc := range []struct {
		name string
		key  int
	}{{"service", 3}, {"grant-root", 0}, {"operator", 4}, {"purpose5", 5}, {"commit", 1}} {
		v := freshnessBase()
		if tc.name == "service" {
			svc := serviceBase()
			delete(v.Fixture, "enrollment_publisher")
			v.Fixture["service_authority"], v.Fixture["service_attestations"] = svc.Fixture["service_authority"], svc.Fixture["service_attestations"]
		}
		c := v.Input["chain"].([]any)
		b := decode(c[0].(string))["body"].(M)
		c[0] = wire(envelope(b, keys[tc.key], "author"))
		add("N-FR-signer-"+tc.name, "Only the registry-owner role can sign freshness, even when foreign signature math is valid.", "P-FR-old-snapshot", "freshness_signature_invalid", v)
	}
	v := freshnessBase()
	freshnessChanged(&v, []any{})
	freshnessEdit(&v, func(b M) { b["publication_seq"] = v.Fixture["freshness_anchor"].(M)["publication_seq"] })
	add("N-FR-fork-binding", "A current changed snapshot/checkpoint at an already accepted publication position is a fork, not a valid renewal.", "P-FR-changed", "freshness_fork", v)
	v = freshnessBase()
	freshnessChanged(&v, []any{M{"kind": "key", "id": keys[2].ID, "from": "2026-01-01T00:02:00Z"}})
	add("N-FR-revoked", "Current freshness retains effective revocation matching; no accepted partial plan.", "P-FR-changed", "revoked", v)
	v = freshnessBase()
	add("P-FR-old-snapshot", "A complete snapshot120seconds old remains usable only through current signed freshness and an exact fresh witnessed head.", "", "accept", v)
	v = freshnessBase()
	freshnessChanged(&v, []any{})
	add("P-FR-changed", "A changed snapshot is usable with its new checkpoint, fresh head read and newly bound freshness.", "", "accept", v)
	v = freshnessBase()
	v.Fixture["freshness_anchor"] = freshnessFact(decode(v.Input["chain"].([]any)[0].(string)))
	add("P-FR-retransmit", "An identical current publication can be retransmitted without changing its accepted state.", "", "accept", v)
	v = freshnessBase()
	b := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
	b["issued_at"] = "2026-01-01T00:01:20Z"
	middle := envelope(b, keys[7], "author")
	b = decode(wire(b))
	b["publication_seq"], b["prev"], b["issued_at"] = 3, middle["id"], "2026-01-01T00:03:00Z"
	v.Input["chain"] = []any{wire(middle), wire(envelope(b, keys[7], "author"))}
	add("P-FR-chain", "Old intermediate publications prove complete hash-linked history while only the tip supplies current freshness.", "", "accept", v)
	v = freshnessBase()
	middleBody := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
	middleBody["issued_at"] = "2026-01-01T00:01:20Z"
	middle = envelope(middleBody, keys[7], "author")
	freshnessChanged(&v, []any{})
	freshnessEdit(&v, func(b M) { b["publication_seq"] = 3 })
	v.Input["chain"] = []any{wire(middle), v.Input["chain"].([]any)[0]}
	add("P-FR-head-chain", "A head change resets only the same-head predecessor; a complete signed global sequence and increasing time still span both heads.", "", "accept", v)

	// Valid signed boundary chains isolate count limits from malformed parsing.
	for _, n := range []int{65, 64} {
		v := freshnessBase()
		a := v.Fixture["freshness_anchor"].(M)
		prev := a["freshness_id"]
		chain := []any{}
		for i := 1; i <= n; i++ {
			b := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
			b["publication_seq"], b["prev"], b["issued_at"] = i+1, prev, time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC).Add(time.Duration(i)*time.Second).Format(time.RFC3339)
			e := envelope(b, keys[7], "author")
			chain = append(chain, wire(e))
			prev = e["id"]
		}
		v.Input["chain"] = chain
		if n == 65 {
			add("N-FR-count65", "An otherwise valid65-record publication proof exceeds the count bound.", "P-FR-count64", "freshness_malformed", v)
		} else {
			add("P-FR-count64", "A complete64-record signed proof reaches the exact count boundary; old intermediates do not provide current authority.", "", "accept", v)
		}
	}
	v = freshnessBase()
	a := v.Fixture["freshness_anchor"].(M)
	a["publication_seq"], a["freshness_id"], a["issued_at"] = 0, nil, nil
	freshnessEdit(&v, func(b M) { b["publication_seq"], b["prev"] = 1, nil })
	add("P-FR-genesis", "Explicit protected publication-genesis provisioning admits a first signed record; absent state still refuses.", "", "accept", v)

	freshnessOrderVectors()
	freshnessDomainVectors()
}
func freshnessOrderVectors() {
	for _, tc := range []struct {
		id, claim, code string
		edit            func(*Vector)
	}{
		{"parse-policy", "F1 shape precedes missing registry policy.", "freshness_malformed", func(v *Vector) {
			freshnessEdit(v, func(b M) { b["extra"] = true })
			delete(v.Fixture, "registry_owner")
		}},
		{"policy-signature", "F2 policy precedes invalid signature.", "freshness_unavailable", func(v *Vector) {
			delete(v.Fixture, "registry_owner")
			v.Input["chain"].([]any)[0] = wire(envelope(decode(v.Input["chain"].([]any)[0].(string))["body"].(M), keys[0], "author"))
		}},
		{"signature-witness", "F3 signature precedes missing witness.", "freshness_signature_invalid", func(v *Vector) {
			delete(v.Fixture, "journal_witness")
			c := v.Input["chain"].([]any)
			c[0] = wire(envelope(decode(c[0].(string))["body"].(M), keys[0], "author"))
		}},
		{"snapshot-witness", "F4 snapshot signature precedes missing witness.", "freshness_snapshot_invalid", func(v *Vector) {
			delete(v.Fixture, "journal_witness")
			row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			e := decode(row["snapshot"].(string))
			e["signatures"].([]any)[0].(M)["sig"] = b64(make([]byte, 64))
			row["snapshot"] = wire(e)
		}},
		{"witness-binding", "F5 witness availability precedes wrong snapshot reference.", "freshness_unavailable", func(v *Vector) {
			delete(v.Fixture, "journal_witness")
			freshnessEdit(v, func(b M) { b["snapshot"] = digest([]byte("other")) })
		}},
		{"witness-currency", "F5 malformed witness precedes F8 stale freshness.", "freshness_witness_invalid", func(v *Vector) {
			v.Fixture["journal_witness"] = true
			freshnessEdit(v, func(b M) { b["issued_at"] = "2026-01-01T00:01:59Z" })
		}},
		{"binding-currency", "F6 exact snapshot binding precedes F8 stale freshness.", "freshness_binding_mismatch", func(v *Vector) {
			freshnessEdit(v, func(b M) { b["snapshot"], b["issued_at"] = digest([]byte("other")), "2026-01-01T00:01:59Z" })
		}},
		{"binding-sequence", "F6 current binding precedes a publication gap.", "freshness_binding_mismatch", func(v *Vector) {
			freshnessEdit(v, func(b M) { b["snapshot"], b["publication_seq"] = digest([]byte("other")), 3 })
		}},
		{"witness-sequence", "F7 head rollback precedes publication gap.", "freshness_rollback", func(v *Vector) {
			v.Fixture["journal_witness"].(M)["registry_seq"] = 3
			freshnessEdit(v, func(b M) { b["publication_seq"] = 3 })
		}},
		{"sequence-revoked", "F8 gap precedes F9 effective revocation.", "freshness_gap", func(v *Vector) {
			freshnessChanged(v, []any{M{"kind": "key", "id": keys[2].ID, "from": "2026-01-01T00:02:00Z"}})
			freshnessEdit(v, func(b M) { b["publication_seq"] = 3 })
		}},
	} {
		v := freshnessBase()
		tc.edit(&v)
		add("N-ORD-FR-"+tc.id, tc.claim, "P-FR-old-snapshot", tc.code, v)
	}
}
func freshnessDomainVectors() {
	tags := []string{"swarma-msg/2", "swarma-waggle grant/1", "swarma-waggle operator-act/1", "swarma-attestation attestation/1", "swarma-attestation revocation/1", "swarma-registrar registration/1", "swarma-registrar enrollment/1", "swarma-credential-broker grant/1", "swarma-credential-broker revocation/1", domain("journal-entry/1"), domain("checkpoint/1"), domain("freshness/1")}
	probe := func(actual, expected string) Vector {
		raw := append([]byte(actual+"\n"), canonical(M{"type": "domain-math-only"})...)
		return Vector{Mode: "domain", Input: M{"preimage": b64(raw), "key": keys[0].ID, "sig": b64(sign(keys[0], raw))}, Fixture: M{"expected_tag": expected}}
	}
	for i, tag := range tags[:11] {
		positive := ""
		for _, v := range cases {
			if v.Mode == "domain" && v.Expected["code"] == "accept" && v.Fixture["expected_tag"] == tag {
				positive = v.ID
				break
			}
		}
		if positive == "" {
			panic("missing domain control")
		}
		add(fmt.Sprintf("N-FR-domain-%02d-11", i), "Foreign registered domain does not become freshness by signature math.", "P-FR-domain", "domain_mismatch", probe(tag, tags[11]))
		add(fmt.Sprintf("N-FR-domain-11-%02d", i), "Freshness domain does not become any other registered profile.", positive, "domain_mismatch", probe(tags[11], tag))
	}
	add("N-FR-signer-domain", "The message signer refuses the exact freshness tag.", "PS1", "signer_domain_refused", Vector{Mode: "signer", Input: M{"preimage": b64(append([]byte(domain("freshness/1")+"\n"), canonical(M{})...))}, Fixture: M{}})
	add("P-FR-domain", "Freshness raw signature-math control is separate from registry authority admission.", "", "accept", probe(tags[11], tags[11]))
}
