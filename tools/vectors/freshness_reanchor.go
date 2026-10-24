package main

// Synthetic signed recovery fixtures preserve normal current-evidence gates;
// the audit expectation is computed from the two explicit endpoints.
func freshnessInteger(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case float64:
		return int64(n)
	default:
		panic("unexpected fixture integer")
	}
}
func freshnessReanchorBase() Vector {
	v := freshnessBase()
	v.Mode = "freshness-reanchor"
	freshnessEdit(&v, func(b M) { b["publication_seq"], b["prev"] = 67, digest([]byte("unprovided predecessor")) })
	return v
}
func reanchorCheckpoint(v *Vector, edit func(M)) {
	journalCheckpoint(v, edit)
	cp := decode(v.Input["checkpoint"].(string))
	cb := cp["body"].(M)
	w := v.Fixture["journal_witness"].(M)
	w["registry_seq"], w["registry_head"], w["checkpoint_id"] = cb["seq"], cb["head"], cp["id"]
	freshnessEdit(v, func(b M) { b["registry_seq"], b["checkpoint_id"] = cb["seq"], cp["id"] })
}

// Retained state derives from a real signed higher-head publication; the
// candidate current head is deliberately older, isolating the rollback gate.
func freshnessHigherAnchor(v *Vector) {
	cp := decode(v.Input["checkpoint"].(string))["body"].(M)
	cp["seq"], cp["head"] = 3, digest([]byte("retained higher registry head"))
	checkpoint := envelope(cp, keys[7], "author")
	b := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
	b["publication_seq"], b["prev"], b["issued_at"] = 1, nil, "2026-01-01T00:01:00Z"
	b["registry_seq"], b["checkpoint_id"] = 3, checkpoint["id"]
	v.Fixture["freshness_anchor"] = freshnessFact(envelope(b, keys[7], "author"))
}
func freshnessReanchorVectors() {
	v := freshnessReanchorBase()
	add("P-FR-RA-same", "Explicit recovery at the same head skips exactly65 positions and audits both freshness and checkpoint endpoints.", "", "accept", v)
	v = freshnessReanchorBase()
	freshnessChanged(&v, []any{})
	add("P-FR-RA-higher", "A fresh authenticated higher registry head and cumulative snapshot permit explicit recovery across65 missing positions.", "", "accept", v)
	v = freshnessBase()
	v.Mode = "freshness-reanchor"
	add("P-FR-RA-adjacent", "Explicit recovery is permitted for an adjacent publication and reports zero skipped positions explicitly.", "", "accept", v)
	v = freshnessReanchorBase()
	freshnessEdit(&v, func(b M) { b["publication_seq"] = 9007199254740991 })
	add("P-FR-RA-safe-max", "Skipped positions use exact safe-integer subtraction, including the maximum wire publication sequence.", "", "accept", v)
	for _, tc := range []struct {
		id, claim, code string
		edit            func(*Vector)
	}{
		{"registry-lower", "A current witnessed head below the stored anchor refuses rollback despite a higher publication sequence.", "freshness_rollback", func(v *Vector) { freshnessHigherAnchor(v) }},
		{"head-fork", "Equal registry sequence cannot replace the retained head even with a newly valid checkpoint and witness.", "freshness_fork", func(v *Vector) { reanchorCheckpoint(v, func(b M) { b["head"] = digest([]byte("forked head")) }) }},
		{"checkpoint-fork", "Equal registry sequence and head cannot replace the retained checkpoint id.", "freshness_fork", func(v *Vector) { reanchorCheckpoint(v, func(b M) { b["at"] = "2026-01-01T00:01:01Z" }) }},
		{"publication-equal", "Explicit recovery requires strict publication advance, including an otherwise identical stored tip.", "freshness_rollback", func(v *Vector) {
			v.Fixture["freshness_anchor"] = freshnessFact(decode(v.Input["chain"].([]any)[0].(string)))
		}},
		{"publication-lower", "Recovery cannot roll back publication positions at a current witnessed head.", "freshness_rollback", func(v *Vector) { v.Fixture["freshness_anchor"].(M)["publication_seq"] = 68 }},
		{"time-equal", "A higher publication position with equal retained issuance refuses rollback.", "freshness_rollback", func(v *Vector) { v.Fixture["freshness_anchor"].(M)["issued_at"] = v.Fixture["now"] }},
		{"time-lower", "A higher publication position with older issuance refuses rollback.", "freshness_rollback", func(v *Vector) {
			v.Fixture["freshness_anchor"].(M)["issued_at"] = "2026-01-01T00:03:01Z"
			v.Fixture["watermark"] = "2026-01-01T00:03:01Z"
		}},
		{"tip-stale", "Recovery never renews a stale signed tip.", "freshness_unavailable", func(v *Vector) { freshnessEdit(v, func(b M) { b["issued_at"] = "2026-01-01T00:01:59Z" }) }},
		{"read-stale", "Recovery never renews an old authenticated witness read.", "freshness_unavailable", func(v *Vector) { v.Fixture["witness_read_at"] = "2026-01-01T00:01:59Z" }},
		{"read-absent", "A witness projection without an authenticated read timestamp cannot recover.", "freshness_unavailable", func(v *Vector) { delete(v.Fixture, "witness_read_at") }},
		{"witness-absent", "Unavailable witness fails closed on recovery as on normal admission.", "freshness_unavailable", func(v *Vector) { delete(v.Fixture, "journal_witness") }},
		{"snapshot-binding", "Recovery keeps exact snapshot equals checkpoint.snapshot binding.", "freshness_binding_mismatch", func(v *Vector) {
			reanchorCheckpoint(v, func(b M) { b["snapshot"] = digest([]byte("other checkpoint snapshot")) })
		}},
		{"snapshot-incomplete", "Recovery never turns an incomplete base into cumulative revocation evidence.", "freshness_unavailable", func(v *Vector) {
			row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			b := decode(row["snapshot"].(string))["body"].(M)
			b["complete"] = false
			row["snapshot"] = evidenceWire(b, keys[7])
		}},
		{"snapshot-continuity", "Recovery never waives protected cumulative snapshot continuity.", "freshness_unavailable", func(v *Vector) { v.Fixture["revocations"].(M)[keys[7].ID].(M)["rollback_safe"] = false }},
		{"anchor-absent", "Explicit recovery does not bootstrap an absent stored anchor.", "freshness_unavailable", func(v *Vector) { delete(v.Fixture, "freshness_anchor") }},
		{"genesis", "Recovery needs a real prior publication for its strict time and endpoint audit; genesis uses the normal path.", "freshness_state_invalid", func(v *Vector) {
			a := v.Fixture["freshness_anchor"].(M)
			a["publication_seq"], a["freshness_id"], a["issued_at"] = 0, nil, nil
		}},
		{"signature", "Explicit recovery still requires the registry-owner freshness signature.", "freshness_signature_invalid", func(v *Vector) {
			c := v.Input["chain"].([]any)
			b := decode(c[0].(string))["body"].(M)
			c[0] = wire(envelope(b, keys[0], "author"))
		}},
		{"request", "Recovery validates queries after the full current-evidence and anchor gates.", "freshness_request_invalid", func(v *Vector) { v.Input["ids"] = []any{"bad id"} }},
	} {
		v = freshnessReanchorBase()
		tc.edit(&v)
		add("N-FR-RA-"+tc.id, tc.claim, "P-FR-RA-same", tc.code, v)
	}
	v = freshnessReanchorBase()
	freshnessChanged(&v, []any{M{"kind": "key", "id": keys[2].ID, "from": "2026-01-01T00:02:00Z"}})
	add("N-FR-RA-revoked", "Recovery at a higher cumulative head cannot hide an effective revocation or return a partial audit plan.", "P-FR-RA-higher", "revoked", v)
	v = freshnessReanchorBase()
	v.Mode = "freshness"
	add("N-FR-RA-default-gap", "The default normal API never silently recovers a missing publication chain.", "P-FR-RA-same", "freshness_gap", v)
	// Each compound has its earlier-only operand above and a later-only operand;
	// codes distinguish the observable F8R order from downstream query matching.
	for _, tc := range []struct {
		id, code string
		edit     func(*Vector)
	}{
		{"currency-registry", "freshness_unavailable", func(v *Vector) {
			v.Fixture["witness_read_at"] = "2026-01-01T00:01:59Z"
			freshnessHigherAnchor(v)
		}},
		{"registry-publication", "freshness_fork", func(v *Vector) {
			reanchorCheckpoint(v, func(b M) { b["head"] = digest([]byte("forked head")) })
			v.Fixture["freshness_anchor"].(M)["publication_seq"] = 68
		}},
		{"publication-query", "freshness_rollback", func(v *Vector) {
			v.Fixture["freshness_anchor"].(M)["publication_seq"] = 68
			v.Input["ids"] = []any{"bad id"}
		}},
		{"time-query", "freshness_rollback", func(v *Vector) {
			v.Fixture["freshness_anchor"].(M)["issued_at"] = v.Fixture["now"]
			v.Input["ids"] = []any{"bad id"}
		}},
		{"binding-read", "freshness_binding_mismatch", func(v *Vector) {
			reanchorCheckpoint(v, func(b M) { b["snapshot"] = digest([]byte("other checkpoint snapshot")) })
			v.Fixture["witness_read_at"] = "2026-01-01T00:01:59Z"
		}},
	} {
		v = freshnessReanchorBase()
		tc.edit(&v)
		add("N-ORD-FR-RA-"+tc.id, "Recovery preserves the specified first refusal for simultaneous "+tc.id+" faults.", "P-FR-RA-same", tc.code, v)
	}
}
