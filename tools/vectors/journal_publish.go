package main

// A record publication includes the witnessed anchor, a real agent attestation
// reference, and a strictly later reissue of the identical cumulative entries.
func journalPublishReissue() Vector {
	v := journalBase()
	editedJournalPrior(&v, keys[7], func(b M) { b["at"] = "2026-01-01T00:01:10Z" })
	anchor := v.Input["entries"].([]any)[0]
	ref := v.Fixture["agent_attestation_ids"].(M)[keys[2].ID]
	entry := entryRecord(2, decode(anchor.(string))["id"], "2026-01-01T00:01:10Z", "add", "attestation/1")
	b := entry["body"].(M)
	b["record"] = ref
	entry["id"] = digest(append([]byte(domain("journal-entry/1")+"\n"), canonical(b)...))
	row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
	snapshot := decode(row["snapshot"].(string))["body"].(M)
	snapshot["issued_at"] = "2026-01-01T00:01:05Z"
	row["snapshot"] = evidenceWire(snapshot, keys[7])
	snapID := decode(row["snapshot"].(string))["id"]
	reissue := entryRecord(3, entry["id"], "2026-01-01T00:01:10Z", "add", "revocation/1")
	b = reissue["body"].(M)
	b["record"] = snapID
	reissue["id"] = digest(append([]byte(domain("journal-entry/1")+"\n"), canonical(b)...))
	v.Input["entries"] = []any{anchor, wire(entry), wire(reissue)}
	journalCheckpoint(&v, func(b M) {
		b["seq"], b["head"], b["at"], b["snapshot"] = 3, reissue["id"], "2026-01-01T00:01:20Z", snapID
	})
	v.Fixture["now"], v.Fixture["watermark"] = "2026-01-01T00:01:20Z", "2026-01-01T00:01:20Z"
	return v
}
func journalPublishVectors() {
	v := journalPublishReissue()
	add("P-JRN-publish-reissue", "One publication proof binds the witnessed anchor, new agent attestation entry, unchanged cumulative snapshot reissued later, descendant checkpoint and exact prior checkpoint bytes.", "", "accept", v)
	// Codes come from J3, J5a and J6 in the specification, not either verifier.
	for _, tc := range []struct {
		id, claim, code string
		edit            func(*Vector)
	}{
		{"old-snapshot", "J3 refuses a new checkpoint naming the pre-reissue snapshot instead of the supplied current signed reissue.", "checkpoint_snapshot_invalid", func(v *Vector) {
			w := v.Fixture["journal_witness"].(M)
			prior := decode(v.Fixture["seen"].(M)[w["checkpoint_id"].(string)].(string))
			journalCheckpoint(v, func(b M) { b["snapshot"] = prior["body"].(M)["snapshot"] })
		}},
		{"missing-reissue", "J6 refuses a proof missing the final reissue entry because it cannot reach the checkpoint head and sequence.", "journal_chain_broken", func(v *Vector) { v.Input["entries"] = v.Input["entries"].([]any)[:2] }},
		{"missing-record", "J6 refuses a proof omitting the new attestation entry between anchor and reissue.", "journal_chain_broken", func(v *Vector) { a := v.Input["entries"].([]any); v.Input["entries"] = []any{a[0], a[2]} }},
		{"missing-prior", "J5a refuses unavailable exact witnessed checkpoint bytes despite a complete entry suffix.", "journal_unavailable", func(v *Vector) {
			delete(v.Fixture["seen"].(M), v.Fixture["journal_witness"].(M)["checkpoint_id"].(string))
		}},
		{"wrong-prior", "J5a refuses genuinely signed prior bytes whose content id differs from the witness checkpoint id at that lookup key.", "checkpoint_invalid", func(v *Vector) {
			id := v.Fixture["journal_witness"].(M)["checkpoint_id"].(string)
			b := decode(v.Fixture["seen"].(M)[id].(string))["body"].(M)
			b["at"] = "2026-01-01T00:01:11Z"
			v.Fixture["seen"].(M)[id] = wire(envelope(b, keys[7], "author"))
		}},
		{"backward-time", "J5a refuses candidate checkpoint time before its authenticated prior checkpoint; J3 snapshot time and currency remain valid.", "journal_rollback", func(v *Vector) { journalCheckpoint(v, func(b M) { b["at"] = "2026-01-01T00:01:09Z" }) }},
	} {
		v = journalPublishReissue()
		tc.edit(&v)
		add("N-JRN-publish-reissue-"+tc.id, tc.claim, "P-JRN-publish-reissue", tc.code, v)
	}
}
