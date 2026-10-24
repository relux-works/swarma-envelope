package main

// Prior checkpoint bytes are exact signed evidence, not a timestamp copied
// from an unauthenticated header or from the previous entry's distinct at.
func editedJournalPrior(v *Vector, signer Key, edit func(M)) {
	journalPrior(v)
	w := v.Fixture["journal_witness"].(M)
	b := decode(v.Fixture["seen"].(M)[w["checkpoint_id"].(string)].(string))["body"].(M)
	edit(b)
	e := envelope(b, signer, "author")
	raw := rememberJournalCheckpoint(e)
	w["checkpoint_id"] = e["id"]
	v.Fixture["seen"] = M{e["id"].(string): raw}
}
func journalAnchorVectors() {
	for _, tc := range []struct {
		id, claim, code string
		edit            func(*Vector)
	}{
		{"prior-missing", "Advancing requires the exact prior checkpoint bytes from the protected id journal.", "journal_unavailable", func(v *Vector) {}},
		{"prior-unavailable", "An unavailable id journal cannot supply the witnessed checkpoint.", "journal_unavailable", func(v *Vector) { journalPrior(v); v.Fixture["id_journal_available"] = false }},
		{"prior-invalid", "Malformed prior checkpoint bytes are invalid, not a missing-time default.", "checkpoint_invalid", func(v *Vector) {
			journalPrior(v)
			w := v.Fixture["journal_witness"].(M)
			v.Fixture["seen"].(M)[w["checkpoint_id"].(string)] = wire(M{"bad": true})
		}},
		{"prior-signature", "Prior checkpoint authentication remains strict even without a current-age check.", "checkpoint_invalid", func(v *Vector) {
			journalPrior(v)
			w := v.Fixture["journal_witness"].(M)
			e := decode(v.Fixture["seen"].(M)[w["checkpoint_id"].(string)].(string))
			e["signatures"].([]any)[0].(M)["sig"] = b64(make([]byte, 64))
			v.Fixture["seen"].(M)[w["checkpoint_id"].(string)] = wire(e)
		}},
		{"prior-registry", "A genuinely signed foreign-registry checkpoint is not this witness's prior checkpoint.", "checkpoint_invalid", func(v *Vector) { editedJournalPrior(v, keys[0], func(b M) { b["registry"] = keys[0].ID }) }},
		{"prior-owner", "A prior checkpoint signed for another owner cannot order this journal.", "checkpoint_invalid", func(v *Vector) { editedJournalPrior(v, keys[7], func(b M) { b["owner"] = "other-owner" }) }},
		{"prior-seq", "Prior bytes must match the witnessed registry sequence, not only checkpoint id.", "checkpoint_invalid", func(v *Vector) { editedJournalPrior(v, keys[7], func(b M) { b["seq"] = 2 }) }},
		{"prior-head", "Prior bytes must match the witnessed entry head, not only checkpoint id.", "checkpoint_invalid", func(v *Vector) {
			editedJournalPrior(v, keys[7], func(b M) { b["head"] = decode(v.Input["entries"].([]any)[1].(string))["id"] })
		}},
		{"prior-time", "Candidate checkpoint time cannot roll back the distinct prior checkpoint time.", "journal_rollback", func(v *Vector) {
			editedJournalPrior(v, keys[7], func(b M) { b["at"] = "2026-01-01T00:01:30Z" })
			v.Fixture["now"], v.Fixture["watermark"] = "2026-01-01T00:01:30Z", "2026-01-01T00:01:30Z"
		}},
		{"anchor-required", "An advancing suffix cannot omit the authenticated prior-head entry.", "journal_anchor_required", func(v *Vector) { journalPrior(v); v.Input["entries"] = v.Input["entries"].([]any)[1:] }},
		{"anchor-hash", "A claimed anchor id cannot authenticate changed entry bytes.", "journal_entry_invalid", func(v *Vector) { journalPrior(v); journalEntry(v, 0, func(b M) { b["at"] = "2026-01-01T00:00:15Z" }) }},
		{"prior-before-anchor", "J5a missing prior checkpoint precedes J6 missing entry anchor.", "journal_unavailable", func(v *Vector) { v.Input["entries"] = v.Input["entries"].([]any)[1:] }},
		{"anchor-before-entry", "J6 required anchor precedes the unanchored entry's invalid content id.", "journal_anchor_required", func(v *Vector) {
			journalPrior(v)
			v.Input["entries"] = v.Input["entries"].([]any)[1:]
			journalEntry(v, 0, func(b M) { b["at"] = "2026-01-01T00:00:31Z" })
		}},
	} {
		v := journalBase()
		tc.edit(&v)
		add("N-JRN-"+tc.id, tc.claim, "P-JRN-genesis", tc.code, v)
	}
	v := journalBase()
	editedJournalPrior(&v, keys[7], func(b M) { b["at"] = "2026-01-01T00:01:30Z" })
	journalCheckpoint(&v, func(b M) { b["at"] = "2026-01-01T00:01:30Z" })
	v.Fixture["now"], v.Fixture["watermark"] = "2026-01-01T00:01:30Z", "2026-01-01T00:01:30Z"
	add("P-JRN-prior-time-equal", "Equal prior/current checkpoint times accept with authenticated prior bytes and required entry anchor.", "", "accept", v)
	v = journalBase()
	journalPrior(&v)
	row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
	b := decode(row["snapshot"].(string))["body"].(M)
	b["issued_at"] = "2026-01-01T00:02:20Z"
	row["snapshot"] = evidenceWire(b, keys[7])
	id := decode(row["snapshot"].(string))["id"]
	journalCheckpoint(&v, func(b M) { b["at"], b["snapshot"] = "2026-01-01T00:02:20Z", id })
	v.Fixture["now"], v.Fixture["watermark"] = "2026-01-01T00:02:20Z", "2026-01-01T00:02:20Z"
	add("P-JRN-prior-aged", "An authenticated prior checkpoint older than max age still orders a new current checkpoint; it is not a current admission permit.", "", "accept", v)
}
