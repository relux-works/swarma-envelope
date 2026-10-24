package main

// Epoch fixtures keep all signed evidence and protected clocks at the documented
// minimum or its immediate neighbor. No predecessor time exists at genesis.
func freshnessEpoch(at string) Vector {
	v := freshnessBase()
	row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
	b := decode(row["snapshot"].(string))["body"].(M)
	b["issued_at"] = at
	snap := envelope(b, keys[7], "author")
	row["snapshot"] = wire(snap)
	entry := entryRecord(1, nil, at, "add", "revocation/1")
	entry["body"].(M)["record"] = snap["id"]
	entry["id"] = digest(append([]byte(domain("journal-entry/1")+"\n"), canonical(entry["body"])...))
	journalCheckpoint(&v, func(b M) { b["seq"], b["head"], b["at"], b["snapshot"] = 1, entry["id"], at, snap["id"] })
	cp := decode(v.Input["checkpoint"].(string))
	v.Fixture["journal_witness"] = M{"registry_id": keys[7].ID, "owner": "owner-a", "registry_seq": 1, "registry_head": entry["id"], "checkpoint_id": cp["id"], "previous_checkpoint_id": nil}
	freshnessEdit(&v, func(b M) {
		b["publication_seq"], b["prev"], b["issued_at"], b["snapshot"], b["registry_seq"], b["checkpoint_id"] = 1, nil, at, snap["id"], 1, cp["id"]
	})
	v.Fixture["freshness_anchor"] = freshnessFact(decode(v.Input["chain"].([]any)[0].(string)))
	a := v.Fixture["freshness_anchor"].(M)
	a["publication_seq"], a["freshness_id"], a["issued_at"] = 0, nil, nil
	v.Fixture["now"], v.Fixture["watermark"], v.Fixture["witness_read_at"] = at, at, at
	v.Fixture["time"].(M)["authority_until"] = "1970-01-01T00:06:00Z"
	return v
}
func freshnessEpochVectors() {
	const epoch = "1970-01-01T00:00:00Z"
	const next = "1970-01-01T00:00:01Z"
	v := freshnessEpoch(epoch)
	v.Fixture["freshness_anchor"] = freshnessFact(decode(v.Input["chain"].([]any)[0].(string)))
	freshnessEdit(&v, func(b M) { b["publication_seq"], b["prev"] = 2, v.Fixture["freshness_anchor"].(M)["freshness_id"] })
	add("N-FR-epoch-equal", "An actual epoch-zero predecessor requires strict time increase; zero is not absence.", "P-FR-epoch-advance", "freshness_time_invalid", v)
	v = freshnessEpoch(epoch)
	add("P-FR-genesis-epoch", "The minimum timestamp accepts as the first publication when predecessor time is absent.", "", "accept", v)
	v = freshnessEpoch(next)
	add("P-FR-genesis-epoch-plus-one", "The one-second neighbor accepts with no predecessor timestamp.", "", "accept", v)
	v = freshnessEpoch(epoch)
	v.Fixture["freshness_anchor"] = freshnessFact(decode(v.Input["chain"].([]any)[0].(string)))
	add("P-FR-epoch-retransmit", "Exact epoch-zero publication retransmission preserves the accepted id, time and bindings.", "", "accept", v)
	v = freshnessEpoch(epoch)
	v.Fixture["freshness_anchor"] = freshnessFact(decode(v.Input["chain"].([]any)[0].(string)))
	freshnessEdit(&v, func(b M) {
		b["publication_seq"], b["prev"], b["issued_at"] = 2, v.Fixture["freshness_anchor"].(M)["freshness_id"], next
	})
	v.Fixture["now"], v.Fixture["watermark"], v.Fixture["witness_read_at"] = next, next, next
	add("P-FR-epoch-advance", "A real epoch-zero predecessor permits a strictly later publication.", "", "accept", v)
}
