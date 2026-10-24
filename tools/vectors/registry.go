package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

// Exact synthetic signed checkpoint bytes are retained for fixture construction;
// only cases that consume the prior-checkpoint gate attach them as evidence.
var journalCheckpoints = map[string]string{}

func rememberJournalCheckpoint(e M) string {
	raw := wire(e)
	journalCheckpoints[e["id"].(string)] = raw
	return raw
}
func journalPrior(v *Vector) {
	id := v.Fixture["journal_witness"].(M)["checkpoint_id"].(string)
	raw, ok := journalCheckpoints[id]
	if !ok {
		panic("missing constructed prior checkpoint")
	}
	v.Fixture["seen"].(M)[id] = raw
}

// Registry witnesses are constructed independently of both verifiers. Each
// negative keeps a nearby accepted control; all signatures are real unless
// the named claim is specifically the invalid signature.
func registryVectors() {
	serviceVectors()
	journalVectors()
	reissueVectors()
	journalPublishVectors()
	capacityVectors()
	registryOrderVectors()
	registryDomainVectors()
	journalAnchorVectors()
	for _, kind := range []string{"journal-entry/1", "checkpoint/1"} {
		v := Vector{Mode: "signer", Input: M{"preimage": b64(append([]byte(domain(kind)+"\n"), canonical(M{})...))}, Fixture: M{}}
		add("N-REG-signer-"+kind[:len(kind)-2], "The new exact registry tag never enters the message signer.", "PS1", "signer_domain_refused", v)
	}
}
func serviceBase() Vector {
	v := reviewSource("PG1")
	v.Fixture["service_authority"] = M{"key": keys[0].ID, "purpose": "grant-service", "owner": "owner-a"}
	b := M{"type": "attestation/1", "issuer": keys[0].ID, "subject": M{"algorithm": "Ed25519", "key_id": keys[3].ID, "public_bytes": keys[3].ID[len("ed25519:"):]}, "key_class": "service", "purpose": "grant-service", "roles": []any{"author"}, "actions": []any{"grant.sign"}, "iat": "2026-01-01T00:00:00Z", "exp": "2026-01-02T00:00:00Z", "binding": M{"owner": "owner-a"}}
	v.Fixture["service_attestations"] = M{keys[3].ID: evidenceWire(b, keys[0])}
	root := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
	root["issuer"], root["subject"], root["parent"], root["depth"] = keys[0].ID, keys[3].ID, nil, 1
	root["actions"] = []any{"agent.spawn", "credential.lease"}
	root["targets"] = []any{M{"kind": "station", "id": "team/*"}, target("team/*")}
	r := envelope(root, keys[0], "author")
	leaf := decode(wire(r))["body"].(M)
	leaf["issuer"], leaf["subject"], leaf["parent"], leaf["depth"] = keys[3].ID, keys[2].ID, r["id"], 0
	leaf["actions"], leaf["targets"] = []any{"credential.lease"}, []any{target("team/member")}
	v.Input["chain"] = []any{wire(envelope(leaf, keys[3], "author")), wire(r)}
	return v
}
func serviceRecord(v *Vector, edit func(M)) {
	rows := v.Fixture["service_attestations"].(M)
	b := decode(rows[keys[3].ID].(string))["body"].(M)
	edit(b)
	rows[keys[3].ID] = evidenceWire(b, keys[0])
}
func serviceParent(v *Vector, edit func(M)) {
	chain := v.Input["chain"].([]any)
	b := decode(chain[1].(string))["body"].(M)
	edit(b)
	p := envelope(b, keys[0], "author")
	leaf := decode(chain[0].(string))["body"].(M)
	leaf["parent"] = p["id"]
	chain[0], chain[1] = wire(envelope(leaf, keys[3], "author")), wire(p)
}
func serviceVectors() {
	for _, tc := range []struct {
		id, claim, code string
		edit            func(*Vector)
	}{
		{"no-parent", "Service attestation cannot replace its missing parent grant.", "grant_root_unknown", func(v *Vector) {
			c := v.Input["chain"].([]any)
			b := decode(c[0].(string))["body"].(M)
			b["parent"] = nil
			v.Input["chain"] = []any{wire(envelope(b, keys[3], "author"))}
		}},
		{"agent-profile", "A root-signed agent profile is not a grant-service profile.", "key_binding_invalid", func(v *Vector) {
			serviceRecord(v, func(b M) { b["key_class"], b["purpose"], b["actions"] = "agent", "swarma-msg", []any{"message.sign"} })
		}},
		{"parent-expired", "An individually current leaf cannot bypass an expired service parent; G2 precedes G4.", "expired", func(v *Vector) {
			serviceParent(v, func(b M) { b["exp"], b["expires"] = "2026-01-01T00:01:00Z", "2026-01-01T00:01:00Z" })
		}},
		{"parent-revoked", "Revoking a parent grant id refuses an otherwise current service leaf.", "revoked", func(v *Vector) {
			id := decode(v.Input["chain"].([]any)[1].(string))["id"]
			setGrantEntries(v, []any{M{"kind": "record", "id": id, "from": v.Fixture["now"]}})
		}},
		{"key-revoked", "Revoking the service key refuses its otherwise valid attestation and chain.", "revoked", func(v *Vector) {
			setGrantEntries(v, []any{M{"kind": "key", "id": keys[3].ID, "from": v.Fixture["now"]}})
		}},
		{"wider-action", "A service leaf cannot add an action outside its parent grant.", "grant_not_narrowing", func(v *Vector) {
			c := v.Input["chain"].([]any)
			b := decode(c[0].(string))["body"].(M)
			b["actions"], b["targets"] = []any{"message.deliver"}, []any{M{"kind": "station", "id": "team/member"}}
			c[0] = wire(envelope(b, keys[3], "author"))
		}},
		{"parent-depth-zero", "An attested service cannot delegate from a depth-zero parent.", "grant_not_narrowing", func(v *Vector) { serviceParent(v, func(b M) { b["depth"] = 0 }) }},
		{"owner", "Signed and protected service owners must match.", "key_binding_invalid", func(v *Vector) { serviceRecord(v, func(b M) { b["binding"] = M{"owner": "other-owner"} }) }},
		{"owner-missing", "A service owner never defaults from signed bytes.", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture["service_authority"].(M), "owner") }},
		{"purpose", "An ordinary root pin does not select the service attestation purpose.", "key_binding_invalid", func(v *Vector) { v.Fixture["service_authority"].(M)["purpose"] = "other" }},
		{"actions", "Service attestation admits exactly grant.sign, no message-signing action.", "key_binding_invalid", func(v *Vector) { serviceRecord(v, func(b M) { b["actions"] = []any{"grant.sign", "message.sign"} }) }},
		{"subject", "Service attestation key derivation must equal the requested service key.", "key_binding_invalid", func(v *Vector) { serviceRecord(v, func(b M) { b["subject"].(M)["key_id"] = keys[1].ID }) }},
		{"attestation-expired", "A current delegation cannot revive expired service identity.", "key_binding_invalid", func(v *Vector) { serviceRecord(v, func(b M) { b["exp"] = "2026-01-01T00:01:00Z" }) }},
		{"role-collision", "A protected current-agent key cannot also select the service role.", "key_binding_invalid", func(v *Vector) { v.Fixture["active_generations"].(M)[keys[3].ID] = M{} }},
		{"missing-record", "Missing required service evidence refuses without a permissive identity default.", "key_binding_unavailable", func(v *Vector) { v.Fixture["service_attestations"].(M)[keys[3].ID] = nil }},
	} {
		v := serviceBase()
		tc.edit(&v)
		add("N-SVC-"+tc.id, tc.claim, "P-SVC-chain", tc.code, v)
	}

	v := serviceBase()
	rows := v.Fixture["service_attestations"].(M)
	b := decode(rows[keys[3].ID].(string))["body"].(M)
	b["issuer"] = keys[3].ID
	rows[keys[3].ID] = evidenceWire(b, keys[3])
	add("N-SVC-sign-attestation", "A valid service signature cannot replace its pinned grant-owner attestation issuer.", "P-SVC-chain", "key_binding_invalid", v)
	v = serviceBase()
	row := v.Fixture["revocations"].(M)[keys[0].ID].(M)
	b = decode(row["snapshot"].(string))["body"].(M)
	b["issuer"] = keys[3].ID
	row["snapshot"] = evidenceWire(b, keys[3])
	add("N-SVC-sign-revocation", "A service cannot sign its own revocation domain even with valid signature math.", "P-SVC-chain", "key_binding_invalid", v)
	v = serviceBase()
	ref := v.Fixture["agent_attestation_ids"].(M)[keys[2].ID].(string)
	v.Fixture["service_attestations"].(M)[keys[3].ID] = v.Fixture["attestations"].(M)[ref]
	add("N-SVC-agent-evidence", "A genuine purpose-5 agent attestation is never service identity evidence.", "P-SVC-chain", "key_binding_invalid", v)
	v = reviewSource("PO1")
	svc := serviceBase()
	v.Fixture["service_attestations"], v.Fixture["service_authority"] = svc.Fixture["service_attestations"], svc.Fixture["service_authority"]
	v.Input["envelope"] = wire(envelope(body(v), keys[3], "approver"))
	add("N-SVC-act", "A service signature never acquires the operator-act approver profile.", "PO1", "signature_profile_invalid", v)
	v = journalBase()
	svc = serviceBase()
	delete(v.Fixture, "enrollment_publisher")
	v.Fixture["service_attestations"], v.Fixture["service_authority"] = svc.Fixture["service_attestations"], svc.Fixture["service_authority"]
	b = decode(v.Input["checkpoint"].(string))["body"].(M)
	b["registry"] = keys[3].ID
	v.Input["checkpoint"] = wire(envelope(b, keys[3], "author"))
	add("N-SVC-checkpoint", "A valid service signature cannot replace the registry-owner checkpoint root.", "P-JRN-genesis", "checkpoint_invalid", v)
	v = serviceBase()
	add("P-SVC-chain", "Root delegates both registered rights with depth1 to an attested service; service narrows to an agent credential leaf with depth0.", "", "accept", v)
	v = reviewSource("PN02")
	svc = serviceBase()
	v.Fixture["service_attestations"], v.Fixture["service_authority"] = svc.Fixture["service_attestations"], svc.Fixture["service_authority"]
	b = body(v)
	b["author"] = keys[3].ID
	v.Fixture["known_keys"] = []any{keys[3].ID}
	v.Input["envelope"] = wire(envelope(b, keys[3], "author"))
	add("N-SVC-message", "An attested service has no message author profile, even with a valid signature and admission-list entry.", "PN02", "signature_profile_invalid", v)
}
func setGrantEntries(v *Vector, entries []any) {
	r := v.Fixture["revocations"].(M)[keys[0].ID].(M)
	b := decode(r["snapshot"].(string))["body"].(M)
	b["entries"] = entries
	r["snapshot"] = evidenceWire(b, keys[0])
}
func entryRecord(seq int, prev any, at, op, kind string) M {
	b := M{"type": "journal-entry/1", "registry": keys[7].ID, "owner": "owner-a", "seq": seq, "prev": prev, "at": at, "op": op, "record_type": kind, "record": digest([]byte("opaque stored signed record " + kind))}
	return M{"version": "swarm-envelope/2", "body": b, "id": digest(append([]byte(domain("journal-entry/1")+"\n"), canonical(b)...))}
}
func journalBase() Vector {
	v := reviewSource("PG1")
	v.Mode = "journal"
	v.Input = M{}
	v.Fixture["registry_owner"] = "owner-a"
	v.Fixture["commit_signing_key"], v.Fixture["enrollment_publisher"] = keys[1].ID, keys[3].ID
	a := entryRecord(1, nil, "2026-01-01T00:00:00Z", "add", "enrollment/1")
	b := entryRecord(2, a["id"], "2026-01-01T00:00:30Z", "revoke", "attestation/1")
	v.Input["entries"] = []any{wire(a), wire(b)}
	snap := decode(v.Fixture["revocations"].(M)[keys[7].ID].(M)["snapshot"].(string))["id"]
	cp := M{"type": "checkpoint/1", "registry": keys[7].ID, "owner": "owner-a", "seq": 2, "head": b["id"], "at": "2026-01-01T00:01:00Z", "snapshot": snap}
	v.Input["checkpoint"] = rememberJournalCheckpoint(envelope(cp, keys[7], "author"))
	journalAnchor(&v, 1, a["id"], nil)
	return v
}

// The caller has already verified these six projection facts; this builder
// creates real checkpoint IDs independently and does not parse witness wire.
func journalAnchor(v *Vector, seq int, head, previous any) {
	b := decode(v.Input["checkpoint"].(string))["body"].(M)
	b["seq"], b["head"] = seq, head
	cp := envelope(b, keys[7], "author")
	rememberJournalCheckpoint(cp)
	v.Fixture["journal_witness"] = M{"registry_id": keys[7].ID, "owner": "owner-a", "registry_seq": seq, "registry_head": head, "checkpoint_id": cp["id"], "previous_checkpoint_id": previous}
}
func journalCheckpoint(v *Vector, edit func(M)) {
	b := decode(v.Input["checkpoint"].(string))["body"].(M)
	edit(b)
	v.Input["checkpoint"] = rememberJournalCheckpoint(envelope(b, keys[7], "author"))
}
func journalEntry(v *Vector, position int, edit func(M)) {
	a := v.Input["entries"].([]any)
	e := decode(a[position].(string))
	edit(e["body"].(M))
	a[position] = wire(e)
}
func journalVectors() {
	// Fully valid boundary chains ensure removing the count guard admits65,
	// rather than merely reaching a different malformed-input rejection.
	for _, n := range []int{65, 64} {
		v := journalBase()
		entries := []any{}
		var prev any
		for seq := 1; seq <= n; seq++ {
			e := entryRecord(seq, prev, "2026-01-01T00:00:00Z", "add", "grant/1")
			entries = append(entries, wire(e))
			prev = e["id"]
		}
		v.Input["entries"] = entries
		journalCheckpoint(&v, func(b M) { b["seq"], b["head"] = n, prev })
		journalAnchor(&v, 1, decode(entries[0].(string))["id"], nil)
		if n == 65 {
			add("N-JRN-entries65", "65otherwise valid hash-chain entries exceed the bounded suffix count before policy or crypto.", "P-JRN-entries64", "journal_malformed", v)
		} else {
			journalPrior(&v)
			add("P-JRN-entries64", "A fully valid64entry suffix reaches the exact permitted count boundary with a real checkpoint signature.", "", "accept", v)
		}
	}

	for _, tc := range []struct {
		id, claim, code string
		edit            func(M)
	}{
		{"seq-gap", "A correctly hashed suffix cannot skip a sequence number.", "journal_chain_broken", func(b M) { b["seq"] = 3 }},
		{"time-backward", "A correctly hashed entry cannot move journal time backward.", "journal_chain_broken", func(b M) { b["at"] = "2025-12-31T23:59:59Z" }},
		{"time-after-checkpoint", "Journal entry time cannot exceed its authenticated checkpoint time.", "journal_chain_broken", func(b M) { b["at"] = "2026-01-01T00:01:01Z" }},
		{"entry-owner", "An otherwise correctly hashed entry cannot change protected owner scope.", "journal_entry_invalid", func(b M) { b["owner"] = "other-owner" }},
		{"entry-registry", "An otherwise correctly hashed entry cannot change registry scope.", "journal_entry_invalid", func(b M) { b["registry"] = keys[0].ID }},
	} {
		v := journalBase()
		entries := v.Input["entries"].([]any)
		e := decode(entries[1].(string))
		b := e["body"].(M)
		tc.edit(b)
		e["id"] = digest(append([]byte(domain("journal-entry/1")+"\n"), canonical(b)...))
		entries[1] = wire(e)
		journalCheckpoint(&v, func(b M) { b["head"] = e["id"] })
		if tc.code == "journal_entry_invalid" || tc.code == "journal_chain_broken" {
			journalPrior(&v)
		}
		add("N-JRN-"+tc.id, tc.claim, "P-JRN-genesis", tc.code, v)
	}

	for _, tc := range []struct {
		id, claim, code string
		edit            func(*Vector)
	}{
		{"entry-id", "Unsigned journal content must match its hash-bound id.", "journal_entry_invalid", func(v *Vector) { journalEntry(v, 1, func(b M) { b["record"] = digest([]byte("substitution")) }) }},
		{"signed-entry", "An individually signed entry is outside the closed unsigned format.", "journal_malformed", func(v *Vector) {
			a := v.Input["entries"].([]any)
			e := decode(a[0].(string))
			e["signatures"] = []any{}
			a[0] = wire(e)
		}},
		{"operation", "Journal operations form a closed add/revoke vocabulary.", "journal_malformed", func(v *Vector) { journalEntry(v, 0, func(b M) { b["op"] = "update" }) }},
		{"record-type", "The registry journal cannot introduce recovery or arbitrary records.", "journal_malformed", func(v *Vector) { journalEntry(v, 0, func(b M) { b["record_type"] = "recovery/1" }) }},
		{"seq-type", "Boolean seq is not safe-integer sequence1.", "journal_malformed", func(v *Vector) { journalEntry(v, 0, func(b M) { b["seq"] = true }) }},
		{"witness-missing", "A missing witness never bootstraps an empty journal implicitly.", "journal_unavailable", func(v *Vector) { delete(v.Fixture, "journal_witness") }},
		{"witness-scope", "A witness for another owner cannot fence this journal.", "journal_witness_invalid", func(v *Vector) { v.Fixture["journal_witness"].(M)["owner"] = "other-owner" }},
		{"witness-null", "Available null witness is unavailable, never genesis.", "journal_unavailable", func(v *Vector) { v.Fixture["journal_witness"] = nil }},
		{"witness-bool", "A boolean registry_seq is not a positive safe integer.", "journal_witness_invalid", func(v *Vector) { v.Fixture["journal_witness"].(M)["registry_seq"] = false }},
		{"checkpoint-id", "Checkpoint content-id substitution refuses despite otherwise valid record shape.", "checkpoint_invalid", func(v *Vector) {
			e := decode(v.Input["checkpoint"].(string))
			e["id"] = digest([]byte("wrong"))
			v.Input["checkpoint"] = wire(e)
		}},
		{"checkpoint-signature", "Checkpoint root signature is verified rather than trusting its registry header.", "checkpoint_invalid", func(v *Vector) {
			e := decode(v.Input["checkpoint"].(string))
			s := e["signatures"].([]any)[0].(M)
			raw := unb64(s["sig"].(string))
			raw[0] ^= 1
			s["sig"] = b64(raw)
			v.Input["checkpoint"] = wire(e)
		}},
		{"checkpoint-role", "Only one registry-author checkpoint signature is admitted.", "checkpoint_invalid", func(v *Vector) {
			e := decode(v.Input["checkpoint"].(string))
			e["signatures"].([]any)[0].(M)["role"] = "approver"
			v.Input["checkpoint"] = wire(e)
		}},
		{"snapshot-ref", "A checkpoint must bind the exact supplied current registry snapshot.", "checkpoint_snapshot_invalid", func(v *Vector) { journalCheckpoint(v, func(b M) { b["snapshot"] = digest([]byte("other snapshot")) }) }},
		{"snapshot-stale", "A valid checkpoint cannot make a stale registry snapshot current.", "journal_unavailable", func(v *Vector) {
			v.Fixture["now"], v.Fixture["watermark"] = "2026-01-01T00:02:01Z", "2026-01-01T00:02:01Z"
		}},
		{"checkpoint-future", "A future checkpoint cannot bypass protected min-time admission.", "journal_unavailable", func(v *Vector) { journalCheckpoint(v, func(b M) { b["at"] = "2026-01-01T00:01:01Z" }) }},
		{"owner-missing", "Protected registry owner is required before checkpoint admission.", "journal_unavailable", func(v *Vector) { delete(v.Fixture, "registry_owner") }},
		{"commit-overlap", "The repository commit signer cannot be the registry record signer.", "journal_invalid", func(v *Vector) { v.Fixture["commit_signing_key"] = keys[7].ID }},
		{"publisher-overlap", "An enrollment publisher cannot become the online registry checkpoint signer.", "journal_invalid", func(v *Vector) { v.Fixture["enrollment_publisher"] = keys[7].ID }},
		{"commit-publisher-overlap", "Repository commit and offline enrollment-publisher keys are separate roles.", "journal_invalid", func(v *Vector) { v.Fixture["commit_signing_key"] = v.Fixture["enrollment_publisher"] }},
		{"fork", "Two valid current same-seq checkpoints with different heads are explicit fork evidence.", "journal_fork", func(v *Vector) {
			e := decode(v.Input["checkpoint"].(string))
			b := e["body"].(M)
			b["head"] = digest([]byte("other head"))
			v.Input["conflict"] = wire(envelope(b, keys[7], "author"))
		}},
		{"conflict-checkpoint", "Two valid checkpoints with the same seq and head but different content ids are fork evidence.", "journal_fork", func(v *Vector) {
			b := decode(v.Input["checkpoint"].(string))["body"].(M)
			b["at"] = "2026-01-01T00:01:01Z"
			v.Fixture["now"], v.Fixture["watermark"] = b["at"], b["at"]
			v.Input["conflict"] = wire(envelope(b, keys[7], "author"))
		}},
		{"forged-fork", "Corrupt fork evidence cannot be treated as a valid fork or ignored.", "checkpoint_invalid", func(v *Vector) {
			e := decode(v.Input["checkpoint"].(string))
			e["id"] = digest([]byte("forged"))
			v.Input["conflict"] = wire(e)
		}},
		{"witness-fork", "Same-seq head disagreement with the protected witness is a fork.", "journal_fork", func(v *Vector) {
			journalAnchor(v, 2, digest([]byte("witness head")), v.Fixture["journal_witness"].(M)["checkpoint_id"])
		}},
		{"rollback", "An earlier checkpoint cannot roll back an external witness.", "journal_rollback", func(v *Vector) {
			journalAnchor(v, 3, digest([]byte("later")), v.Fixture["journal_witness"].(M)["checkpoint_id"])
		}},
		{"checkpoint-fork", "Same sequence and head with a different checkpoint content id is a fork.", "journal_fork", func(v *Vector) {
			previous := v.Fixture["journal_witness"].(M)["checkpoint_id"]
			cp := decode(v.Input["checkpoint"].(string))["body"].(M)
			journalAnchor(v, 2, cp["head"], previous)
			alternative := decode(v.Input["checkpoint"].(string))["body"].(M)
			alternative["at"] = "2026-01-01T00:01:01Z"
			v.Fixture["now"], v.Fixture["watermark"] = alternative["at"], alternative["at"]
			v.Fixture["journal_witness"].(M)["checkpoint_id"] = envelope(alternative, keys[7], "author")["id"]
		}},
		{"witness-registry", "A projection for another registry root is invalid.", "journal_witness_invalid", func(v *Vector) { v.Fixture["journal_witness"].(M)["registry_id"] = keys[0].ID }},
		{"witness-extra", "A full wire projection is not the exact six-field interface fact.", "journal_witness_invalid", func(v *Vector) { v.Fixture["journal_witness"].(M)["checkpoint_time"] = v.Fixture["now"] }},
		{"witness-checkpoint-missing", "Every verified projection includes the exact checkpoint content id.", "journal_witness_invalid", func(v *Vector) { delete(v.Fixture["journal_witness"].(M), "checkpoint_id") }},
		{"witness-previous", "A malformed predecessor cannot qualify as a verified projection.", "journal_witness_invalid", func(v *Vector) { v.Fixture["journal_witness"].(M)["previous_checkpoint_id"] = false }},
		{"chain-prev", "Every entry prev must bind the immediately preceding content id.", "journal_chain_broken", func(v *Vector) {
			a := v.Input["entries"].([]any)
			b := decode(a[1].(string))["body"].(M)
			b["prev"] = digest([]byte("unrelated"))
			e := M{"version": "swarm-envelope/2", "body": b, "id": digest(append([]byte(domain("journal-entry/1")+"\n"), canonical(b)...))}
			a[1] = wire(e)
			journalCheckpoint(v, func(b M) { b["head"] = e["id"] })
		}},
		{"final-head", "A signed checkpoint head must equal the verified suffix head.", "journal_chain_broken", func(v *Vector) { journalCheckpoint(v, func(b M) { b["head"] = digest([]byte("missing head")) }) }},
	} {
		v := journalBase()
		tc.edit(&v)
		if tc.code == "journal_entry_invalid" || tc.code == "journal_chain_broken" {
			journalPrior(&v)
		}
		add("N-JRN-"+tc.id, tc.claim, "P-JRN-genesis", tc.code, v)
	}
	v := journalBase()
	journalPrior(&v)
	add("P-JRN-genesis", "An already verified genesis checkpoint fact anchors unsigned entries and a fresh descendant checkpoint without re-signing referenced enrollment.", "", "accept", v)
	v = journalBase()
	a := v.Input["entries"].([]any)
	anchor := decode(a[1].(string))
	journalAnchor(&v, 2, anchor["id"], v.Fixture["journal_witness"].(M)["checkpoint_id"])
	next := entryRecord(3, anchor["id"], "2026-01-01T00:00:45Z", "add", "grant/1")
	v.Input["entries"] = []any{wire(anchor), wire(next)}
	journalCheckpoint(&v, func(b M) { b["seq"], b["head"] = 3, next["id"] })
	journalPrior(&v)
	add("P-JRN-suffix", "A required authenticated anchor orders a bounded suffix after a witnessed checkpoint without replaying genesis.", "", "accept", v)
	v = journalBase()
	cp := decode(v.Input["checkpoint"].(string))["body"].(M)
	journalAnchor(&v, 2, cp["head"], v.Fixture["journal_witness"].(M)["checkpoint_id"])
	v.Input["entries"] = []any{}
	add("P-JRN-retransmit", "An identical witnessed checkpoint head admits an empty suffix with current signed snapshot evidence.", "", "accept", v)
}

// A reissue changes issued_at, hence content ID, even if cumulative entries
// are unchanged. These are format witnesses, not live transaction qualification.
func reissueBase() Vector {
	v := journalBase()
	row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
	snapshot := decode(row["snapshot"].(string))["body"].(M)
	snapshot["issued_at"] = "2026-01-01T00:01:20Z"
	row["snapshot"] = evidenceWire(snapshot, keys[7])
	v.Fixture["now"], v.Fixture["watermark"] = snapshot["issued_at"], snapshot["issued_at"]
	anchor := v.Fixture["journal_witness"].(M)["registry_head"]
	entry := entryRecord(2, anchor, snapshot["issued_at"].(string), "add", "revocation/1")
	b := entry["body"].(M)
	b["record"] = decode(row["snapshot"].(string))["id"]
	entry["id"] = digest(append([]byte(domain("journal-entry/1")+"\n"), canonical(b)...))
	v.Input["entries"] = []any{wire(entry)}
	journalCheckpoint(&v, func(cp M) { cp["head"], cp["at"], cp["snapshot"] = entry["id"], snapshot["issued_at"], b["record"] })
	return v
}
func reissueVectors() {
	v := reissueBase()
	previous := decode(journalBase().Input["checkpoint"].(string))["body"].(M)["snapshot"]
	journalCheckpoint(&v, func(b M) { b["snapshot"] = previous })
	add("N-JRN-reissue-old-snapshot", "A fresh reissue checkpoint cannot retain the previous snapshot content id.", "P-JRN-reissue", "checkpoint_snapshot_invalid", v)
	v = reissueBase()
	w := v.Fixture["journal_witness"].(M)
	v.Input["entries"] = []any{}
	journalCheckpoint(&v, func(b M) { b["seq"], b["head"] = w["registry_seq"], w["registry_head"] })
	add("N-JRN-reissue-no-entry", "A reissue cannot rewrite the witnessed checkpoint at the same sequence without a journal advance.", "P-JRN-reissue", "journal_fork", v)
	v = reissueBase()
	anchor := journalBase().Input["entries"].([]any)[0]
	v.Input["entries"] = append([]any{anchor}, v.Input["entries"].([]any)...)
	journalPrior(&v)
	add("P-JRN-reissue", "An unchanged revocation set reissued20seconds later has its own signed snapshot id, add entry and descendant checkpoint anchored to the prior verified projection.", "", "accept", v)
}
func capacityVectors() {
	for _, n := range []int{64, 65} {
		v := reviewSource("PG1")
		entries := []any{}
		for i := 0; i < n; i++ {
			private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(90 + i)}, 32)) // Synthetic capacity operands.
			id := "ed25519:" + b64(private.Public().(ed25519.PublicKey))
			entries = append(entries, M{"kind": "key", "id": id, "from": "2026-01-02T00:00:00Z"})
		}
		setGrantEntries(&v, entries)
		if n == 64 {
			add("P-CAP-64", "A complete64entry key snapshot that fits8192bytes retains the original single-snapshot profile.", "", "accept", v)
		} else {
			add("N-CAP-65", "An over-capacity domain cannot use65entries or silently truncate its cumulative snapshot.", "P-CAP-64", "revocation_invalid", v)
		}
	}
	v := reviewSource("PG1")
	entries := []any{}
	for i := 0; i < 64; i++ {
		entries = append(entries, M{"kind": "record", "id": digest([]byte(fmt.Sprint("retained record", i))), "from": "2026-01-02T00:00:00Z"})
	}
	setGrantEntries(&v, entries)
	raw := unb64(v.Fixture["revocations"].(M)[keys[0].ID].(M)["snapshot"].(string))
	if len(raw) <= 8192 {
		panic("capacity byte-bound premise")
	}
	add("N-CAP-bytes", "Even64cumulative record entries can exceed the full received snapshot byte limit.", "P-CAP-64", "revocation_invalid", v)
	v = reviewSource("PG1")
	row := v.Fixture["revocations"].(M)[keys[0].ID].(M)
	raw = unb64(row["snapshot"].(string))
	raw = append(raw, bytes.Repeat([]byte{' '}, 8192-len(raw))...)
	row["snapshot"] = b64(raw)
	add("P-CAP-bytes8192", "Exactly8192received snapshot bytes retain the original complete-snapshot acceptance bound.", "", "accept", v)
	v = copyVector(v)
	v.Fixture["revocations"].(M)[keys[0].ID].(M)["snapshot"] = b64(append(raw, ' '))
	add("N-CAP-bytes8193", "8193received snapshot bytes refuse without a candidate plan.", "P-CAP-bytes8192", "revocation_invalid", v)

}

// Named extensions of the U order matrix preserve inherited sweep bytes.
// Each compound combines two real refusals and names the earlier J/K row.
func registryOrderVectors() {
	for _, tc := range []struct {
		id, claim, code string
		edit            func(*Vector)
	}{
		{"parse-policy", "J1 closed schema precedes missing protected registry policy.", "journal_malformed", func(v *Vector) {
			journalEntry(v, 0, func(b M) { b["extra"] = true })
			delete(v.Fixture, "registry_owner")
		}},
		{"policy-signature", "J2 missing owner precedes a bad checkpoint signature.", "journal_unavailable", func(v *Vector) { delete(v.Fixture, "registry_owner"); badCheckpoint(v) }},
		{"signature-witness", "J3 invalid checkpoint crypto precedes missing witness.", "checkpoint_invalid", func(v *Vector) { badCheckpoint(v); delete(v.Fixture, "journal_witness") }},
		{"snapshot-witness", "J3 snapshot reference precedes missing witness.", "checkpoint_snapshot_invalid", func(v *Vector) {
			journalCheckpoint(v, func(b M) { b["snapshot"] = digest([]byte("other")) })
			delete(v.Fixture, "journal_witness")
		}},
		{"witness-fork", "J4 absent witness precedes otherwise valid same-seq fork evidence.", "journal_unavailable", func(v *Vector) { delete(v.Fixture, "journal_witness"); forkCheckpoint(v) }},
		{"fork-entry", "J5 authenticated fork precedes J6 entry-id failure.", "journal_fork", func(v *Vector) {
			forkCheckpoint(v)
			journalEntry(v, 1, func(b M) { b["record"] = digest([]byte("wrong")) })
		}},
		{"rollback-entry", "J5 rollback precedes J6 entry-id failure.", "journal_rollback", func(v *Vector) {
			journalAnchor(v, 3, digest([]byte("later")), v.Fixture["journal_witness"].(M)["checkpoint_id"])
			journalEntry(v, 1, func(b M) { b["record"] = digest([]byte("wrong")) })
		}},
		{"candidate-conflict", "J3 authenticates the candidate before optional fork evidence.", "checkpoint_invalid", func(v *Vector) { badCheckpoint(v); forkCheckpoint(v) }},
	} {
		v := journalBase()
		tc.edit(&v)
		add("N-ORD-JRN-"+tc.id, tc.claim, "P-JRN-genesis", tc.code, v)
	}
	v := serviceBase()
	serviceRecord(&v, func(b M) { delete(b, "actions") })
	rows := v.Fixture["service_attestations"].(M)
	e := decode(rows[keys[3].ID].(string))
	s := e["signatures"].([]any)[0].(M)
	raw := unb64(s["sig"].(string))
	raw[0] ^= 1
	s["sig"] = b64(raw)
	rows[keys[3].ID] = wire(e)
	add("N-ORD-SVC-signature-profile", "K1 strict attestation signature precedes missing required service-profile fields.", "P-SVC-chain", "key_binding_invalid", v)
	v = serviceBase()
	delete(v.Fixture, "service_authority")
	serviceParent(&v, func(b M) { b["exp"], b["expires"] = "2026-01-01T00:01:00Z", "2026-01-01T00:01:00Z" })
	// The leaf is checked before its parent at G2, so missing leaf-issuer K1
	// evidence wins over a later parent T2 expiry.
	add("N-ORD-SVC-leaf-parent", "G2 completes leaf K1 before a later parent expiry.", "P-SVC-chain", "key_binding_unavailable", v)
}
func badCheckpoint(v *Vector) {
	e := decode(v.Input["checkpoint"].(string))
	sig := e["signatures"].([]any)[0].(M)
	raw := unb64(sig["sig"].(string))
	raw[0] ^= 1
	sig["sig"] = b64(raw)
	v.Input["checkpoint"] = wire(e)
}
func forkCheckpoint(v *Vector) {
	e := decode(v.Input["checkpoint"].(string))
	b := e["body"].(M)
	b["head"] = digest([]byte("fork head"))
	v.Input["conflict"] = wire(envelope(b, keys[7], "author"))
}

// Add only directed domain pairs involving the two registry tags; all72
// inherited pairs and their exact bytes stay unchanged. These are codec/math
// controls, not registry schema or authority admission.
func registryDomainVectors() {
	tags := []string{"swarma-msg/2", "swarma-waggle grant/1", "swarma-waggle operator-act/1", "swarma-attestation attestation/1", "swarma-attestation revocation/1", "swarma-registrar registration/1", "swarma-registrar enrollment/1", "swarma-credential-broker grant/1", "swarma-credential-broker revocation/1", domain("journal-entry/1"), domain("checkpoint/1")}
	positive := func(tag string) string {
		if tag == tags[9] {
			return "P-REG-domain-journal-entry"
		}
		if tag == tags[10] {
			return "P-REG-domain-checkpoint"
		}
		for _, v := range cases {
			if v.Mode == "domain" && v.Expected["code"] == "accept" && v.Fixture["expected_tag"] == tag {
				return v.ID
			}
		}
		panic("missing accepted domain neighbor")
	}
	probe := func(actual, expected string) Vector {
		raw := append([]byte(actual+"\n"), canonical(M{"type": "domain-math-only"})...)
		return Vector{Mode: "domain", Input: M{"preimage": b64(raw), "key": keys[0].ID, "sig": b64(sign(keys[0], raw))}, Fixture: M{"expected_tag": expected}}
	}
	for i, source := range tags {
		for j, target := range tags {
			if i == j || i < 9 && j < 9 {
				continue
			}
			add(fmt.Sprintf("N-REG-domain-%02d-%02d", i, j), "A valid raw signature under one exact registered domain never verifies as another domain; no body/authority profile is claimed.", positive(target), "domain_mismatch", probe(source, target))
		}
	}
	for _, tag := range tags[9:] {
		add(positive(tag), "The new exact registry domain has an ordinary valid raw signature-math control; record admission remains separate.", "", "accept", probe(tag, tag))
	}
}
