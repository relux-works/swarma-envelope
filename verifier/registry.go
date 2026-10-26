package verifier

import "github.com/relux-works/waggle/record"

// Parse all bounded wire structures before any protected policy or signature.
func journalRecord(raw []byte, checkpoint bool) map[string]any {
	return mapped(func() map[string]any {
		parsed := must(record.Parse(raw, 8192, 16))
		outer := "version body id"
		if checkpoint {
			outer += " signatures"
		}
		e := exact(parsed, outer, "journal_malformed")
		need(isString(e["version"]), "journal_malformed")
		hashID(e["id"])
		names := "type registry owner seq at "
		if checkpoint {
			names += "head snapshot"
		} else {
			names += "prev op record_type record"
		}
		b := exact(e["body"], names, "journal_malformed")
		need(isString(b["type"]), "journal_malformed")
		key(b["registry"])
		text(b["owner"], "journal_malformed")
		need(isInt(b["seq"]) && num(b["seq"]) >= 1 && num(b["seq"]) <= 9007199254740991, "journal_malformed")
		stamp(b["at"])
		if checkpoint {
			hashID(b["head"])
			hashID(b["snapshot"])
			sigs, ok := e["signatures"].([]any)
			need(ok && len(sigs) >= 1 && len(sigs) <= 8, "journal_malformed")
			for _, v := range sigs {
				s := exact(v, "role key sig", "journal_malformed")
				need(isString(s["role"]) && isString(s["sig"]), "journal_malformed")
				key(s["key"])
				must(record.DecodeBase64(str(s["sig"]), 64))
			}
		} else {
			need((num(b["seq"]) == 1) == (b["prev"] == nil), "journal_malformed")
			if b["prev"] != nil {
				hashID(b["prev"])
			}
			need(b["op"] == "add" || b["op"] == "revoke", "journal_malformed")
			need(b["record_type"] == "attestation/1" || b["record_type"] == "grant/1" || b["record_type"] == "revocation/1" || b["record_type"] == "enrollment/1", "journal_malformed")
			hashID(b["record"])
		}
		return e
	}, "*", "journal_malformed")
}
func journalPolicy(f facts) (root, owner string) {
	mapped(func() bool {
		return mapped(func() bool {
			need(f["registry_owner"] != nil, "key_binding_unavailable")
			owner = text(f["registry_owner"], "key_binding_invalid")
			policy := evidenceExact(f["agent_revocation_root"], "key purpose attestation_root")
			root = str(policy["key"])
			snapshotPolicy(f, policy["key"])
			return true
		}, "key_binding_invalid", "journal_invalid")
	}, "key_binding_unavailable", "journal_unavailable")
	return
}
func checkpointSignature(e map[string]any, root, owner string) {
	b := obj(e["body"])
	mapped(func() bool {
		sigs := array(e["signatures"])
		need(len(sigs) == 1, "checkpoint_invalid")
		s := obj(sigs[0])
		need(e["version"] == "swarm-envelope/2" && b["type"] == "checkpoint/1" && b["registry"] == root && b["owner"] == owner && s["key"] == root && s["role"] == "author", "checkpoint_invalid")
		need(e["id"] == must(record.ContentID("checkpoint/1", b)), "checkpoint_invalid")
		signature := must(record.DecodeBase64(str(s["sig"]), 64))
		need(record.VerifySignature(root, signature, must(record.SigningPreimage("checkpoint/1", root, "author", b))) == nil, "checkpoint_invalid")
		return true
	}, "*", "checkpoint_invalid")
}
func checkpointAdmission(e map[string]any, root, owner string, f facts) {
	checkpointSignature(e, root, owner)
	b := obj(e["body"])
	low, high := times(f)
	at := stamp(b["at"])
	need(at <= low && high-at <= 60, "journal_unavailable")
	snap := mapped(func() map[string]any {
		return mapped(func() map[string]any { return snapshot(f, root, nil, nil) }, "key_binding_invalid", "checkpoint_snapshot_invalid")
	}, "key_binding_unavailable", "journal_unavailable")
	need(b["snapshot"] == snap["id"], "checkpoint_snapshot_invalid")
	row := obj(obj(f["revocations"])[root])
	need(stamp(obj(snap["body"])["issued_at"]) <= at && high-at <= num(row["max_age"]), "journal_unavailable")
}
func journalWitness(f facts, root, owner string) map[string]any {
	need(f["journal_witness"] != nil, "journal_unavailable")
	return mapped(func() map[string]any {
		w := exact(f["journal_witness"], "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id", "journal_witness_invalid")
		need(w["registry_id"] == root && w["owner"] == owner && isInt(w["registry_seq"]) && num(w["registry_seq"]) >= 1 && num(w["registry_seq"]) <= 9007199254740991, "journal_witness_invalid")
		hashID(w["registry_head"])
		hashID(w["checkpoint_id"])
		if w["previous_checkpoint_id"] != nil {
			hashID(w["previous_checkpoint_id"])
			need(w["previous_checkpoint_id"] != w["checkpoint_id"], "journal_witness_invalid")
		}
		return w
	}, "*", "journal_witness_invalid")
}

// Advancing calls retain the exact witnessed checkpoint in the protected id
// journal. Its authenticated time is distinct from the anchor entry's time.
func journalPriorCheckpoint(f facts, w map[string]any, root, owner string) map[string]any {
	need(f["id_journal_available"] == true && f["seen"] != nil, "journal_unavailable")
	seen, ok := f["seen"].(map[string]any)
	need(ok, "checkpoint_invalid")
	value := seen[str(w["checkpoint_id"])]
	need(value != nil, "journal_unavailable")
	raw, ok := value.([]byte)
	need(ok, "checkpoint_invalid")
	prior := mapped(func() map[string]any { return journalRecord(raw, true) }, "*", "checkpoint_invalid")
	checkpointSignature(prior, root, owner)
	b := obj(prior["body"])
	need(prior["id"] == w["checkpoint_id"] && equal(b["seq"], w["registry_seq"]) && b["head"] == w["registry_head"], "checkpoint_invalid")
	return prior
}

// VerifyJournal verifies a bounded oldest-first suffix and current checkpoint
// against Context.JournalWitness, with optional second checkpoint fork evidence.
// Witness facts must already be authenticated outside the registry's failure
// domain; this method defines no witness wire protocol. References convey no
// record/action authority. The /1 plan names only the exact verified checkpoint; /2 also inventories
// complete-prefix dependencies and returns its detached candidate index.
func (v Verifier) VerifyJournal(entries [][]byte, checkpoint, conflict []byte) Result {
	if v.context.RegistryCurrencyVersion != 0 && v.context.RegistryCurrencyVersion != 1 {
		return v.verifyJournal2(entries, checkpoint, conflict)
	}
	return decide(func() Plan {
		need(len(entries) <= 64, "journal_malformed")
		total := len(checkpoint) + len(conflict)
		for _, raw := range entries {
			need(len(raw) <= 8192, "journal_malformed")
			total += len(raw)
		}
		need(total <= 540672, "journal_malformed")
		currencyVersion(checkpoint, "checkpoint/1")
		if len(conflict) > 0 {
			currencyVersion(conflict, "checkpoint/1")
		}
		es := make([]map[string]any, len(entries))
		for i, raw := range entries {
			es[i] = journalRecord(raw, false)
		}
		cp := journalRecord(checkpoint, true)
		var other map[string]any
		if len(conflict) > 0 {
			other = journalRecord(conflict, true)
		}
		f := v.facts()
		root, owner := journalPolicy(f)
		checkpointAdmission(cp, root, owner, f)
		if other != nil {
			checkpointAdmission(other, root, owner, f)
		}
		w := journalWitness(f, root, owner)
		b := obj(cp["body"])
		if other != nil {
			o := obj(other["body"])
			need(b["seq"] != o["seq"] || (b["head"] == o["head"] && cp["id"] == other["id"]), "journal_fork")
		}
		need(!equal(b["seq"], w["registry_seq"]) || (equal(b["head"], w["registry_head"]) && cp["id"] == w["checkpoint_id"]), "journal_fork")
		need(num(b["seq"]) >= num(w["registry_seq"]), "journal_rollback")
		advancing := num(b["seq"]) > num(w["registry_seq"])
		if advancing {
			prior := journalPriorCheckpoint(f, w, root, owner)
			need(stamp(b["at"]) >= stamp(obj(prior["body"])["at"]), "journal_rollback")
			need(len(es) > 0 && num(obj(es[0]["body"])["seq"]) == num(w["registry_seq"]) && es[0]["id"] == w["registry_head"], "journal_anchor_required")
		}
		seq, head, at := num(w["registry_seq"]), w["registry_head"], int64(0)
		for i, e := range es {
			entry := obj(e["body"])
			need(e["version"] == "swarm-envelope/2" && entry["type"] == "journal-entry/1" && entry["registry"] == root && entry["owner"] == owner && e["id"] == must(record.ContentID("journal-entry/1", entry)), "journal_entry_invalid")
			when := stamp(entry["at"])
			// The required advancing anchor entry supplies its timestamp without
			// requiring a timestamp member in the caller's witness projection.
			if i == 0 && num(entry["seq"]) == seq {
				need(equal(e["id"], head) && when <= stamp(b["at"]), "journal_chain_broken")
				at = when
				continue
			}
			need(num(entry["seq"]) == seq+1 && equal(entry["prev"], head) && when >= at && when <= stamp(b["at"]), "journal_chain_broken")
			seq, head, at = num(entry["seq"]), e["id"], when
		}
		need(seq == num(b["seq"]) && equal(head, b["head"]), "journal_chain_broken")
		return plan([]map[string]any{cp}, f)
	})
}
