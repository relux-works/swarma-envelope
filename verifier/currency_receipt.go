package verifier

func currencyPinFacts(f facts) map[string]any {
	out := map[string]any{}
	for _, name := range []string{"root", "operator_root", "agent_revocation_root", "service_root", "commit_signing_key", "enrollment_publisher", "operator_owner", "service_authority"} {
		if value, ok := f[name]; ok {
			out[name] = value
		}
	}
	return out
}
func mintReceipt2(c Context, tip, cp map[string]any, set []SnapshotBinding, state *SnapshotJournalState, pins map[string]string, age, read int64, reanchor *FreshnessReanchorPlan) *FreshnessReceipt {
	b, cb := obj(tip["body"]), obj(cp["body"])
	root := str(b["registry"])
	r := &FreshnessReceipt{premise: c.SignedSnapshots.identity, journalPremise: c.SnapshotJournal.identity, snapshots: map[string]string{}, pins: map[string]string{}, index: currencyStateCopy(state), pinFacts: currencyPinFacts(New(c).facts()), issued: stamp(b["issued_at"]), read: read, maxAge: age}
	r.audit = FreshnessAudit{RegistryID: root, Owner: str(b["owner"]), CheckpointID: str(cp["id"]), FreshnessID: str(tip["id"]), RegistryCurrencyVersion: 2, Snapshots: append([]SnapshotBinding(nil), set...)}
	for role, k := range pins {
		r.pins[role] = k
	}
	for _, s := range set {
		raw := obj(obj(c.SignedSnapshots.value)[s.RootKeyID])["snapshot"].([]byte)
		r.snapshots[s.RootKeyID] = string(raw)
		if s.RootRole == "registry-owner" {
			r.audit.SnapshotID = s.SnapshotID
		}
	}
	r.witness = map[string]any{"registry_id": root, "owner": b["owner"], "registry_seq": cb["seq"], "registry_head": cb["head"], "checkpoint_id": cp["id"]}
	r.anchor = map[string]any{"registry_id": root, "owner": b["owner"], "publication_seq": b["publication_seq"], "freshness_id": tip["id"], "issued_at": b["issued_at"], "snapshots": b["snapshots"], "registry_seq": cb["seq"], "checkpoint_id": cp["id"]}
	r.expires = min(r.issued+age, read+age)
	if reanchor != nil {
		r.audit.Reanchored = true
		r.audit.OldFreshnessID = reanchor.OldFreshnessID
		r.audit.OldCheckpointID = reanchor.OldCheckpointID
	}
	r.self = r
	return r
}
func receiptGate2(f facts, low, high int64, c *Context) {
	r := c.FreshnessReceipt
	need(r != nil, "freshness_receipt_unavailable")
	_, authentic := r.Audit()
	need(authentic && c.FreshnessMarginSeconds >= 0 && c.FreshnessMarginSeconds <= 60, "freshness_receipt_invalid")
	for _, name := range []string{"agent_revocation_root", "registry_owner", "journal_witness", "freshness_anchor", "witness_read_at", "revocations", "snapshot_journal"} {
		need(f[name] != nil, "freshness_receipt_unavailable")
	}
	for name := range r.pinFacts {
		need(f[name] != nil, "freshness_receipt_unavailable")
	}
	// Entire R2 presence precedes syntax, preserving the inherited missing-first rule.
	receiptPresence(f["agent_revocation_root"], "key purpose attestation_root", "")
	receiptPresence(f["journal_witness"], "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id", "previous_checkpoint_id")
	receiptPresence(f["freshness_anchor"], "registry_id owner publication_seq freshness_id issued_at snapshots registry_seq checkpoint_id", "freshness_id issued_at")
	receiptPresence(f["snapshot_journal"], "anchor entries", "")
	if p, ok := f["snapshot_journal"].(map[string]any); ok {
		receiptPresence(p["anchor"], "version registry_id owner registry_seq registry_head checkpoint_id latest", "registry_head checkpoint_id")
		if a, ok := p["anchor"].(map[string]any); ok {
			if rows, ok := a["latest"].([]any); ok {
				for _, r := range rows {
					receiptPresence(r, "root_role root_key_id snapshot_id record_seq", "snapshot_id")
				}
			}
		}
	}
	records, valid := f["revocations"].(map[string]any)
	if valid {
		for k := range r.snapshots {
			value, ok := records[k]
			need(ok && value != nil, "freshness_receipt_unavailable")
			receiptPresence(value, "snapshot", "")
		}
	}
	var pins map[string]string
	var witness, anchor map[string]any
	var read int64
	mapped(func() bool {
		pins = currencyPins(f)
		p := evidenceExact(f["agent_revocation_root"], "key purpose attestation_root")
		key(p["attestation_root"])
		need(p["purpose"] == "registry-revocation", "freshness_receipt_invalid")
		text(f["registry_owner"], "freshness_receipt_invalid")
		w := exact(f["journal_witness"], "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id", "freshness_receipt_invalid")
		key(w["registry_id"])
		text(w["owner"], "freshness_receipt_invalid")
		witness = journalWitness(f, str(w["registry_id"]), str(w["owner"]))
		a := exact(f["freshness_anchor"], "registry_id owner publication_seq freshness_id issued_at snapshots registry_seq checkpoint_id", "freshness_receipt_invalid")
		key(a["registry_id"])
		text(a["owner"], "freshness_receipt_invalid")
		anchor, _, _ = currencyFreshAnchor(f, str(a["registry_id"]), str(a["owner"]))
		currencyProofShape(f["snapshot_journal"])
		read = stamp(f["witness_read_at"])
		need(read <= low, "freshness_receipt_invalid")
		need(valid, "freshness_receipt_invalid")
		for k := range r.snapshots {
			row, ok := records[k].(map[string]any)
			need(ok, "freshness_receipt_invalid")
			_, ok = row["snapshot"].([]byte)
			need(ok, "freshness_receipt_invalid")
		}
		return true
	}, "*", "freshness_receipt_invalid")
	need(c.RegistryCurrencyVersion == 2 && r.audit.RegistryCurrencyVersion == 2, "freshness_receipt_binding_mismatch")
	need(equal(pins, r.pins) && equal(currencyPinFacts(f), r.pinFacts) && f["registry_owner"] == r.audit.Owner, "freshness_receipt_binding_mismatch")
	need(c.SignedSnapshots.identity == r.premise && c.SnapshotJournal.identity == r.journalPremise, "freshness_receipt_binding_mismatch")
	for k, value := range r.witness {
		need(equal(witness[k], value), "freshness_receipt_binding_mismatch")
	}
	need(equal(anchor, r.anchor), "freshness_receipt_binding_mismatch")
	for k, value := range r.snapshots {
		need(string(obj(records[k])["snapshot"].([]byte)) == value, "freshness_receipt_binding_mismatch")
	}
	need(read >= r.read, "freshness_receipt_binding_mismatch")
	need(high < r.expires-c.FreshnessMarginSeconds, "freshness_receipt_expired")
}
func receiptSnapshot2(c *Context, root any, snap map[string]any) bool {
	for _, s := range c.FreshnessReceipt.audit.Snapshots {
		if s.RootKeyID == root {
			need(s.SnapshotID == snap["id"], "freshness_receipt_binding_mismatch")
			return true
		}
	}
	need(!c.RequireFreshnessReceipt, "freshness_receipt_unavailable")
	return false
}
