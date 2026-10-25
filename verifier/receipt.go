package verifier

import (
	"fmt"
	"strings"
)

// FreshnessReceipt is immutable, process-local evidence from successful F
// verification. Only the original pointer is usable. It has no wire format and
// grants neither persistence nor effects. Retain its SignedSnapshots Evidence and, for /2, SnapshotJournal Evidence.
type FreshnessReceipt struct {
	self                          *FreshnessReceipt
	premise                       *byte
	audit                         FreshnessAudit
	journalPremise                *byte
	snapshots                     map[string]string
	pins                          map[string]string
	pinFacts                      map[string]any
	index                         *SnapshotJournalState
	snapshot                      string
	witness, anchor               map[string]any
	issued, read, maxAge, expires int64
}

// FreshnessAudit is detached origin metadata, never admission evidence.
// Checkpoint IDs commit the corresponding registry heads.
type FreshnessAudit struct {
	RegistryCurrencyVersion                                  int               `json:"registry_currency_version,omitempty"`
	Snapshots                                                []SnapshotBinding `json:"snapshots,omitempty"`
	RegistryID, Owner, SnapshotID, CheckpointID, FreshnessID string
	Reanchored                                               bool
	OldFreshnessID, OldCheckpointID                          string
}

// Audit reports authentic origin, not currency or authority. Changing the
// returned value has no effect on the receipt.
func (r *FreshnessReceipt) Audit() (FreshnessAudit, bool) {
	if r == nil || r.self != r || r.premise == nil {
		return FreshnessAudit{}, false
	}
	a := r.audit
	a.Snapshots = append([]SnapshotBinding(nil), a.Snapshots...)
	return a, true
}

// MarshalJSON refuses persistence of process-local authority.
func (r FreshnessReceipt) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("freshness receipt has no wire format")
}

// UnmarshalJSON never constructs or changes receipt authority.
func (r *FreshnessReceipt) UnmarshalJSON([]byte) error {
	return fmt.Errorf("freshness receipt has no wire format")
}

func mintReceipt(c Context, tip, cp, snap map[string]any, age, read int64, reanchor *FreshnessReanchorPlan) *FreshnessReceipt {
	b, cb := obj(tip["body"]), obj(cp["body"])
	root := str(b["registry"])
	row := obj(obj(c.SignedSnapshots.value)[root])
	r := &FreshnessReceipt{premise: c.SignedSnapshots.identity, snapshot: string(row["snapshot"].([]byte)),
		issued: stamp(b["issued_at"]), read: read, maxAge: age,
		audit:   FreshnessAudit{RegistryID: root, Owner: str(b["owner"]), SnapshotID: str(snap["id"]), CheckpointID: str(cp["id"]), FreshnessID: str(tip["id"])},
		witness: map[string]any{"registry_id": root, "owner": b["owner"], "registry_seq": cb["seq"], "registry_head": cb["head"], "checkpoint_id": cp["id"]},
		anchor:  map[string]any{"registry_id": root, "owner": b["owner"], "publication_seq": b["publication_seq"], "freshness_id": tip["id"], "issued_at": b["issued_at"], "snapshot": snap["id"], "registry_seq": cb["seq"], "checkpoint_id": cp["id"]},
	}
	r.expires = min(r.issued+age, read+age)
	if reanchor != nil {
		r.audit.Reanchored = true
		r.audit.OldFreshnessID = reanchor.OldFreshnessID
		r.audit.OldCheckpointID = reanchor.OldCheckpointID
	}
	r.self = r
	return r
}

func (v Verifier) consumerFacts() facts {
	f := v.facts()
	c := v.context
	if c.FreshnessReceipt != nil || c.RequireFreshnessReceipt {
		f["_receiptContext"] = &c
	}
	return f
}

// Presence inspection deliberately defers wrong container types to syntax,
// so a different missing required binding still wins. Explicit nullable values
// remain present; their semantic constraints are checked in the syntax phase.
func receiptPresence(value any, names, nullable string) {
	m, ok := value.(map[string]any)
	if !ok {
		return
	}
	for _, name := range strings.Fields(names) {
		v, present := m[name]
		need(present && (v != nil || strings.Contains(" "+nullable+" ", " "+name+" ")), "freshness_receipt_unavailable")
	}
}

// R runs immediately after the existing trusted-time gate in consumer paths.
// Producers and VerifyJournal never receive this internal consumer marker.
func receiptGate(f facts, low, high int64) {
	c, ok := f["_receiptContext"].(*Context)
	if !ok {
		return
	}
	r := c.FreshnessReceipt
	if c.RegistryCurrencyVersion == 2 || r != nil && r.audit.RegistryCurrencyVersion == 2 {
		receiptGate2(f, low, high, c)
		return
	}
	need(r != nil, "freshness_receipt_unavailable")
	_, authentic := r.Audit()
	need(authentic && c.FreshnessMarginSeconds >= 0 && c.FreshnessMarginSeconds <= 60, "freshness_receipt_invalid")
	for _, name := range []string{"agent_revocation_root", "registry_owner", "journal_witness", "freshness_anchor", "witness_read_at", "revocations"} {
		need(f[name] != nil, "freshness_receipt_unavailable")
	}
	// R2 presence: inspect every required location before any syntax parser.
	receiptPresence(f["agent_revocation_root"], "key purpose attestation_root", "")
	receiptPresence(f["journal_witness"], "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id", "previous_checkpoint_id")
	receiptPresence(f["freshness_anchor"], "registry_id owner publication_seq freshness_id issued_at snapshot registry_seq checkpoint_id", "freshness_id issued_at")
	records, validRecords := f["revocations"].(map[string]any)
	if validRecords {
		value, present := records[r.audit.RegistryID]
		need(present && value != nil, "freshness_receipt_unavailable")
		receiptPresence(value, "snapshot", "")
	}
	// R2 syntax follows the complete presence stage.
	var policy, witness, anchor map[string]any
	var read int64
	mapped(func() bool {
		policy = evidenceExact(f["agent_revocation_root"], "key purpose attestation_root")
		key(policy["key"])
		key(policy["attestation_root"])
		need(policy["purpose"] == "registry-revocation", "freshness_receipt_invalid")
		text(f["registry_owner"], "freshness_receipt_invalid")
		// Parse against each fact's own scope first: foreign valid facts are binding
		// mismatches, whereas malformed facts are invalid.
		w := exact(f["journal_witness"], "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id", "freshness_receipt_invalid")
		key(w["registry_id"])
		text(w["owner"], "freshness_receipt_invalid")
		witness = journalWitness(f, str(w["registry_id"]), str(w["owner"]))
		a := exact(f["freshness_anchor"], "registry_id owner publication_seq freshness_id issued_at snapshot registry_seq checkpoint_id", "freshness_receipt_invalid")
		key(a["registry_id"])
		text(a["owner"], "freshness_receipt_invalid")
		anchor = freshnessAnchor(f, str(a["registry_id"]), str(a["owner"]))
		read = stamp(f["witness_read_at"])
		need(read <= low, "freshness_receipt_invalid")
		return true
	}, "*", "freshness_receipt_invalid")

	need(validRecords, "freshness_receipt_invalid")
	row, validRow := records[r.audit.RegistryID].(map[string]any)
	need(validRow, "freshness_receipt_invalid")
	raw, valid := row["snapshot"].([]byte)
	need(valid, "freshness_receipt_invalid")
	need(policy["key"] == r.audit.RegistryID && f["registry_owner"] == r.audit.Owner, "freshness_receipt_binding_mismatch")
	need(c.SignedSnapshots.identity == r.premise, "freshness_receipt_binding_mismatch")
	if explicit, exists := f["_receiptRoot"]; exists {
		need(explicit == r.audit.RegistryID, "freshness_receipt_binding_mismatch")
	}
	for name, value := range r.witness {
		need(equal(witness[name], value), "freshness_receipt_binding_mismatch")
	}
	for name, value := range r.anchor {
		need(equal(anchor[name], value), "freshness_receipt_binding_mismatch")
	}
	need(string(raw) == r.snapshot, "freshness_receipt_binding_mismatch")
	need(read >= r.read, "freshness_receipt_binding_mismatch")
	need(high < r.expires-c.FreshnessMarginSeconds, "freshness_receipt_expired")
}

func receiptSnapshot(f facts, root any, snap map[string]any) bool {
	c, ok := f["_receiptContext"].(*Context)
	if ok && c.FreshnessReceipt != nil && c.FreshnessReceipt.audit.RegistryCurrencyVersion == 2 {
		return receiptSnapshot2(c, root, snap)
	}
	if !ok || c.FreshnessReceipt == nil || root != c.FreshnessReceipt.audit.RegistryID {
		return false
	}
	need(snap["id"] == c.FreshnessReceipt.audit.SnapshotID, "freshness_receipt_binding_mismatch")
	return true
}
