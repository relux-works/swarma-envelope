package verifier

func currencyFreshAnchor(f facts, root, owner string) (map[string]any, []SnapshotBinding, int) {
	need(f["freshness_anchor"] != nil, "freshness_unavailable")
	returnAnchor := obj(f["freshness_anchor"])
	if _, old := returnAnchor["snapshot"]; old {
		a := freshnessAnchor(f, root, owner)
		return a, []SnapshotBinding{{"registry-owner", root, str(a["snapshot"])}}, 1
	}
	a := exact(f["freshness_anchor"], "registry_id owner publication_seq freshness_id issued_at snapshots registry_seq checkpoint_id", "freshness_state_invalid")
	mapped(func() bool {
		need(a["registry_id"] == root && a["owner"] == owner && isInt(a["publication_seq"]) && num(a["publication_seq"]) >= 0 && num(a["publication_seq"]) <= 9007199254740991 && isInt(a["registry_seq"]) && num(a["registry_seq"]) >= 1 && num(a["registry_seq"]) <= 9007199254740991, "freshness_state_invalid")
		hashID(a["checkpoint_id"])
		if num(a["publication_seq"]) == 0 {
			need(a["freshness_id"] == nil && a["issued_at"] == nil, "freshness_state_invalid")
		} else {
			hashID(a["freshness_id"])
			stamp(a["issued_at"])
		}
		return true
	}, "*", "freshness_state_invalid")
	return a, currencyList(a["snapshots"], "freshness_state_invalid"), 2
}
func currencySnapshotBases(f facts, set []SnapshotBinding, cp map[string]any, unavailable, invalid string) ([]map[string]any, int64) {
	out := []map[string]any{}
	age := int64(60)
	for _, row := range set {
		var a int64
		e := mapped(func() map[string]any {
			return mapped(func() map[string]any { e, n := snapshotBase(f, row.RootKeyID); a = n; return e }, "key_binding_invalid", invalid)
		}, "key_binding_unavailable", unavailable)
		need(e["id"] == row.SnapshotID, invalid)
		need(stamp(obj(e["body"])["issued_at"]) <= stamp(obj(cp["body"])["at"]), unavailable)
		out = append(out, e)
		age = min(age, a)
	}
	return out, age
}
func currencyFreshIndex(f facts, root, owner string, pins map[string]string, cp map[string]any) (state *SnapshotJournalState) {
	defer func() {
		if x := recover(); x != nil {
			if code, ok := x.(refusal); ok {
				switch string(code) {
				case "journal_unavailable":
					panic(refusal("freshness_unavailable"))
				case "checkpoint_snapshot_invalid":
					panic(refusal("freshness_binding_mismatch"))
				default:
					panic(refusal("freshness_state_invalid"))
				}
			}
			panic(x)
		}
	}()
	return currencyDerive(f, root, owner, pins, currencyEntries(f), cp)
}
func (v Verifier) verifyFreshness2(chain [][]byte, checkpoint []byte, ids, keys []string, reanchor bool) Result {
	var receipt *FreshnessReceipt
	r := decide(func() Plan {
		// F1: bounded candidate structures, profile pin and whole-call capacity.
		need(len(chain) > 0, "freshness_unavailable")
		need(len(chain) <= 64, "freshness_malformed")
		need(len(checkpoint) <= 8192, "freshness_malformed")
		total := len(checkpoint)
		for _, raw := range chain {
			need(len(raw) <= 8192, "freshness_malformed")
			total += len(raw)
		}
		need(total <= 532480, "freshness_malformed")
		v.currencyCapacity(total, "freshness_malformed")
		for _, raw := range chain {
			currencyVersion(raw, "freshness/2")
		}
		currencyVersion(checkpoint, "checkpoint/2")
		es := make([]map[string]any, len(chain))
		for i, raw := range chain {
			es[i] = currencyWire(raw, false)
		}
		cp := mapped(func() map[string]any { return currencyWire(checkpoint, true) }, "*", "freshness_malformed")
		f := v.facts()
		need(v.context.RegistryCurrencyVersion == 0 || v.context.RegistryCurrencyVersion == 1 || v.context.RegistryCurrencyVersion == 2, "freshness_invalid")
		need(v.context.RegistryCurrencyVersion == 2, "registry_currency_version_mismatch")
		// F2 protected D30 roles and pins, never supplied by the list.
		var root, owner string
		mapped(func() bool {
			return mapped(func() bool { root, owner = journalPolicy(f); return true }, "journal_invalid", "freshness_invalid")
		}, "journal_unavailable", "freshness_unavailable")
		pins := mapped(func() map[string]string { return currencyPins(f) }, "*", "freshness_invalid")
		for _, e := range append(append([]map[string]any{}, es...), cp) {
			currencyPinList(currencyList(obj(e["body"])["snapshots"], "freshness_malformed"), pins, "freshness_invalid")
		}
		// F3 original registry math for every current-profile candidate.
		for _, e := range es {
			currencySignature(e, "freshness/2", root, owner, "freshness_signature_invalid")
		}
		currencySignature(cp, "checkpoint/2", root, owner, "checkpoint_invalid")
		tip := es[len(es)-1]
		b, cb := obj(tip["body"]), obj(cp["body"])
		issued := stamp(b["issued_at"])
		set := currencyList(b["snapshots"], "freshness_malformed")
		// F4 all selected root originals and independent cumulative premises.
		snaps, age := currencySnapshotBases(f, currencyList(cb["snapshots"], "freshness_malformed"), cp, "freshness_unavailable", "freshness_snapshot_invalid")
		low, high := times(f)
		need(stamp(cb["at"]) <= low, "freshness_unavailable")
		// F5 externally authenticated witness and read. No cached-success fallback.
		w := mapped(func() map[string]any {
			return mapped(func() map[string]any { return journalWitness(f, root, owner) }, "journal_witness_invalid", "freshness_witness_invalid")
		}, "journal_unavailable", "freshness_unavailable")
		need(f["witness_read_at"] != nil, "freshness_unavailable")
		read := mapped(func() int64 { return stamp(f["witness_read_at"]) }, "*", "freshness_witness_invalid")
		// F6 compare every signed list element, not only the registry snapshot.
		need(currencyEqual(set, currencyList(cb["snapshots"], "freshness_malformed")) && b["registry_seq"] == cb["seq"] && b["checkpoint_id"] == cp["id"], "freshness_binding_mismatch")
		// F6L derives every journal position, including omitted-root updates.
		state := currencyFreshIndex(f, root, owner, pins, cp)
		// F7 exact current authenticated prefix.
		need(num(b["registry_seq"]) <= num(w["registry_seq"]), "freshness_unavailable")
		need(num(b["registry_seq"]) >= num(w["registry_seq"]), "freshness_rollback")
		need(cp["id"] == w["checkpoint_id"] && cb["head"] == w["registry_head"], "freshness_fork")
		// F8 same lifetime rules, taking the minimum of INCLUDED root policies.
		need(issued <= low && high-issued <= age && stamp(cb["at"]) <= issued && read >= issued && read <= low && high-read <= age, "freshness_unavailable")
		a, oldset, oldversion := currencyFreshAnchor(f, root, owner)
		seq, prev := num(a["publication_seq"]), a["freshness_id"]
		var when *int64
		if a["issued_at"] != nil {
			x := stamp(a["issued_at"])
			when = &x
		}
		registrySeq, checkpointID := num(a["registry_seq"]), a["checkpoint_id"]
		if oldversion == 1 {
			need(num(cb["seq"]) > registrySeq, "freshness_binding_mismatch")
		}
		var audit *FreshnessReanchorPlan
		if reanchor {
			need(seq > 0 && when != nil, "freshness_state_invalid")
			need(num(b["registry_seq"]) >= registrySeq, "freshness_rollback")
			if num(b["registry_seq"]) == registrySeq {
				need(b["checkpoint_id"] == checkpointID, "freshness_fork")
				need(currencyEqual(set, oldset), "freshness_binding_mismatch")
			} else {
				need(b["checkpoint_id"] != checkpointID, "freshness_binding_mismatch")
			}
			need(num(b["publication_seq"]) > seq && issued > *when, "freshness_rollback")
			audit = &FreshnessReanchorPlan{Reanchored: true, SkippedPublications: num(b["publication_seq"]) - seq - 1, OldFreshnessID: str(prev), NewFreshnessID: str(tip["id"]), OldCheckpointID: str(checkpointID), NewCheckpointID: str(cp["id"]), OldSnapshots: append([]SnapshotBinding(nil), oldset...), NewSnapshots: append([]SnapshotBinding(nil), set...), OldRegistryCurrencyVersion: oldversion, NewRegistryCurrencyVersion: 2}
		} else {
			for i, e := range es {
				p := obj(e["body"])
				n := num(p["publication_seq"])
				at := stamp(p["issued_at"])
				ps := currencyList(p["snapshots"], "freshness_malformed")
				need(n >= seq, "freshness_rollback")
				if n == seq {
					need(e["id"] == prev, "freshness_fork")
					need(i == 0 && when != nil && at == *when && num(p["registry_seq"]) == registrySeq && p["checkpoint_id"] == checkpointID && currencyEqual(ps, oldset), "freshness_state_invalid")
					continue
				}
				need(n == seq+1, "freshness_gap")
				need(num(p["registry_seq"]) >= registrySeq, "freshness_rollback")
				same := num(p["registry_seq"]) == registrySeq
				var expected any
				if same {
					need(p["checkpoint_id"] == checkpointID, "freshness_fork")
					expected = prev
				} else {
					need(p["checkpoint_id"] != checkpointID, "freshness_binding_mismatch")
				}
				need(equal(p["prev"], expected), "freshness_gap")
				need(when == nil || at > *when, "freshness_time_invalid")
				if same {
					need(currencyEqual(ps, oldset), "freshness_binding_mismatch")
				}
				seq, prev, registrySeq, checkpointID = n, e["id"], num(p["registry_seq"]), p["checkpoint_id"]
				when = &at
				oldset = ps
			}
		}
		// F9 queries remain registry-domain, not a blanket foreign-root verdict.
		mapped(func() bool {
			need(len(ids) <= 64 && len(keys) <= 64, "freshness_request_invalid")
			for _, id := range ids {
				hashID(id)
			}
			for _, k := range keys {
				key(k)
			}
			return true
		}, "*", "freshness_request_invalid")
		for i, row := range set {
			if row.RootRole == "registry-owner" {
				snapshotEntries(snapshotProof{entries: array(obj(snaps[i]["body"])["entries"]), high: high}, ids, keys)
			}
		}
		admitted := append(append(append([]map[string]any{}, es...), cp), snaps...)
		p := currencyPlan(admitted, state, f, currencyEntries(f))
		p.Reanchor = audit
		receipt = mintReceipt2(v.context, tip, cp, set, state, pins, age, read, audit)
		return p
	})
	if r.Code == "accept" {
		r.FreshnessReceipt = receipt
	}
	return r
}
func (v Verifier) verifyJournal2(entries [][]byte, checkpoint, conflict []byte) Result {
	return decide(func() Plan {
		need(len(entries) <= 64, "journal_malformed")
		need(len(checkpoint) <= 8192 && len(conflict) <= 8192, "journal_malformed")
		total := len(checkpoint) + len(conflict)
		for _, raw := range entries {
			need(len(raw) <= 8192, "journal_malformed")
			total += len(raw)
		}
		need(total <= 540672, "journal_malformed")
		v.currencyCapacity(total, "journal_malformed")
		// Both current checkpoint profiles precede either closed-body parse.
		currencyVersion(checkpoint, "checkpoint/2")
		if len(conflict) > 0 {
			currencyVersion(conflict, "checkpoint/2")
		}
		for _, raw := range entries {
			journalRecord(raw, false)
		}
		cp := currencyWire(checkpoint, true)
		var other map[string]any
		if len(conflict) > 0 {
			other = currencyWire(conflict, true)
		}
		currencyProfile(v.context)
		need(v.context.RegistryCurrencyVersion == 2, "registry_currency_version_mismatch")
		f := v.facts()
		root, owner := journalPolicy(f)
		pins := mapped(func() map[string]string { return currencyPins(f) }, "*", "journal_invalid")
		for _, e := range []map[string]any{cp, other} {
			if e == nil {
				continue
			}
			set := currencyList(obj(e["body"])["snapshots"], "journal_malformed")
			currencyPinList(set, pins, "journal_invalid")
			currencySignature(e, "checkpoint/2", root, owner, "checkpoint_invalid")
			low, high := times(f)
			at := stamp(obj(e["body"])["at"])
			need(at <= low && high-at <= 60, "journal_unavailable")
			_, age := currencySnapshotBases(f, set, e, "journal_unavailable", "checkpoint_snapshot_invalid")
			need(high-at <= age, "journal_unavailable")
		}
		w := journalWitness(f, root, owner)
		b := obj(cp["body"])
		if other != nil {
			o := obj(other["body"])
			need(b["seq"] != o["seq"] || (b["head"] == o["head"] && cp["id"] == other["id"]), "journal_fork")
		}
		need(num(b["seq"]) >= num(w["registry_seq"]), "journal_rollback")
		if b["seq"] == w["registry_seq"] {
			need(b["head"] == w["registry_head"] && cp["id"] == w["checkpoint_id"], "journal_fork")
		}
		_, anchor := currencyAnchor(f, root, owner, pins)
		need(anchor.RegistrySeq == num(w["registry_seq"]) && anchor.RegistryHead == w["registry_head"] && anchor.CheckpointID == w["checkpoint_id"], "journal_invalid")
		// The explicit journal argument is authoritative; the Context suffix is for F.
		currencyEntries(f)
		state := currencyDerive(f, root, owner, pins, entries, cp)
		return currencyPlan([]map[string]any{cp}, state, f, entries)
	})
}
