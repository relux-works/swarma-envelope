package verifier

import "github.com/relux-works/waggle/record"

func freshnessWire(raw []byte) map[string]any {
	return mapped(func() map[string]any {
		e := exact(must(record.Parse(raw, 8192, 16)), "version body id signatures", "freshness_malformed")
		need(isString(e["version"]), "freshness_malformed")
		hashID(e["id"])
		b := exact(e["body"], "type registry owner publication_seq prev issued_at snapshot registry_seq checkpoint_id", "freshness_malformed")
		need(isString(b["type"]), "freshness_malformed")
		key(b["registry"])
		text(b["owner"], "freshness_malformed")
		for _, name := range []string{"publication_seq", "registry_seq"} {
			need(isInt(b[name]) && num(b[name]) >= 1 && num(b[name]) <= 9007199254740991, "freshness_malformed")
		}
		need(num(b["publication_seq"]) != 1 || b["prev"] == nil, "freshness_malformed")
		if b["prev"] != nil {
			hashID(b["prev"])
		}
		stamp(b["issued_at"])
		hashID(b["snapshot"])
		hashID(b["checkpoint_id"])
		sigs, ok := e["signatures"].([]any)
		need(ok && len(sigs) >= 1 && len(sigs) <= 8, "freshness_malformed")
		for _, v := range sigs {
			s := exact(v, "role key sig", "freshness_malformed")
			need(isString(s["role"]) && isString(s["sig"]), "freshness_malformed")
			key(s["key"])
			must(record.DecodeBase64(str(s["sig"]), 64))
		}
		return e
	}, "*", "freshness_malformed")
}
func freshnessSignature(e map[string]any, root, owner string) {
	mapped(func() bool {
		b := obj(e["body"])
		sigs := array(e["signatures"])
		need(len(sigs) == 1, "freshness_signature_invalid")
		s := obj(sigs[0])
		need(e["version"] == "swarm-envelope/2" && b["type"] == "freshness/1" && b["registry"] == root && b["owner"] == owner && s["key"] == root && s["role"] == "author", "freshness_signature_invalid")
		need(e["id"] == must(record.ContentID("freshness/1", b)), "freshness_signature_invalid")
		sig := must(record.DecodeBase64(str(s["sig"]), 64))
		need(record.VerifySignature(root, sig, must(record.SigningPreimage("freshness/1", root, "author", b))) == nil, "freshness_signature_invalid")
		return true
	}, "*", "freshness_signature_invalid")
}
func freshnessAnchor(f facts, root, owner string) map[string]any {
	need(f["freshness_anchor"] != nil, "freshness_unavailable")
	return mapped(func() map[string]any {
		a := exact(f["freshness_anchor"], "registry_id owner publication_seq freshness_id issued_at snapshot registry_seq checkpoint_id", "freshness_state_invalid")
		need(a["registry_id"] == root && a["owner"] == owner && isInt(a["publication_seq"]) && num(a["publication_seq"]) >= 0 && num(a["publication_seq"]) <= 9007199254740991 && isInt(a["registry_seq"]) && num(a["registry_seq"]) >= 1 && num(a["registry_seq"]) <= 9007199254740991, "freshness_state_invalid")
		hashID(a["snapshot"])
		hashID(a["checkpoint_id"])
		if num(a["publication_seq"]) == 0 {
			need(a["freshness_id"] == nil && a["issued_at"] == nil, "freshness_state_invalid")
		} else {
			hashID(a["freshness_id"])
			stamp(a["issued_at"])
		}
		return a
	}, "*", "freshness_state_invalid")
}

// VerifyFreshness checks registry-domain revocation with a complete bounded
// oldest-first publication proof, exact snapshot/checkpoint binding and fresh
// authenticated witness facts. Only its tip extends snapshot age; historical
// proof signatures establish continuity, not historical effect authority.
// Refusal has a zero plan. Acceptance is only a candidate transaction naming
// the proof, checkpoint and snapshot; the caller persists state atomically.
// Legacy /1 receipts renew registry own-age; /2 receipts cover the exact
// selected roots, backed by the complete-prefix index.
func (v Verifier) VerifyFreshness(chain [][]byte, checkpoint []byte, ids, keys []string) Result {
	return v.verifyFreshness(chain, checkpoint, ids, keys, false)
}

// VerifyFreshnessReanchor explicitly skips publication continuity after a gap.
// It admits one current tip against the retained positive anchor and a fresh
// authenticated witness, preserving all snapshot, signature and revocation gates.
// Acceptance includes both endpoints and the exact skipped-position count;
// the caller must atomically persist the new anchor/watermark and audit the skip.
// Skipped publication forks cannot be detected by this recovery operation.
func (v Verifier) VerifyFreshnessReanchor(tip, checkpoint []byte, ids, keys []string) Result {
	return v.verifyFreshness([][]byte{tip}, checkpoint, ids, keys, true)
}

func (v Verifier) verifyFreshness(chain [][]byte, checkpoint []byte, ids, keys []string, reanchor bool) Result {
	if v.context.RegistryCurrencyVersion != 0 && v.context.RegistryCurrencyVersion != 1 {
		return v.verifyFreshness2(chain, checkpoint, ids, keys, reanchor)
	}
	var receipt *FreshnessReceipt
	r := decide(func() Plan {
		// F1: absent freshness refuses; all bounded wire parses precede policy.
		need(len(chain) > 0, "freshness_unavailable")
		need(len(chain) <= 64, "freshness_malformed")
		total := len(checkpoint)
		for _, raw := range chain {
			total += len(raw)
			need(len(raw) <= 8192, "freshness_malformed")
		}
		need(total <= 532480, "freshness_malformed")
		// Current candidates use the protected profile, not a positional probe.
		// Retained archival predecessor bytes are checked separately at J5a/F8.
		for _, raw := range chain {
			currencyVersion(raw, "freshness/1")
		}
		currencyVersion(checkpoint, "checkpoint/1")
		es := make([]map[string]any, len(chain))
		for i, raw := range chain {
			es[i] = freshnessWire(raw)
		}
		cp := mapped(func() map[string]any { return journalRecord(checkpoint, true) }, "*", "freshness_malformed")
		f := v.facts()
		var root, owner string
		mapped(func() bool {
			return mapped(func() bool { root, owner = journalPolicy(f); return true }, "journal_invalid", "freshness_invalid")
		}, "journal_unavailable", "freshness_unavailable")
		// F3: every publication's root math, then checkpoint root math.
		for _, e := range es {
			freshnessSignature(e, root, owner)
		}
		checkpointSignature(cp, root, owner)
		tip := es[len(es)-1]
		b := obj(tip["body"])
		cb := obj(cp["body"])
		issued := stamp(b["issued_at"])
		// F4: validate the base without age; currency is a later full-profile gate.
		var maxAge int64
		snap := mapped(func() map[string]any {
			return mapped(func() map[string]any { e, age := snapshotBase(f, root); maxAge = age; return e }, "key_binding_invalid", "freshness_snapshot_invalid")
		}, "key_binding_unavailable", "freshness_unavailable")
		low, high := times(f)
		need(stamp(obj(snap["body"])["issued_at"]) <= stamp(cb["at"]) && stamp(cb["at"]) <= low, "freshness_unavailable")
		// F5: projection verification is external; this is its exact interface.
		w := mapped(func() map[string]any {
			return mapped(func() map[string]any { return journalWitness(f, root, owner) }, "journal_witness_invalid", "freshness_witness_invalid")
		}, "journal_unavailable", "freshness_unavailable")
		need(f["witness_read_at"] != nil, "freshness_unavailable")
		read := mapped(func() int64 { return stamp(f["witness_read_at"]) }, "*", "freshness_witness_invalid")
		// F6: all three exact snapshot/checkpoint references must coincide.
		need(b["snapshot"] == snap["id"] && b["snapshot"] == cb["snapshot"] && b["registry_seq"] == cb["seq"] && b["checkpoint_id"] == cp["id"], "freshness_binding_mismatch")
		// F7: unavailable old read, rollback, and same-position equivocation differ.
		need(num(b["registry_seq"]) <= num(w["registry_seq"]), "freshness_unavailable")
		need(num(b["registry_seq"]) >= num(w["registry_seq"]), "freshness_rollback")
		need(cp["id"] == w["checkpoint_id"] && cb["head"] == w["registry_head"], "freshness_fork")
		// F8: current tip/read currency, then retained complete publication history.
		need(issued <= low && high-issued <= maxAge && stamp(cb["at"]) <= issued && read >= issued && read <= low && high-read <= maxAge, "freshness_unavailable")
		a := freshnessAnchor(f, root, owner)
		seq, prev := num(a["publication_seq"]), a["freshness_id"]
		// Only publication genesis lacks a predecessor time; Unix zero is valid.
		var at *int64
		if a["issued_at"] != nil {
			when := stamp(a["issued_at"])
			at = &when
		}
		registrySeq, checkpointID, snapshotID := num(a["registry_seq"]), a["checkpoint_id"], a["snapshot"]
		var audit *FreshnessReanchorPlan
		if reanchor {
			// F8R: scoped stored positive state, registry rollback/fork, then strictly
			// advancing publication sequence and time. The verified checkpoint ID
			// commits its head; equality with the anchor ID also pins that old head.
			need(seq > 0 && at != nil, "freshness_state_invalid")
			need(num(b["registry_seq"]) >= registrySeq, "freshness_rollback")
			if num(b["registry_seq"]) == registrySeq {
				need(b["checkpoint_id"] == checkpointID, "freshness_fork")
				need(b["snapshot"] == snapshotID, "freshness_binding_mismatch")
			} else {
				need(b["checkpoint_id"] != checkpointID, "freshness_binding_mismatch")
			}
			need(num(b["publication_seq"]) > seq, "freshness_rollback")
			need(issued > *at, "freshness_rollback")
			audit = &FreshnessReanchorPlan{
				Reanchored:          true,
				SkippedPublications: num(b["publication_seq"]) - seq - 1,
				OldFreshnessID:      str(prev), NewFreshnessID: str(tip["id"]),
				OldCheckpointID: str(checkpointID), NewCheckpointID: str(cp["id"]),
			}
		} else {
			for i, e := range es {
				p := obj(e["body"])
				n := num(p["publication_seq"])
				when := stamp(p["issued_at"])
				need(n >= seq, "freshness_rollback")
				if n == seq {
					need(e["id"] == prev, "freshness_fork")
					need(i == 0 && at != nil && when == *at && num(p["registry_seq"]) == registrySeq && p["checkpoint_id"] == checkpointID && p["snapshot"] == snapshotID, "freshness_state_invalid")
					continue
				}
				need(n == seq+1, "freshness_gap")
				need(num(p["registry_seq"]) >= registrySeq, "freshness_rollback")
				sameHead := num(p["registry_seq"]) == registrySeq
				var expectedPrev any
				if sameHead {
					need(p["checkpoint_id"] == checkpointID, "freshness_fork")
					expectedPrev = prev
				} else {
					need(p["checkpoint_id"] != checkpointID, "freshness_binding_mismatch")
				}
				need(equal(p["prev"], expectedPrev), "freshness_gap")
				need(at == nil || when > *at, "freshness_time_invalid")
				if sameHead {
					need(p["snapshot"] == snapshotID, "freshness_binding_mismatch")
				}
				seq, prev = n, e["id"]
				at = &when
				registrySeq, checkpointID, snapshotID = num(p["registry_seq"]), p["checkpoint_id"], p["snapshot"]
			}
		}
		// F9: query shape, then effective matching after the complete proof.
		mapped(func() bool {
			need(len(ids) <= 64 && len(keys) <= 64, "freshness_request_invalid")
			for _, id := range ids {
				hashID(id)
			}
			for _, id := range keys {
				key(id)
			}
			return true
		}, "*", "freshness_request_invalid")
		for _, value := range array(obj(snap["body"])["entries"]) {
			entry := obj(value)
			if stamp(entry["from"]) > high {
				continue
			}
			query := ids
			if entry["kind"] == "key" {
				query = keys
			}
			for _, id := range query {
				need(entry["id"] != id, "revoked")
			}
		}
		admitted := append(es, cp, snap)
		p := plan(admitted, f)
		p.Reanchor = audit
		receipt = mintReceipt(v.context, tip, cp, snap, maxAge, read, audit)
		return p
	})
	if r.Code == "accept" {
		r.FreshnessReceipt = receipt
	}
	return r
}
