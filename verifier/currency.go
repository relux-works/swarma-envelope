package verifier

import (
	"reflect"
	"strings"

	"github.com/relux-works/swarma-envelope/record"
)

// SnapshotBinding identifies content selected by a version 2 checkpoint.
type SnapshotBinding struct {
	RootRole   string `json:"root_role"`
	RootKeyID  string `json:"root_key_id"`
	SnapshotID string `json:"snapshot_id"`
}

// SnapshotJournalEntry retains omitted roles too. Nil/zero means qualified absence.
type SnapshotJournalEntry struct {
	RootRole   string  `json:"root_role"`
	RootKeyID  string  `json:"root_key_id"`
	SnapshotID *string `json:"snapshot_id"`
	RecordSeq  int64   `json:"record_seq"`
}

// SnapshotJournalState is a detached candidate complete-prefix projection.
// Returned endpoints are positive. Explicit input genesis uses null head/id.
type SnapshotJournalState struct {
	Version      int                    `json:"version"`
	RegistryID   string                 `json:"registry_id"`
	Owner        string                 `json:"owner"`
	RegistrySeq  int64                  `json:"registry_seq"`
	RegistryHead string                 `json:"registry_head"`
	CheckpointID string                 `json:"checkpoint_id"`
	Latest       []SnapshotJournalEntry `json:"latest"`
}

func currencyKind(raw []byte) string {
	e, err := record.Parse(raw, 8192, 16)
	if err != nil {
		return ""
	}
	m, ok := e.(map[string]any)
	if !ok {
		return ""
	}
	b, ok := m["body"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := b["type"].(string)
	return s
}
func currencyList(value any, code string) []SnapshotBinding {
	return mapped(func() []SnapshotBinding {
		xs, ok := value.([]any)
		need(ok && len(xs) >= 1 && len(xs) <= 3, code)
		out := make([]SnapshotBinding, 0, len(xs))
		roles, keys := map[string]bool{}, map[string]bool{}
		previous := ""
		for _, x := range xs {
			row := exact(x, "root_role root_key_id snapshot_id", code)
			role := str(row["root_role"])
			need(role == "grant" || role == "operator" || role == "registry-owner", code)
			key(row["root_key_id"])
			hashID(row["snapshot_id"])
			k := str(row["root_key_id"])
			order := role + "\x00" + k
			need(!roles[role] && !keys[k] && order > previous, code)
			previous = order
			roles[role] = true
			keys[k] = true
			out = append(out, SnapshotBinding{role, k, str(row["snapshot_id"])})
		}
		need(roles["registry-owner"], code)
		return out
	}, "*", code)
}
func currencyPins(f facts) map[string]string {
	distinct(f)
	p := evidenceExact(f["agent_revocation_root"], "key purpose attestation_root")
	key(p["key"])
	pins := map[string]string{"registry-owner": str(p["key"])}
	for role, name := range map[string]string{"grant": "root", "operator": "operator_root"} {
		if value, ok := f[name]; ok {
			key(value)
			pins[role] = str(value)
		}
	}
	return pins
}
func currencyPinList(set []SnapshotBinding, pins map[string]string, code string) {
	for _, s := range set {
		need(pins[s.RootRole] == s.RootKeyID, code)
	}
}
func currencyEqual(a, b []SnapshotBinding) bool { return reflect.DeepEqual(a, b) }
func currencyWire(raw []byte, checkpoint bool) map[string]any {
	code := "freshness_malformed"
	if checkpoint {
		code = "journal_malformed"
	}
	return mapped(func() map[string]any {
		e := exact(must(record.Parse(raw, 8192, 16)), "version body id signatures", code)
		hashID(e["id"])
		need(isString(e["version"]), code)
		names := "type registry owner publication_seq prev issued_at snapshots registry_seq checkpoint_id"
		if checkpoint {
			names = "type registry owner seq head at snapshots"
		}
		b := exact(e["body"], names, code)
		need(isString(b["type"]), code)
		key(b["registry"])
		text(b["owner"], code)
		currencyList(b["snapshots"], code)
		if checkpoint {
			need(isInt(b["seq"]) && num(b["seq"]) >= 1 && num(b["seq"]) <= 9007199254740991, code)
			hashID(b["head"])
			stamp(b["at"])
		} else {
			for _, n := range []string{"publication_seq", "registry_seq"} {
				need(isInt(b[n]) && num(b[n]) >= 1 && num(b[n]) <= 9007199254740991, code)
			}
			need(num(b["publication_seq"]) != 1 || b["prev"] == nil, code)
			if b["prev"] != nil {
				hashID(b["prev"])
			}
			stamp(b["issued_at"])
			hashID(b["checkpoint_id"])
		}
		sigs, ok := e["signatures"].([]any)
		need(ok && len(sigs) >= 1 && len(sigs) <= 8, code)
		for _, value := range sigs {
			s := exact(value, "role key sig", code)
			need(isString(s["role"]) && isString(s["sig"]), code)
			key(s["key"])
			must(record.DecodeBase64(str(s["sig"]), 64))
		}
		return e
	}, "*", code)
}
func currencySignature(e map[string]any, kind, root, owner, code string) {
	mapped(func() bool {
		b := obj(e["body"])
		ss := array(e["signatures"])
		need(len(ss) == 1, code)
		s := obj(ss[0])
		need(e["version"] == "swarm-envelope/2" && b["type"] == kind && b["registry"] == root && b["owner"] == owner && s["key"] == root && s["role"] == "author", code)
		need(e["id"] == must(record.ContentID(kind, b)), code)
		sig := must(record.DecodeBase64(str(s["sig"]), 64))
		need(record.VerifySignature(root, sig, must(record.SigningPreimage(kind, root, "author", b))) == nil, code)
		return true
	}, "*", code)
}

// Raw bytes and the declared protected proof Evidence are charged, including repeated
// copies. Metadata/output inventory reserves 64KiB within the 2MiB whole-call cap.
func (v Verifier) currencyCapacity(rawBytes int, code string) {
	c := v.context
	// All charges are available before profile probes or body parsing. Evidence
	// retains its immutable construction cost; raw inputs need only their lengths.
	total := 65536 + rawBytes + c.SnapshotJournal.cost + c.SignedSnapshots.cost +
		c.IDJournal.cost + c.FreshnessAnchor.cost + c.JournalWitness.cost +
		c.AgentRevocationRoot.cost + c.RegistryOwner.cost + c.GrantRoot.cost +
		c.OperatorRoot.cost + c.ServiceRoot.cost + c.WitnessReadAt.cost
	need(total <= 2<<20, code)
	var visit func(any)
	visit = func(value any) {
		switch x := value.(type) {
		case []byte:
			need(len(x) <= 8192, code)
		case []any:
			for _, n := range x {
				visit(n)
			}
		case map[string]any:
			for _, n := range x {
				visit(n)
			}
		}
	}
	visit(c.SnapshotJournal.value)
	visit(c.SignedSnapshots.value)
	visit(c.IDJournal.value)
}
func currencyProfile(c Context) {
	need(c.RegistryCurrencyVersion == 0 || c.RegistryCurrencyVersion == 1 || c.RegistryCurrencyVersion == 2, "journal_invalid")
}
func currencyVersion(raw []byte, kind string) {
	k := currencyKind(raw)
	if k == "checkpoint/1" || k == "freshness/1" || k == "checkpoint/2" || k == "freshness/2" {
		need(k == kind, "registry_currency_version_mismatch")
	}
}
func currencyOriginal(f facts, id, root, unavailable, invalid string) (result map[string]any) {
	defer func() {
		if x := recover(); x != nil {
			if c, ok := x.(refusal); ok {
				if string(c) == unavailable {
					panic(c)
				}
				panic(refusal(invalid))
			}
			panic(x)
		}
	}()
	need(f["id_journal_available"] == true && f["seen"] != nil, unavailable)
	return mapped(func() map[string]any {
		m, ok := f["seen"].(map[string]any)
		need(ok, invalid)
		raw, exists := m[id]
		need(exists && raw != nil, unavailable)
		e := signed(raw, "revocation/1", root)
		need(e["id"] == id, invalid)
		b := exact(e["body"], "type issuer issued_at complete entries", invalid)
		need(b["complete"] == true, invalid)
		stamp(b["issued_at"])
		entries, ok := b["entries"].([]any)
		need(ok && len(entries) <= 64, invalid)
		snapshotEntries(snapshotProof{entries: entries, high: 0}, nil, nil)
		return e
	}, "key_binding_unavailable", unavailable)
}

// The relation is exactly section 2.6: changed content advances issuance and
// keeps each prior subject/record with no later effective time. Original bytes
// for BOTH endpoints are mandatory, including omitted-role historical rows.
func currencyExtends(old, next map[string]any, code string) {
	a, b := obj(old["body"]), obj(next["body"])
	need(stamp(b["issued_at"]) > stamp(a["issued_at"]), code)
	for _, value := range array(a["entries"]) {
		x := obj(value)
		found := false
		for _, n := range array(b["entries"]) {
			y := obj(n)
			if x["kind"] == y["kind"] && x["id"] == y["id"] && stamp(y["from"]) <= stamp(x["from"]) {
				found = true
				break
			}
		}
		need(found, code)
	}
}
func currencyStateCopy(s *SnapshotJournalState) *SnapshotJournalState {
	if s == nil {
		return nil
	}
	out := *s
	out.Latest = append([]SnapshotJournalEntry(nil), s.Latest...)
	for i, r := range out.Latest {
		if r.SnapshotID != nil {
			v := *r.SnapshotID
			out.Latest[i].SnapshotID = &v
		}
	}
	return &out
}
func currencyAnchor(f facts, root, owner string, pins map[string]string) (proof map[string]any, state *SnapshotJournalState) {
	defer func() {
		if x := recover(); x != nil {
			if c, ok := x.(refusal); ok {
				if string(c) == "journal_unavailable" {
					panic(c)
				}
				panic(refusal("journal_invalid"))
			}
			panic(x)
		}
	}()
	need(f["snapshot_journal"] != nil, "journal_unavailable")
	proof = exact(f["snapshot_journal"], "anchor entries", "journal_invalid")
	a := exact(proof["anchor"], "version registry_id owner registry_seq registry_head checkpoint_id latest", "journal_invalid")
	need(isInt(a["version"]) && num(a["version"]) == 2 && a["registry_id"] == root && a["owner"] == owner && isInt(a["registry_seq"]) && num(a["registry_seq"]) >= 0 && num(a["registry_seq"]) <= 9007199254740991, "journal_invalid")
	state = &SnapshotJournalState{Version: 2, RegistryID: root, Owner: owner, RegistrySeq: num(a["registry_seq"])}
	if state.RegistrySeq == 0 {
		need(a["registry_head"] == nil && a["checkpoint_id"] == nil, "journal_invalid")
	} else {
		hashID(a["registry_head"])
		hashID(a["checkpoint_id"])
		state.RegistryHead = str(a["registry_head"])
		state.CheckpointID = str(a["checkpoint_id"])
	}
	rows, ok := a["latest"].([]any)
	need(ok && len(rows) == len(pins), "journal_invalid")
	seen := map[string]bool{}
	prev := ""
	for _, value := range rows {
		r := exact(value, "root_role root_key_id snapshot_id record_seq", "journal_invalid")
		role, k := str(r["root_role"]), str(r["root_key_id"])
		need(pins[role] == k && k != "" && !seen[role] && role > prev && isInt(r["record_seq"]), "journal_invalid")
		seen[role] = true
		prev = role
		entry := SnapshotJournalEntry{RootRole: role, RootKeyID: k, RecordSeq: num(r["record_seq"])}
		if r["snapshot_id"] == nil {
			need(entry.RecordSeq == 0, "journal_invalid")
		} else {
			hashID(r["snapshot_id"])
			id := str(r["snapshot_id"])
			entry.SnapshotID = &id
			need(entry.RecordSeq >= 1 && entry.RecordSeq <= state.RegistrySeq, "journal_invalid")
			currencyOriginal(f, id, k, "journal_unavailable", "journal_invalid")
		}
		state.Latest = append(state.Latest, entry)
	}
	return proof, state
}
func currencyPrior(f facts, state *SnapshotJournalState, root, owner string) map[string]any {
	need(f["id_journal_available"] == true && f["seen"] != nil, "journal_unavailable")
	m, ok := f["seen"].(map[string]any)
	need(ok, "journal_invalid")
	value := m[state.CheckpointID]
	need(value != nil, "journal_unavailable")
	raw, ok := value.([]byte)
	need(ok, "checkpoint_invalid")
	var e map[string]any
	if currencyKind(raw) == "checkpoint/1" {
		e = journalRecord(raw, true)
		checkpointSignature(e, root, owner)
	} else {
		e = currencyWire(raw, true)
		currencySignature(e, "checkpoint/2", root, owner, "checkpoint_invalid")
	}
	b := obj(e["body"])
	need(e["id"] == state.CheckpointID && num(b["seq"]) == state.RegistrySeq && b["head"] == state.RegistryHead, "checkpoint_invalid")
	return e
}
func currencyDerive(f facts, root, owner string, pins map[string]string, entries [][]byte, cp map[string]any) (state *SnapshotJournalState) {
	defer func() {
		if x := recover(); x != nil {
			if c, ok := x.(refusal); ok {
				if strings.HasPrefix(string(c), "journal_") || strings.HasPrefix(string(c), "checkpoint_") {
					panic(c)
				}
				panic(refusal("journal_invalid"))
			}
			panic(x)
		}
	}()
	_, state = currencyAnchor(f, root, owner, pins)
	b := obj(cp["body"])
	seq := state.RegistrySeq
	head := state.RegistryHead
	at := int64(0)
	need(len(entries) <= 64, "journal_malformed")
	need(num(b["seq"]) >= seq, "journal_rollback")
	if num(b["seq"]) == seq {
		need(cp["id"] == state.CheckpointID && b["head"] == head, "journal_fork")
	} else if seq > 0 {
		prior := currencyPrior(f, state, root, owner)
		need(stamp(b["at"]) >= stamp(obj(prior["body"])["at"]), "journal_rollback")
		need(len(entries) > 0, "journal_anchor_required")
		first := journalRecord(entries[0], false)
		need(num(obj(first["body"])["seq"]) == seq && first["id"] == head, "journal_anchor_required")
	}
	for i, raw := range entries {
		e := journalRecord(raw, false)
		x := obj(e["body"])
		need(e["version"] == "swarm-envelope/2" && x["type"] == "journal-entry/1" && x["registry"] == root && x["owner"] == owner && e["id"] == must(record.ContentID("journal-entry/1", x)), "journal_entry_invalid")
		when := stamp(x["at"])
		if i == 0 && num(x["seq"]) == seq {
			need(e["id"] == head && when <= stamp(b["at"]), "journal_chain_broken")
			at = when
			continue
		}
		need(num(x["seq"]) == seq+1 && equal(x["prev"], func() any {
			if seq == 0 {
				return nil
			}
			return head
		}()) && when >= at && when <= stamp(b["at"]), "journal_chain_broken")
		seq, head, at = num(x["seq"]), str(e["id"]), when
		if x["op"] != "add" || x["record_type"] != "revocation/1" {
			continue
		}
		originals, ok := f["seen"].(map[string]any)
		need(f["id_journal_available"] == true && ok, "journal_unavailable")
		value := originals[str(x["record"])]
		need(value != nil, "journal_unavailable")
		raw, ok := value.([]byte)
		need(ok, "journal_invalid")
		original := must(record.Parse(raw, 8192, 16))
		issuer := str(obj(obj(original)["body"])["issuer"])
		key(issuer)
		next := currencyOriginal(f, str(x["record"]), issuer, "journal_unavailable", "journal_invalid")
		need(stamp(obj(next["body"])["issued_at"]) <= when, "journal_invalid")
		for j, row := range state.Latest {
			if row.RootKeyID != issuer {
				continue
			}
			id := str(x["record"])
			if row.SnapshotID != nil {
				if *row.SnapshotID == id {
					break
				}
				old := currencyOriginal(f, *row.SnapshotID, issuer, "journal_unavailable", "journal_invalid")
				currencyExtends(old, next, "journal_invalid")
			}
			state.Latest[j].SnapshotID = &id
			state.Latest[j].RecordSeq = seq
			break
		}
	}
	need(seq == num(b["seq"]) && head == b["head"], "journal_chain_broken")
	for _, selected := range currencyList(b["snapshots"], "journal_malformed") {
		found := false
		for _, row := range state.Latest {
			if row.RootRole == selected.RootRole && row.RootKeyID == selected.RootKeyID && row.SnapshotID != nil && *row.SnapshotID == selected.SnapshotID {
				found = true
			}
		}
		need(found, "checkpoint_snapshot_invalid")
	}
	state.RegistrySeq = seq
	state.RegistryHead = head
	state.CheckpointID = str(cp["id"])
	return state
}
func currencyEntries(f facts) [][]byte {
	need(f["snapshot_journal"] != nil, "journal_unavailable")
	p := exact(f["snapshot_journal"], "anchor entries", "journal_invalid")
	xs, ok := p["entries"].([]any)
	need(ok, "journal_invalid")
	need(len(xs) <= 64, "journal_malformed")
	out := make([][]byte, len(xs))
	for i, x := range xs {
		raw, ok := x.([]byte)
		need(ok && len(raw) <= 8192, "journal_malformed")
		out[i] = raw
	}
	return out
}
func currencyPlan(es []map[string]any, state *SnapshotJournalState, f facts, entries [][]byte) Plan {
	p := plan(es, f)
	seen := map[string]bool{}
	ids := []string{}
	add := func(id string) {
		if id != "" && !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	for _, id := range p.IDs {
		add(id)
	}
	// Anchor originals precede suffix dependencies; IDs are deduplicated on first use.
	proof := obj(f["snapshot_journal"])
	anchor := obj(proof["anchor"])
	if anchor["checkpoint_id"] != nil {
		add(str(anchor["checkpoint_id"]))
	}
	for _, row := range array(anchor["latest"]) {
		r := obj(row)
		if r["snapshot_id"] != nil {
			add(str(r["snapshot_id"]))
		}
	}
	for _, raw := range entries {
		e := journalRecord(raw, false)
		add(str(e["id"]))
		b := obj(e["body"])
		if b["op"] == "add" && b["record_type"] == "revocation/1" {
			add(str(b["record"]))
		}
	}
	p.IDs = ids
	p.SnapshotJournal = currencyStateCopy(state)
	return p
}

// Shape-only parsing for R2: classify malformed replacement premises before
// binding comparisons without re-deriving authority or resolving history.
func currencyProofShape(value any) {
	proof := exact(value, "anchor entries", "freshness_receipt_invalid")
	a := exact(proof["anchor"], "version registry_id owner registry_seq registry_head checkpoint_id latest", "freshness_receipt_invalid")
	need(isInt(a["version"]) && num(a["version"]) == 2 && isInt(a["registry_seq"]) && num(a["registry_seq"]) >= 0 && num(a["registry_seq"]) <= 9007199254740991, "freshness_receipt_invalid")
	key(a["registry_id"])
	text(a["owner"], "freshness_receipt_invalid")
	if num(a["registry_seq"]) == 0 {
		need(a["registry_head"] == nil && a["checkpoint_id"] == nil, "freshness_receipt_invalid")
	} else {
		hashID(a["registry_head"])
		hashID(a["checkpoint_id"])
	}
	rows, ok := a["latest"].([]any)
	need(ok && len(rows) >= 1 && len(rows) <= 3, "freshness_receipt_invalid")
	seen := map[string]bool{}
	prev := ""
	for _, value := range rows {
		r := exact(value, "root_role root_key_id snapshot_id record_seq", "freshness_receipt_invalid")
		role := str(r["root_role"])
		need(role == "grant" || role == "operator" || role == "registry-owner", "freshness_receipt_invalid")
		key(r["root_key_id"])
		k := str(r["root_key_id"])
		need(role > prev && !seen[k] && isInt(r["record_seq"]), "freshness_receipt_invalid")
		prev = role
		seen[k] = true
		if r["snapshot_id"] == nil {
			need(num(r["record_seq"]) == 0, "freshness_receipt_invalid")
		} else {
			hashID(r["snapshot_id"])
			need(num(r["record_seq"]) >= 1 && num(r["record_seq"]) <= num(a["registry_seq"]), "freshness_receipt_invalid")
		}
	}
	xs, ok := proof["entries"].([]any)
	need(ok && len(xs) <= 64, "freshness_receipt_invalid")
	for _, x := range xs {
		raw, ok := x.([]byte)
		need(ok && len(raw) <= 8192, "freshness_receipt_invalid")
	}
}
