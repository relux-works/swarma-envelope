package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
)

// Fixture construction only: deliberately malformed CCJ must reach the oracle,
// rather than panic in the generator. Valid records always use the owner codec.
func fixtureCCJ(v any) []byte {
	raw, err := json.Marshal(v)
	must(err)
	parsed, err := ccj.Parse(raw, ccj.RegistrationMalformed)
	if err != nil {
		return raw
	}
	encoded, err := ccj.Marshal(parsed, ccj.RegistrationMalformed)
	must(err)
	return encoded
}
func evidenceWire(b M, k Key) string {
	return evidenceWireFor(b, k, b["type"].(string))
}
func evidenceWireFor(b M, k Key, expected string) string {
	tag := domain(expected)
	pre := append([]byte(tag+"\n"), fixtureCCJ(M{"version": "swarm-envelope/2", "body": b, "key": k.ID, "role": "author"})...)
	e := M{"version": "swarm-envelope/2", "body": b, "id": digest(append([]byte(tag+"\n"), fixtureCCJ(b)...)), "signatures": []any{M{"role": "author", "key": k.ID, "sig": b64(sign(k, pre))}}}
	return b64(fixtureCCJ(e))
}
func putIf(dst M, name string, src M, old string) {
	if x, ok := src[old]; ok {
		dst[name] = x
	}
}
func bindingRecord(v any, uid int) any {
	m, ok := v.(M)
	if !ok {
		return v
	}
	out := M{"uid": uid}
	for k, x := range m {
		if k == "epoch" {
			k = "master_epoch"
		}
		out[k] = x
	}
	return out
}
func makeAttestation(key string, r M, uid int) M {
	sub := M{"algorithm": "Ed25519"}
	putIf(sub, "key_id", r, "key")
	putIf(sub, "public_bytes", r, "public_bytes")
	b := M{"type": "attestation/1", "issuer": keys[5].ID, "subject": sub, "roles": []any{"author"}, "actions": []any{"message.sign"}}
	for old, n := range map[string]string{"class": "key_class", "purpose": "purpose", "not_before": "iat", "not_after": "exp"} {
		putIf(b, n, r, old)
	}
	if x, ok := r["binding"]; ok {
		b["binding"] = bindingRecord(x, uid)
	}
	return b
}
func deviceAttestation(key string) M {
	a, raw, _ := strings.Cut(key, ":")
	algorithm := "P-256"
	if a == "ed25519" {
		algorithm = "Ed25519"
	}
	return M{"type": "attestation/1", "issuer": keys[4].ID, "subject": M{"algorithm": algorithm, "key_id": key, "public_bytes": raw}, "key_class": "operator-device", "purpose": "operator-device", "roles": []any{"act", "approver"}, "actions": []any{"act.sign", "grant.sign", "message.approve"}, "iat": "2026-01-01T00:00:00Z", "exp": "2026-01-02T00:00:00Z", "binding": M{"owner": "owner-a"}}
}
func snapshot(root Key, r M) M {
	entries := []any{}
	for _, pair := range []struct{ field, kind string }{{"revoked_ids", "record"}, {"revoked_keys", "key"}} {
		if rows, ok := r[pair.field].([]any); ok {
			for _, id := range rows {
				entries = append(entries, M{"kind": pair.kind, "id": id, "from": r["issued_at"]})
			}
		}
	}
	if r["verdict"] == "revoked" {
		entries = append(entries, M{"kind": "key", "id": root.ID, "from": r["issued_at"]})
	}
	avail := any("available")
	if r["verdict"] == "unavailable" {
		avail = "unavailable"
	}
	return M{"availability": avail, "max_age": r["max_age"], "rollback_safe": r["rollback_safe"], "snapshot": evidenceWire(M{"type": "revocation/1", "issuer": root.ID, "issued_at": r["issued_at"], "complete": r["complete"], "entries": entries}, root)}
}
func freshSnapshot(root Key) M {
	return snapshot(root, M{"verdict": "not_revoked", "issued_at": "2026-01-01T00:01:00Z", "max_age": 60, "complete": true, "rollback_safe": true, "revoked_ids": []any{}, "revoked_keys": []any{}})
}

// The inherited builders are private construction blueprints, not verifier
// inputs. Materialize every witness into actual root-signed records; there are
// no valid/invalid attestation booleans in the exported verification interface.
func materializeEvidence(v *Vector) {
	f := v.Fixture
	if v.Mode == "domain" {
		return
	}
	if v.Mode == "signer" {
		trimmed := M{}
		for _, n := range []string{"identity_check", "multi_agent", "caller_key_id", "caller_attestation_id"} {
			if x, ok := f[n]; ok {
				trimmed[n] = x
			}
		}
		v.Fixture = trimmed
		return
	}
	attest := M{}
	active := M{}
	revs := M{keys[7].ID: freshSnapshot(keys[7]), keys[4].ID: freshSnapshot(keys[4])}
	root := keys[0]
	for _, k := range keys {
		if k.ID == f["root"] {
			root = k
		}
	}
	revs[root.ID] = snapshot(root, f["revocation"].(M))
	if v.Mode == "operator" {
		revs[keys[4].ID] = snapshot(keys[4], f["revocation"].(M))
	}
	expected, expOK := f["agent_expected"].(M)
	if expOK {
		for key, b := range expected {
			uid := 1000
			for i, k := range keys {
				if k.ID == key {
					uid += i
				}
			}
			active[key] = bindingRecord(b, uid)
		}
	}
	records, recOK := f["agent_evidence"].(M)
	if recOK {
		for key, value := range records {
			r, ok := value.(M)
			if !ok {
				attest[key] = value
				continue
			}
			uid := 1000
			for i, k := range keys {
				if k.ID == key {
					uid += i
				}
			}
			b := makeAttestation(key, r, uid)
			if a, ok := active[key].(M); ok {
				putIf(a, "active", r, "active")
			}
			status, exists := r["attestation"]
			if !exists || status == nil || status == "unavailable" {
				attest[key] = nil
			} else if status == "valid" {
				attest[key] = evidenceWire(b, keys[5])
			} else if status == "invalid" {
				e := decode(evidenceWire(b, keys[5]))
				s := e["signatures"].([]any)[0].(M)
				raw := unb64(s["sig"].(string))
				raw[5] ^= 1
				s["sig"] = b64(raw)
				attest[key] = wire(e)
			} else {
				attest[key] = status
			}
			state, exists := r["revocation"]
			sr := revs[keys[7].ID].(M)
			if !exists || state == nil || state == "unavailable" {
				sr["availability"] = "unavailable"
			} else if state == "revoked" {
				e := decode(sr["snapshot"].(string))
				b := e["body"].(M)
				b["entries"] = append(b["entries"].([]any), M{"kind": "key", "id": key, "from": f["now"]})
				sr["snapshot"] = evidenceWire(b, keys[7])
			} else if state != "not_revoked" {
				sr["availability"] = state
			}
		}
	}
	f["attestations"], f["active_generations"] = attest, active
	if !recOK {
		f["attestations"] = f["agent_evidence"]
	}
	if !expOK {
		f["active_generations"] = f["agent_expected"]
	}
	devices := M{}
	for _, id := range f["operator_pins"].([]any) {
		key := id.(string)
		devices[key] = evidenceWire(deviceAttestation(key), keys[4])
	}
	f["operator_attestations"] = devices
	f["service_root"] = M{"key": keys[5].ID, "purpose": 5}
	f["agent_revocation_root"] = M{"key": keys[7].ID, "purpose": "registry-revocation", "attestation_root": keys[5].ID}
	f["operator_root"] = keys[4].ID
	f["operator_owner"] = "owner-a"
	f["revocations"] = revs
	for _, n := range []string{"agent_evidence", "agent_expected", "operator_pins", "revocation"} {
		delete(f, n)
	}
	// Overrides build explicit signed-record faults, never expected-code shortcuts.
	if edits, ok := f["attestation_edits"].(M); ok {
		for key, fields := range edits {
			e := decode(attest[key].(string))
			b := e["body"].(M)
			for n, x := range fields.(M) {
				b[n] = x
			}
			attest[key] = evidenceWire(b, keys[5])
		}
		delete(f, "attestation_edits")
	}
	if field, ok := f["record_mutation"].(M); ok {
		applyRecordMutation(f, field)
		delete(f, "record_mutation")
	}
	if fault, ok := f["snapshot_fault"].(M); ok {
		idx := 7
		recordMap := attest
		subject := keys[0].ID
		if fault["device"] == true {
			idx = 4
			recordMap = devices
			subject = keys[6].ID
		}
		sr := revs[keys[idx].ID].(M)
		for _, name := range []string{"availability", "max_age", "rollback_safe"} {
			if x, ok := fault[name]; ok {
				sr[name] = x
			}
		}
		fields := M{}
		for _, name := range []string{"entries", "issued_at", "complete"} {
			if x, ok := fault[name]; ok {
				fields[name] = x
			}
		}
		if fault["revoke_attestation"] == true {
			fields["entries"] = []any{M{"kind": "record", "id": decode(recordMap[subject].(string))["id"], "from": f["now"]}}
		}
		applyRecordMutation(f, M{"collection": "revocations", "key": keys[idx].ID, "fields": fields, "corrupt": fault["corrupt"], "foreign_issuer": fault["foreign_issuer"]})
		delete(f, "snapshot_fault")
	}
	if changes, ok := f["context_edits"].(M); ok {
		for n, x := range changes {
			f[n] = x
		}
		delete(f, "context_edits")
	}
	if names, ok := f["context_remove"].([]any); ok {
		for _, name := range names {
			delete(f, name.(string))
		}
		delete(f, "context_remove")
	}
	if role, ok := f["p256_root"].(string); ok {
		old := keys[5].ID
		collection := attest
		if role == "operator" {
			old = keys[4].ID
			collection = devices
			f["operator_root"] = keys[6].ID
		} else {
			f["service_root"] = M{"key": keys[6].ID, "purpose": 5}
		}
		for key, value := range collection {
			e := decode(value.(string))
			b := e["body"].(M)
			b["issuer"] = keys[6].ID
			collection[key] = evidenceWire(b, keys[6])
		}
		if role == "operator" {
			delete(revs, old)
			revs[keys[6].ID] = freshSnapshot(keys[6])
		} else {
			f["agent_revocation_root"].(M)["attestation_root"] = keys[6].ID
		}
		delete(f, "p256_root")
	}
}
func applyRecordMutation(f M, m M) {
	collection := f[m["collection"].(string)].(M)
	key := m["key"].(string)
	value := collection[key]
	snapshotMode := m["collection"] == "revocations"
	if snapshotMode {
		value = value.(M)["snapshot"]
	}
	e := decode(value.(string))
	b := e["body"].(M)
	expected := b["type"].(string)
	idx := 5
	for i, k := range keys {
		if k.ID == b["issuer"] {
			idx = i
		}
	}
	if m["device"] == true {
		idx = 4
	}
	if fields, ok := m["fields"].(M); ok {
		for n, x := range fields {
			b[n] = x
		}
	}
	if path, ok := m["path"].([]any); ok && len(path) > 0 {
		if m["remove"] == true {
			deletePath(b, path)
		} else {
			setPath(b, path, m["value"])
		}
	}
	if m["foreign_issuer"] == true {
		idx = 3
		b["issuer"] = keys[3].ID
	}
	wireValue := evidenceWireFor(b, keys[idx], expected)
	if m["corrupt"] == true {
		e = decode(wireValue)
		s := e["signatures"].([]any)[0].(M)
		raw := unb64(s["sig"].(string))
		raw[5] ^= 1
		s["sig"] = b64(raw)
		wireValue = wire(e)
	}
	if size, ok := m["pad_to"].(int); ok {
		raw := unb64(wireValue)
		if size < len(raw) {
			panic("fixture padding below received length")
		}
		wireValue = b64(append(raw, bytes.Repeat([]byte{' '}, size-len(raw))...))
	}
	if snapshotMode {
		collection[key].(M)["snapshot"] = wireValue
	} else {
		collection[key] = wireValue
	}
}

// Each negative isolates one curator requirement with a valid adjacent control.
func rulingVectors() {
	for i, tc := range []struct {
		claim, code string
		change      func(*Vector)
	}{
		{"Forwarding a signed message into another actual room refuses.", "message_room_mismatch", func(v *Vector) { v.Fixture["delivery"].(M)["room"] = "!other:test.invalid" }},
		{"Forwarding to a different full recipient refuses.", "message_recipient_mismatch", func(v *Vector) { v.Fixture["delivery"].(M)["to"] = "@other:test.invalid" }},
		{"Missing delivered human text refuses even though the signed body is intact.", "message_text_unavailable", func(v *Vector) { delete(v.Fixture["delivery"].(M), "text") }},
		{"A trailing newline is a different text.", "message_text_mismatch", func(v *Vector) { v.Fixture["delivery"].(M)["text"] = b64([]byte("hello\n")) }},
		{"Text substitution cannot borrow a signed typed body.", "message_text_mismatch", func(v *Vector) { v.Fixture["delivery"].(M)["text"] = b64([]byte("goodbye")) }},
		{"A display name with whitespace is not an opaque full room id.", "envelope_malformed", func(v *Vector) { resign(v, 0, func(b M) { b["room"] = "Room alias" }) }},
		{"Uppercase text digest is not the required lowercase hex.", "envelope_malformed", func(v *Vector) {
			resign(v, 0, func(b M) { b["body_sha256"] = strings.ToUpper(b["body_sha256"].(string)) })
		}},
		{"A missing required text digest refuses.", "envelope_malformed", func(v *Vector) { resign(v, 0, func(b M) { delete(b, "body_sha256") }) }},
		{"Invalid UTF-8 is not human-readable UTF-8 text.", "message_text_invalid", func(v *Vector) { v.Fixture["delivery"].(M)["text"] = b64([]byte{255}) }},
		{"Missing actual room context cannot be inferred from the envelope.", "message_context_unavailable", func(v *Vector) { delete(v.Fixture["delivery"].(M), "room") }},
	} {
		v := base("envelope", 0)
		tc.change(&v)
		add(fmt.Sprintf("C%02d", i+1), tc.claim, "PC1", tc.code, v)
	}
	// Signature-valid agent attestations with one changed contract member.
	for i, tc := range []struct {
		claim            string
		fields           M
		path             []any
		value            any
		foreign, corrupt bool
	}{
		{claim: "A self-signed or foreign issuer cannot replace the service root.", foreign: true},
		{claim: "Attestation cryptography is verified, not a caller verdict.", corrupt: true},
		{claim: "The agent purpose is exactly swarma-msg.", fields: M{"purpose": "git-signing"}},
		{claim: "An expired attestation cannot authenticate an agent.", fields: M{"exp": "2026-01-01T00:01:00Z"}},
		{claim: "A not-yet-valid attestation refuses.", fields: M{"iat": "2026-01-01T00:01:01Z"}},
		{claim: "The agent validity window cannot exceed 86400 seconds.", fields: M{"exp": "2026-01-02T00:00:01Z"}},
		{claim: "The signed generation must equal current evidence.", path: []any{"binding", "generation"}, value: "generation-old"},
		{claim: "The signed registration must equal current evidence.", path: []any{"binding", "registration_number"}, value: 9},
		{claim: "The signed master epoch must equal current evidence.", path: []any{"binding", "master_epoch"}, value: "epoch-old"},
		{claim: "The signed UID must equal current evidence.", path: []any{"binding", "uid"}, value: 9999},
		{claim: "The attested role is author, not approver.", fields: M{"roles": []any{"approver"}}},
		{claim: "The permitted signing action is explicit.", fields: M{"actions": []any{"git.sign"}}},
	} {
		v := base("envelope", 0)
		v.Fixture["record_mutation"] = M{"collection": "attestations", "key": keys[0].ID, "fields": tc.fields, "path": tc.path, "value": tc.value, "foreign_issuer": tc.foreign, "corrupt": tc.corrupt}
		add(fmt.Sprintf("A%02d", i+1), tc.claim, "PA1", "key_binding_invalid", v)
	}
	for i, tc := range []struct {
		claim, code string
		change      func(*Vector)
	}{
		{"Ed25519 device attestations are not admitted even when root-signed.", "key_binding_invalid", func(v *Vector) {
			v.Fixture["operator_pins"] = []any{keys[3].ID}
			v.Input["chain"] = vertexChain([]int{0, 3, 2})
		}},
		{"Operator device attestation must have the operator purpose.", "key_binding_invalid", func(v *Vector) {
			v.Fixture["record_mutation"] = M{"collection": "operator_attestations", "key": keys[6].ID, "device": true, "fields": M{"purpose": "swarma-msg"}}
		}},
		{"A forged operator-root issuer refuses.", "key_binding_invalid", func(v *Vector) {
			v.Fixture["record_mutation"] = M{"collection": "operator_attestations", "key": keys[6].ID, "device": true, "foreign_issuer": true}
		}},
	} {
		v := base("grant", 0)
		v.Input["chain"] = vertexChain([]int{0, 6, 2})
		tc.change(&v)
		add(fmt.Sprintf("A%02d", i+13), tc.claim, "PA2", tc.code, v)
	}
	// These use signed snapshots; the oracle recomputes revocation from entries.
	for i, tc := range []struct {
		claim, code string
		m           M
	}{
		{"An agent's attestation id can be revoked without changing its subject key.", "revoked", M{"revoke_attestation": true}},
		{"An old self-declared message iat does not bypass current key revocation.", "revoked", M{"entries": []any{M{"kind": "key", "id": keys[0].ID, "from": "2026-01-01T00:00:30Z"}}}},
		{"Unavailable signed agent revocation data refuses.", "key_binding_unavailable", M{"availability": "unavailable"}},
		{"A forged revocation signature is invalid binding evidence.", "key_binding_invalid", M{"corrupt": true}},
		{"Revocation signed by another issuer cannot revoke or clear this root's keys.", "key_binding_invalid", M{"foreign_issuer": true}},
	} {
		v := base("envelope", 0)
		v.Fixture["snapshot_fault"] = tc.m
		add(fmt.Sprintf("A%02d", i+16), tc.claim, "PA1", tc.code, v)
	}
	for i, tc := range []struct {
		claim, code            string
		parent, child, request string
		pp, cp, rp             bool
	}{
		{"A child may not lower its minimum assurance level.", "grant_not_narrowing", "A2", "A1", "A2", false, false, false},
		{"A child may not remove a required presence flag.", "grant_not_narrowing", "A1", "A1", "A2", true, false, true},
		{"An A1 request cannot satisfy an A2 minimum.", "grant_assurance_insufficient", "A1", "A2", "A1", false, false, false},
		{"A missing presence fact cannot satisfy required presence.", "grant_assurance_insufficient", "A1", "A1", "A2", false, true, false},
		{"An A2 request cannot satisfy an A3 minimum.", "grant_assurance_insufficient", "A1", "A3", "A2", false, false, true},
	} {
		v := assuranceVector(tc.parent, tc.child, tc.request, tc.pp, tc.cp, tc.rp)
		add(fmt.Sprintf("Q%02d", i+1), tc.claim, "PQ1", tc.code, v)
	}
	v := base("operator", 0)
	widen(&v, true)
	add("Q06", "Unqualified presence assertions never open the v0 A3 gate.", "PO1", "act_a3_inactive", v)
	v = base("envelope", 0)
	add("PC1", "Exact room, recipient and exact delivered UTF-8 text verify.", "", "accept", v)
	v = base("envelope", 0)
	resign(&v, 0, func(b M) { b["body_sha256"] = strings.TrimPrefix(digest(nil), "sha256:") })
	v.Fixture["delivery"].(M)["text"] = ""
	add("PC2", "Present empty text uses the SHA-256 of the empty byte string.", "", "accept", v)
	v = base("envelope", 0)
	resign(&v, 0, func(b M) { b["body_sha256"] = strings.TrimPrefix(digest([]byte("é")), "sha256:") })
	v.Fixture["delivery"].(M)["text"] = b64([]byte("é"))
	add("PC3", "Non-ASCII delivered text is hashed as exact UTF-8 bytes.", "", "accept", v)
	v = base("envelope", 0)
	resign(&v, 0, func(b M) { b["body_sha256"] = strings.TrimPrefix(digest([]byte("é")), "sha256:") })
	v.Fixture["delivery"].(M)["text"] = b64([]byte("e\u0301"))
	add("C11", "Unicode-normalized equivalents are different delivered bytes.", "PC3", "message_text_mismatch", v)
	add("PA1", "Root-signed Ed25519 author attestation with exactly 86400-second validity verifies.", "", "accept", base("envelope", 0))
	v = base("grant", 0)
	v.Input["chain"] = vertexChain([]int{0, 6, 2})
	add("PA2", "Operator-root-attested P-256 device retains provenance in a grant.", "", "accept", v)
	v = base("envelope", 0)
	v.Fixture["snapshot_fault"] = M{"entries": []any{M{"kind": "key", "id": keys[0].ID, "from": "2026-01-01T00:01:01Z"}}}
	add("PA3", "Future revocation has no effect before its stated time.", "", "accept", v)
	add("PQ1", "A child raises its minimum from A1 to A2; established A2 satisfies it.", "", "accept", assuranceVector("A1", "A2", "A2", false, false, false))
	add("PQ2", "Equal A1 minima admit a higher established A2 request.", "", "accept", assuranceVector("A1", "A1", "A2", false, false, false))
	add("PQ3", "A child tightens presence and established presence satisfies it.", "", "accept", assuranceVector("A1", "A1", "A2", false, true, true))
	newRecordShapeVectors()

	v = base("operator", 0)
	v.Fixture["snapshot_fault"] = M{"device": true, "revoke_attestation": true}
	add("A27", "Revocation of an operator-device attestation invalidates its narrowing act.", "PO1", "revoked", v)
	v = base("operator", 0)
	v.Fixture["snapshot_fault"] = M{"device": true, "availability": "unavailable"}
	add("A28", "Missing operator-root snapshot refuses through the revocation availability code.", "PO1", "revocation_unavailable", v)
	v = base("envelope", 0)
	resign(&v, 0, func(b M) { b["room"] = strings.Repeat("x", 256) })
	add("C12", "Opaque room identifiers refuse at 256 ASCII bytes.", "PC4", "envelope_malformed", v)
	v = base("envelope", 0)
	resign(&v, 0, func(b M) { b["to"] = "" })
	add("C13", "An empty full recipient is invalid.", "PC4", "envelope_malformed", v)
	v = base("envelope", 0)
	delete(v.Fixture["delivery"].(M), "to")
	add("C14", "Missing actual recipient context is unavailable.", "PC1", "message_context_unavailable", v)
	v = base("envelope", 0)
	text := strings.Repeat("x", 255)
	resign(&v, 0, func(b M) { b["room"], b["to"] = text, text })
	v.Fixture["delivery"].(M)["room"], v.Fixture["delivery"].(M)["to"] = text, text
	add("PC4", "Opaque full carrier identifiers accept the inclusive 255-byte boundary.", "", "accept", v)
	v = base("operator", 0)
	v.Fixture["known_keys"] = nil
	add("PA6", "A root-attested operator device needs no direct device pin or known-key list.", "", "accept", v)
	v = base("envelope", 0)
	extraSignature(&v, false)
	v.Fixture["known_keys"] = []any{keys[0].ID}
	add("PA7", "A message approver uses its root attestation, without a separate device allowlist.", "", "accept", v)
	v = base("operator", 0)
	v.Fixture["binding"].(M)["owner"] = "owner-b"
	resign(&v, 6, func(b M) { b["owner"] = "owner-b" })
	add("A29", "Matching act and registration owner cannot borrow another owner's attested device.", "PO1", "key_binding_invalid", v)
	// All 30 directed pairs involving either newly registered tag, plus own-tag controls.
	tags := []string{"swarma-msg/2", "swarma-waggle grant/1", "swarma-waggle operator-act/1", "swarma-registrar registration/1", "swarma-registrar enrollment/1", "swarma-credential-broker grant/1", "swarma-credential-broker revocation/1", "swarma-attestation attestation/1", "swarma-attestation revocation/1"}
	n := 0
	payload := M{"probe": "domain separation"}
	for i, a := range tags {
		for j, b := range tags {
			if i == j || (i < 7 && j < 7) {
				continue
			}
			n++
			add(fmt.Sprintf("X%02d", n), "Exact tags never accept a cross-domain signature: "+b+" into "+a+".", fmt.Sprintf("PD%d", i+1), "envelope_signature_invalid", domainVector(a, b, payload))
		}
	}
	for i := 7; i < 9; i++ {
		add(fmt.Sprintf("PD%d", i+1), "The new exact attestation-domain tag verifies its own signature only.", "", "accept", domainVector(tags[i], tags[i], payload))
		add(fmt.Sprintf("X%02d", n+i-6), "The message byte signer refuses the attestation/revocation domain.", "PS1", "signer_domain_refused", signerVector(tagged(tags[i], canonical(payload))))
	}
}
func assuranceVector(parent, child, request string, pp, cp, rp bool) Vector {
	v := base("grant", 0)
	link(&v, 1, 0, func(b M) { b["min_assurance"] = M{"level": parent, "presence": pp} })
	id := decode(v.Input["chain"].([]any)[1].(string))["id"]
	link(&v, 0, 1, func(b M) { b["parent"] = id; b["min_assurance"] = M{"level": child, "presence": cp} })
	v.Fixture["assurance"] = M{"level": request, "presence": rp}
	return v
}

// Claims: new wire members and signed-evidence members retain the inherited
// missing/null versus invalid-type distinction. Valid controls are not rejected.
func newRecordShapeVectors() {
	n := 0
	paths := [][]any{{"type"}, {"issuer"}, {"subject"}, {"subject", "algorithm"}, {"subject", "key_id"}, {"subject", "public_bytes"}, {"key_class"}, {"purpose"}, {"roles"}, {"actions"}, {"iat"}, {"exp"}, {"binding"}, {"binding", "uid"}, {"binding", "generation"}, {"binding", "registration_number"}, {"binding", "master_epoch"}, {"binding", "owner"}, {"binding", "path"}}
	src := makeAttestation(keys[0].ID, context()["agent_evidence"].(M)[keys[0].ID].(M), 1000)
	for _, path := range paths {
		original := atPath(src, path)
		variants := []struct {
			name   string
			value  any
			remove bool
		}{{name: "missing", remove: true}, {name: "null", value: nil}}
		for _, x := range []any{true, 1, "x", []any{}, M{}} {
			if jsonKind(x) != jsonKind(original) {
				variants = append(variants, struct {
					name   string
					value  any
					remove bool
				}{jsonKind(x), x, false})
			}
		}
		for _, tc := range variants {
			n++
			v := base("envelope", 0)
			v.Fixture["record_mutation"] = M{"collection": "attestations", "key": keys[0].ID, "path": path, "value": tc.value, "remove": tc.remove}
			code := "key_binding_invalid"
			if tc.remove || tc.value == nil {
				code = "key_binding_unavailable"
			}
			add(fmt.Sprintf("Z%03d", n), fmt.Sprintf("Signed attestation field %v with %s yields the typed evidence refusal.", path, tc.name), "PA1", code, v)
		}
	}
	for _, path := range [][]any{{"room"}, {"to"}, {"body_sha256"}} {
		for _, x := range []any{nil, true, 1, []any{}, M{}} {
			n++
			v := base("envelope", 0)
			resign(&v, 0, func(b M) { setPath(b, path, x) })
			add(fmt.Sprintf("Z%03d", n), fmt.Sprintf("New signed delivery field %v rejects %s.", path, jsonKind(x)), "PC1", "envelope_malformed", v)
		}
	}
	for _, path := range [][]any{{"min_assurance"}, {"min_assurance", "level"}, {"min_assurance", "presence"}} {
		v := base("grant", 0)
		b := decode(v.Input["chain"].([]any)[0].(string))["body"].(M)
		original := atPath(b, path)
		for _, x := range []any{nil, true, 1, "x", []any{}, M{}} {
			if jsonKind(x) == jsonKind(original) {
				continue
			}
			n++
			v := base("grant", 0)
			link(&v, 0, 1, func(b M) { setPath(b, path, x) })
			add(fmt.Sprintf("Z%03d", n), fmt.Sprintf("New grant minimum field %v rejects %s.", path, jsonKind(x)), "PQ1", "envelope_malformed", v)
		}
	}
	for _, tc := range []struct {
		claim, code string
		value       M
	}{
		{"A caller cannot establish A3 in v0 by setting its level field.", "grant_assurance_unavailable", M{"level": "A3", "presence": true}},
		{"Missing request assurance is unavailable.", "grant_assurance_unavailable", nil},
		{"A nonboolean presence result cannot satisfy a minimum.", "grant_assurance_unavailable", M{"level": "A2", "presence": 1}},
	} {
		n++
		v := base("grant", 0)
		v.Fixture["assurance"] = tc.value
		add(fmt.Sprintf("Z%03d", n), tc.claim, "PQ1", tc.code, v)
	}
	for i, tc := range []struct {
		claim  string
		fields M
		path   []any
		value  any
	}{
		{claim: "Unknown attestation body members refuse.", fields: M{"extra": true}},
		{claim: "An agent attestation binding cannot include unsigned-style active metadata.", path: []any{"binding", "active"}, value: true},
		{claim: "Boolean true is not UID 1.", path: []any{"binding", "uid"}, value: true},
		{claim: "A device purpose is not permitted on an agent author.", fields: M{"purpose": "operator-device"}},
	} {
		v := base("envelope", 0)
		v.Fixture["record_mutation"] = M{"collection": "attestations", "key": keys[0].ID, "fields": tc.fields, "path": tc.path, "value": tc.value}
		add(fmt.Sprintf("A%02d", i+21), tc.claim, "PA1", "key_binding_invalid", v)
	}
	v := base("envelope", 0)
	v.Fixture["context_edits"] = M{"service_root": M{"key": keys[5].ID, "purpose": true}}
	add("A25", "Boolean root purpose is not integer signing-service purpose 5.", "PA1", "key_binding_invalid", v)
	v = base("grant", 0)
	v.Fixture["record_mutation"] = M{"collection": "revocations", "key": keys[0].ID, "corrupt": true}
	add("A26", "Owner-domain revocation signature is verified, not merely available.", "PG1", "revocation_invalid", v)
	v = base("envelope", 0)
	v.Fixture["p256_root"] = "service"
	add("PA4", "A pinned P-256 purpose-5 service root verifies an Ed25519 agent attestation with a separately pinned registry snapshot.", "", "accept", v)
	v = base("operator", 0)
	v.Fixture["p256_root"] = "operator"
	add("PA5", "A pinned P-256 operator root verifies an explicit P-256 device attestation and narrowing act.", "", "accept", v)
}
