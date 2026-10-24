package verifier

import (
	"bytes"

	"github.com/relux-works/waggle/record"
)

func distinct(f facts) {
	pins := []any{obj(f["service_root"])["key"], obj(f["agent_revocation_root"])["key"], f["operator_root"], f["root"]}
	seen := map[string]bool{}
	for _, p := range pins {
		if s, ok := p.(string); ok {
			need(!seen[s], "key_binding_invalid")
			seen[s] = true
		}
	}
}
func signed(v any, kind string, root any) map[string]any {
	need(v != nil, "key_binding_unavailable")
	raw, ok := v.([]byte)
	need(ok && len(raw) <= 8192, "key_binding_invalid")
	parsed := mapped(func() any { return must(record.Parse(raw, 8192, 16)) }, "*", "key_binding_invalid")
	e := evidenceExact(parsed, "version body id signatures")
	b := evidence(e["body"], "type issuer")
	sigs, ok := e["signatures"].([]any)
	need(ok && len(sigs) == 1, "key_binding_invalid")
	sig := evidenceExact(sigs[0], "role key sig")
	mapped(func() bool {
		key(root)
		key(b["issuer"])
		key(sig["key"])
		hashID(e["id"])
		need(e["version"] == "swarm-envelope/2" && b["type"] == kind && equal(b["issuer"], root) && equal(sig["key"], root) && sig["role"] == "author", "key_binding_invalid")
		need(e["id"] == must(record.ContentID(kind, b)), "key_binding_invalid")
		need(isString(sig["sig"]), "key_binding_invalid")
		signature := must(record.DecodeBase64(str(sig["sig"]), 64))
		pre := must(record.SigningPreimage(kind, str(root), "author", b))
		need(record.VerifySignature(str(root), signature, pre) == nil, "key_binding_invalid")
		return true
	}, "*", "key_binding_invalid")
	return e
}
func principal(v any) map[string]any {
	m := evidence(v, "owner path generation registration_number master_epoch uid")
	need(len(m) == 6 || len(m) == 7 && m["active"] != nil, "key_binding_invalid")
	for _, k := range []string{"owner", "path", "generation", "master_epoch"} {
		text(m[k], "key_binding_invalid")
	}
	need(isInt(m["registration_number"]) && num(m["registration_number"]) >= 1 && num(m["registration_number"]) <= 9007199254740991 && isInt(m["uid"]) && num(m["uid"]) >= 0 && num(m["uid"]) <= 4294967294, "key_binding_invalid")
	return m
}
func currentDevice(f facts) {
	m := evidence(f["signer_facts"], "")
	need(isBool(m["current"]), "key_binding_unavailable")
	need(m["current"] == true, "key_binding_invalid")
}
func snapshot(f facts, root any, ids, keys []string) {
	distinct(f)
	records := evidence(f["revocations"], "")
	need(isString(root), "key_binding_invalid")
	r := evidence(records[str(root)], "availability max_age rollback_safe snapshot")
	need(isString(r["availability"]), "key_binding_invalid")
	need(r["availability"] != "unavailable", "key_binding_unavailable")
	need(r["availability"] == "available", "key_binding_invalid")
	need(isInt(r["max_age"]) && num(r["max_age"]) > 0 && num(r["max_age"]) <= 60 && isBool(r["rollback_safe"]), "key_binding_invalid")
	b := evidenceExact(signed(r["snapshot"], "revocation/1", root)["body"], "type issuer issued_at complete entries")
	entries, ok := b["entries"].([]any)
	need(isBool(b["complete"]) && ok, "key_binding_invalid")
	issued := mapped(func() int64 { return stamp(b["issued_at"]) }, "*", "key_binding_invalid")
	low, high := times(f)
	need(b["complete"] == true && r["rollback_safe"] == true && issued <= low && high-issued <= num(r["max_age"]), "key_binding_unavailable")
	type entry struct {
		kind, id string
		from     int64
	}
	valid := make([]entry, 0, len(entries))
	for _, v := range entries {
		m := evidenceExact(v, "kind id from")
		need(m["kind"] == "key" || m["kind"] == "record", "key_binding_invalid")
		when := mapped(func() int64 {
			n := stamp(m["from"])
			if m["kind"] == "key" {
				key(m["id"])
			} else {
				hashID(m["id"])
			}
			return n
		}, "*", "key_binding_invalid")
		valid = append(valid, entry{str(m["kind"]), str(m["id"]), when})
	}
	for _, e := range valid {
		if e.from > high {
			continue
		}
		set := ids
		if e.kind == "key" {
			set = keys
		}
		for _, s := range set {
			need(e.id != s, "revoked")
		}
	}
}
func attestation(keyID, reference string, device, revocations, message bool, f facts) map[string]any {
	distinct(f)
	collection := "attestations"
	lookup := reference
	if device {
		collection = "operator_attestations"
		lookup = keyID
	}
	records := evidence(f[collection], "")
	if !device {
		if !message {
			ids := evidence(f["agent_attestation_ids"], "")
			v := ids[keyID]
			need(v != nil, "key_binding_unavailable")
			mapped(func() bool { hashID(v); return true }, "*", "key_binding_invalid")
			reference = str(v)
			lookup = reference
		}
		need(reference != "", "key_binding_unavailable")
		need(record.IsContentID(reference), "key_binding_invalid")
	}
	v, ok := records[lookup]
	need(ok, "key_binding_unavailable")
	root := f["operator_root"]
	if device {
		need(root != nil, "key_binding_unavailable")
	} else {
		p := evidenceExact(f["service_root"], "key purpose")
		need(isInt(p["purpose"]) && num(p["purpose"]) == 5, "key_binding_invalid")
		root = p["key"]
	}
	e := signed(v, "attestation/1", root)
	b := evidenceExact(e["body"], "type issuer subject key_class purpose roles actions iat exp binding")
	s := evidenceExact(b["subject"], "algorithm key_id public_bytes")
	for _, k := range []string{"algorithm", "key_id", "public_bytes"} {
		need(isString(s[k]), "key_binding_invalid")
	}
	for _, k := range []string{"key_class", "purpose", "iat", "exp"} {
		need(isString(b[k]), "key_binding_invalid")
	}
	_, rolesOK := b["roles"].([]any)
	_, actionsOK := b["actions"].([]any)
	need(rolesOK && actionsOK, "key_binding_invalid")
	requested := keyID
	if message && !device {
		keyID = str(s["key_id"])
	}
	var alg string
	var public []byte
	var start, end int64
	mapped(func() bool {
		alg, public = key(keyID)
		sa, sp := key(s["key_id"])
		n := 32
		if device {
			n = 33
		}
		encoded := must(record.DecodeBase64(str(s["public_bytes"]), n))
		start, end = stamp(b["iat"]), stamp(b["exp"])
		need(record.ValidateKey(keyID) == nil && sa == alg && bytes.Equal(sp, public) && s["key_id"] == keyID && bytes.Equal(encoded, public) && end > start && (device || end-start <= 86400), "key_binding_invalid")
		return true
	}, "*", "key_binding_invalid")
	if device {
		need(alg == "p256" && s["algorithm"] == "P-256" && b["key_class"] == "operator-device" && b["purpose"] == "operator-device" && equal(b["roles"], []any{"act", "approver"}) && equal(b["actions"], []any{"act.sign", "grant.sign", "message.approve"}), "key_binding_invalid")
		owner := f["operator_owner"]
		need(owner != nil, "key_binding_unavailable")
		text(owner, "key_binding_invalid")
		binding := evidenceExact(b["binding"], "owner")
		text(binding["owner"], "key_binding_invalid")
		need(equal(owner, binding["owner"]), "key_binding_invalid")
	} else {
		need(alg == "ed25519" && s["algorithm"] == "Ed25519" && b["key_class"] == "agent" && b["purpose"] == "swarma-msg" && equal(b["roles"], []any{"author"}) && equal(b["actions"], []any{"message.sign"}), "key_binding_invalid")
		active := evidence(f["active_generations"], "")
		v, ok := active[keyID]
		need(ok, "key_binding_unavailable")
		c := evidence(v, "active")
		left, right := principal(b["binding"]), principal(c)
		need(len(left) == 6 && isBool(c["active"]) && c["active"] == true, "key_binding_invalid")
		for _, k := range []string{"owner", "path", "generation", "registration_number", "master_epoch", "uid"} {
			need(equal(left[k], right[k]), "key_binding_invalid")
		}
	}
	low, high := times(f)
	need(start <= low && high < end, "key_binding_invalid")
	if revocations {
		revoker := root
		if !device {
			policy := evidenceExact(f["agent_revocation_root"], "key purpose attestation_root")
			need(policy["purpose"] == "registry-revocation" && equal(policy["attestation_root"], root) && !equal(policy["key"], root), "key_binding_invalid")
			mapped(func() bool { key(policy["key"]); return true }, "*", "key_binding_invalid")
			revoker = policy["key"]
		}
		snapshot(f, revoker, []string{str(e["id"])}, []string{keyID})
	}
	if !device && !message {
		need(e["id"] == reference && keyID == requested, "key_binding_invalid")
	}
	return e
}
func grantRoot(f facts) string {
	v := f["root"]
	need(v != nil, "key_binding_unavailable")
	mapped(func() bool { key(v); return true }, "*", "key_binding_invalid")
	return str(v)
}
func grantBinding(key string, issuer bool, f facts) {
	if key == grantRoot(f) {
		return
	}
	devices := evidence(f["operator_attestations"], "")
	if _, ok := devices[key]; ok {
		attestation(key, "", true, true, false, f)
		currentDevice(f)
	} else {
		attestation(key, "", false, true, false, f)
		need(!issuer, "signature_profile_invalid")
	}
}
func revocation(f facts, root any, ids, keys []string) {
	defer func() {
		if x := recover(); x != nil {
			if c, ok := x.(refusal); ok {
				switch c {
				case "key_binding_unavailable":
					panic(refusal("revocation_unavailable"))
				case "key_binding_invalid":
					panic(refusal("revocation_invalid"))
				}
			}
			panic(x)
		}
	}()
	if root == nil {
		root = grantRoot(f)
	}
	snapshot(f, root, ids, keys)
}

// RevocationState is the specification's tri-state current revocation outcome.
type RevocationState string

const (
	NotRevoked  RevocationState = "not_revoked"
	Revoked     RevocationState = "revoked"
	Unavailable RevocationState = "unavailable"
)

// CheckRevocation evaluates signed snapshots for the exact root authority
// domain. Invalid evidence returns Unavailable plus a definite refusal error;
// it is not a fourth successful state. No historical-iat bypass exists.
func (v Verifier) CheckRevocation(root string, ids, keys []string) (state RevocationState, err error) {
	r := decide(func() Plan { snapshot(v.facts(), root, ids, keys); return Plan{} })
	switch r.Code {
	case "accept":
		return NotRevoked, nil
	case "revoked":
		return Revoked, nil
	case "key_binding_unavailable", "time_unavailable", "watermark_unavailable":
		return Unavailable, nil
	default:
		return Unavailable, &record.Error{Code: r.Code}
	}
}

// Attestation is cryptographically verified identity evidence, not authority.
type Attestation struct {
	ID    string
	Key   string
	Owner string
}

// VerifyAttestation verifies agent evidence by an exact content reference, or
// device evidence by key when device is true; it includes current revocation.
func (v Verifier) VerifyAttestation(key, reference string, device bool) (a Attestation, err error) {
	r := decide(func() Plan {
		e := attestation(key, reference, device, true, !device && reference != "", v.facts())
		b := obj(e["body"])
		s := obj(b["subject"])
		a = Attestation{ID: str(e["id"]), Key: str(s["key_id"]), Owner: str(obj(b["binding"])["owner"])}
		return Plan{}
	})
	if r.Code != "accept" {
		return Attestation{}, &record.Error{Code: r.Code}
	}
	return a, nil
}
