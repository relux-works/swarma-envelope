package verifier

import (
	"github.com/relux-works/swarma-envelope/record"
	"strings"
)

func envelope(raw []byte, kind string, f facts) map[string]any {
	limit := 65536
	if kind == "operator-act/1" {
		limit = 8192
	}
	e, ok := must(record.Parse(raw, limit, 16)).(map[string]any)
	need(ok, "envelope_malformed")
	schema(e, kind)
	b := obj(e["body"])
	sigs := array(e["signatures"])
	need(e["version"] == "swarm-envelope/2", "envelope_version_unsupported")
	need(b["type"] == kind, "envelope_type_mismatch")
	roles := []any{}
	if kind != "grant/1" {
		need(f["required_roles"] != nil, "signer_unavailable")
		var ok bool
		roles, ok = stringsArray(f["required_roles"])
		need(ok, "envelope_role_invalid")
		for _, r := range roles {
			need(r == "author" || r == "approver" || r == "delegate", "envelope_role_invalid")
		}
	}
	required := "author"
	if kind == "operator-act/1" {
		required = "approver"
	}
	seen := map[string]bool{}
	present := map[string]bool{}
	for _, v := range sigs {
		s := obj(v)
		r, k := str(s["role"]), str(s["key"])
		need(r == "author" || r == "approver" || r == "delegate", "envelope_role_invalid")
		pair := r + "\x00" + k
		need(!seen[pair], "envelope_role_invalid")
		seen[pair] = true
		present[r] = true
	}
	need(present[required], "envelope_role_invalid")
	for _, r := range roles {
		need(present[str(r)], "envelope_role_invalid")
	}
	if kind != "message/1" {
		need(len(sigs) == 1 && obj(sigs[0])["role"] == required, "envelope_role_invalid")
	}
	need(e["id"] == must(record.ContentID(kind, b)), "envelope_id_mismatch")
	for _, v := range sigs {
		s := obj(v)
		r, k := str(s["role"]), str(s["key"])
		if kind == "grant/1" {
			need(s["key"] == b["issuer"], "signer_unknown")
		} else if kind == "message/1" && r == "author" {
			need(f["known_keys"] != nil, "signer_unavailable")
			known, ok := stringsArray(f["known_keys"])
			need(ok && includes(known, k) && s["key"] == b["author"], "signer_unknown")
		}
		alg, _ := key(k)
		allowed := kind == "message/1" && (r == "author" && alg == "ed25519" || r == "approver" && alg == "p256") || kind == "operator-act/1" && r == "approver" && alg == "p256" || kind == "grant/1" && r == "author" && (alg == "ed25519" || alg == "p256")
		service := obj(f["service_root"])
		need(service == nil || service["key"] != k, "signature_profile_invalid")
		need(allowed && !excludedSigner(k, kind, f), "signature_profile_invalid")
		pre := must(record.SigningPreimage(kind, k, r, b))
		if kind == "message/1" {
			need(len(pre) <= 24576, "signature_preimage_too_large")
			mapped(func() bool { must(record.Parse(pre[len(record.Tag(kind))+1:], 24576, 12)); return true }, "*", "signature_preimage_invalid")
		}
		// Strict subject crypto follows E6 issuer/profile admission.
		if kind == "grant/1" {
			need(record.ValidateKey(str(b["subject"])) == nil, "envelope_signature_invalid")
		}
		signature := must(record.DecodeBase64(str(s["sig"]), 64))
		if err := record.VerifySignature(k, signature, pre); err != nil {
			panic(refusal(errorCode(err)))
		}
	}
	need(ascii(f["audience"]) && equal(f["audience"], b["aud"]), "audience_mismatch")
	if kind == "message/1" {
		delivery(b, f)
	}
	low, high := times(f)
	receiptGate(f, low, high)
	window(b, low, high)
	if kind == "message/1" {
		a := attestation(str(b["author"]), str(b["author_attestation"]), false, true, true, f)
		has := false
		for _, s := range sigs {
			if obj(s)["role"] == "approver" {
				has = true
			}
		}
		if has {
			currentDevice(f)
			for _, s := range sigs {
				m := obj(s)
				if m["role"] == "approver" {
					attestation(str(m["key"]), "", true, true, false, f)
				}
			}
		}
		need(a["id"] == b["author_attestation"] && obj(obj(a["body"])["subject"])["key_id"] == b["author"], "author_attestation_mismatch")
	} else if kind == "grant/1" {
		grantBinding(str(b["issuer"]), true, f)
		grantBinding(str(b["subject"]), false, f)
	}
	journal(e, raw, f)
	return e
}
func plan(es []map[string]any, f facts) Plan {
	ids := make([]string, len(es))
	for i, e := range es {
		ids[i] = str(e["id"])
	}
	w := str(f["now"])
	if str(f["watermark"]) > w {
		w = str(f["watermark"])
	}
	return Plan{IDs: ids, Watermark: w}
}

// VerifyEnvelope runs E1–E8 for a caller-selected message, grant or operator
// type. It does not replace grant-chain authorization or O1–O5 act validation.
func (v Verifier) VerifyEnvelope(raw []byte, kind string) Result {
	return decide(func() Plan { f := v.consumerFacts(); e := envelope(raw, kind, f); return plan([]map[string]any{e}, f) })
}

// VerifyMessage checks receiver identity, all approvers, delivery and exact text
// binding. Caller handler-schema and concrete authority checks remain mandatory.
func (v Verifier) VerifyMessage(raw []byte) Result { return v.VerifyEnvelope(raw, "message/1") }

// VerifyOperator checks the complete operator-act/1 pipeline, including exact
// protected arguments/binding, currency, revocation, replay and closed widening.
func (v Verifier) VerifyOperator(raw []byte) Result {
	return decide(func() Plan {
		f := v.consumerFacts()
		e := envelope(raw, "operator-act/1", f)
		b := obj(e["body"])
		operation := str(b["operation"])
		need(operation == "revoke" || operation == "grant.issue", "act_operation_unknown")
		kind := "registration"
		widen := operation == "grant.issue"
		if widen {
			kind = "account"
		}
		binding := obj(f["binding"])
		need(binding != nil, "act_binding_mismatch")
		for _, n := range []string{"operation", "target", "owner", "epoch", "arguments"} {
			_, ok := binding[n]
			need(ok, "act_binding_mismatch")
		}
		text(binding["owner"], "act_binding_mismatch")
		need(ascii(binding["epoch"]) && isString(binding["operation"]) && ident(strings.ReplaceAll(str(binding["operation"]), ".", "/"), false, false) && target(binding["target"], false, true) && obj(binding["arguments"]) != nil, "act_binding_mismatch")
		need(equal(b["operation"], binding["operation"]) && equal(b["target"], binding["target"]) && obj(b["target"])["kind"] == kind && equal(b["owner"], binding["owner"]) && equal(b["epoch"], binding["epoch"]) && b["arguments_digest"] == mapped(func() string { return record.Digest(canonical(binding["arguments"])) }, "*", "act_binding_mismatch"), "act_binding_mismatch")
		return operatorTail(e, f, widen)
	})
}

// operatorTail is the shared O2–O5 continuation. The caller must have run
// the common envelope pipeline and its selected operation's complete O1 binding.
// It returns only a prospective plan and does not reserve or perform an effect.
func operatorTail(e map[string]any, f facts, widen bool) Plan {
	b := obj(e["body"])
	if c, selected := f["_ownerActContext"].(OwnerActContext); selected {
		ownerAuthority(e, f, c)
	} else {
		distinct(f)
		currentDevice(f)
	}
	signer := str(obj(array(e["signatures"])[0])["key"])
	a := attestation(signer, "", true, false, false, f)
	need(obj(obj(a["body"])["binding"])["owner"] == b["owner"], "key_binding_invalid")
	revocation(f, f["operator_root"], []string{str(e["id"]), str(a["id"])}, []string{signer})
	if widen || f["_ownerActPresence"] == true {
		need(b["confirmed"] == true, "act_confirmation_required")
		facts := obj(f["signer_facts"])
		need(facts["presence"] == true && facts["presence_current"] == true, "act_presence_required")
	}
	need(f["replay_available"] == true, "replay_unavailable")
	used, ok := stringsArray(f["used_actions"])
	need(ok, "replay_unavailable")
	need(!includes(used, b["action_id"]), "act_replay")
	need(!widen && f["_ownerActRestricted"] != true, "act_a3_inactive")
	p := plan([]map[string]any{e}, f)
	p.ActionID = str(b["action_id"])
	return p
}

func contained(p, c map[string]any) bool {
	if p["kind"] != c["kind"] {
		return false
	}
	if p["kind"] == "credential" && (p["harness"] != c["harness"] || p["profile"] != c["profile"]) {
		return false
	}
	parent, child := str(p["id"]), str(c["id"])
	if !strings.HasSuffix(parent, "/*") {
		return parent == child
	}
	parent = strings.TrimSuffix(parent, "/*")
	if strings.HasSuffix(child, "/*") {
		child = strings.TrimSuffix(child, "/*")
		return child == parent || strings.HasPrefix(child, parent+"/")
	}
	return strings.HasPrefix(child, parent+"/")
}
func effective(b map[string]any) (int64, int64) {
	if c := obj(b["caveats"]); c != nil {
		return stamp(c["not_before"]), stamp(c["expires"])
	}
	return stamp(b["iat"]), stamp(b["exp"])
}
func actionKind(action string) string {
	switch action {
	case "credential.lease":
		return "credential"
	case "agent.spawn", "message.deliver":
		return "station"
	}
	return ""
}

// Authorize validates a leaf-first chain for exactly one closed concrete
// request {key,action,target}. request is protected authenticated caller input.
func (v Verifier) Authorize(chain [][]byte, request Evidence) Result {
	return decide(func() Plan {
		f := v.consumerFacts()
		need(len(chain) >= 1 && len(chain) <= 4, "grant_chain_malformed")
		total := 0
		for _, r := range chain {
			total += len(r)
		}
		need(total <= 262144, "envelope_too_large")
		ids := make([]string, len(chain))
		unique := map[string]bool{}
		for i, r := range chain {
			// G1 examines ids for uniqueness; E1 lexical failures retain their own code.
			parsed := must(record.Parse(r, 65536, 16))
			id := obj(parsed)["id"]
			need(isString(id) && !unique[str(id)], "grant_chain_malformed")
			unique[str(id)] = true
			ids[i] = str(id)
		}
		var rv any
		if request.available {
			rv = request.value
		}
		req := exact(rv, "key action target", "grant_chain_malformed")
		mapped(func() bool {
			key(req["key"])
			need(isString(req["action"]), "envelope_malformed")
			t := obj(req["target"])
			need(t != nil && isString(t["kind"]), "envelope_malformed")
			names := "kind id"
			if t["kind"] == "credential" {
				names += " harness profile"
			}
			exact(t, names, "envelope_malformed")
			for _, x := range t {
				need(isString(x), "envelope_malformed")
			}
			return true
		}, "*", "grant_chain_malformed")
		es := make([]map[string]any, len(chain))
		bs := make([]map[string]any, len(chain))
		for i, r := range chain {
			es[i] = envelope(r, "grant/1", f)
			bs[i] = obj(es[i]["body"])
		}
		for i := 0; i < len(bs)-1; i++ {
			c, p := bs[i], bs[i+1]
			need(c["parent"] == es[i+1]["id"] && c["issuer"] == p["subject"], "grant_chain_broken")
		}
		last := bs[len(bs)-1]
		need(last["parent"] == nil && last["issuer"] == grantRoot(f), "grant_root_unknown")
		for i := 0; i < len(bs)-1; i++ {
			c, p := bs[i], bs[i+1]
			cs, ce := effective(c)
			ps, pe := effective(p)
			narrow := num(c["depth"]) < num(p["depth"]) && stamp(c["iat"]) >= stamp(p["iat"]) && stamp(c["exp"]) <= stamp(p["exp"]) && cs >= ps && ce <= pe && c["aud"] == p["aud"]
			for _, a := range array(c["actions"]) {
				narrow = narrow && includes(array(p["actions"]), a)
			}
			for _, t := range array(c["targets"]) {
				covered := false
				for _, pt := range array(p["targets"]) {
					covered = covered || contained(obj(pt), obj(t))
				}
				narrow = narrow && covered
			}
			cl, cp := assurance(c["min_assurance"], "envelope_malformed")
			pl, pp := assurance(p["min_assurance"], "envelope_malformed")
			need(narrow && cl >= pl && (!pp || cp), "grant_not_narrowing")
		}
		for _, b := range bs {
			kinds := map[string]bool{}
			for _, a := range array(b["actions"]) {
				k := actionKind(str(a))
				need(k != "", "action_unregistered")
				kinds[k] = true
			}
			targets := map[string]bool{}
			for _, t := range array(b["targets"]) {
				targets[str(obj(t)["kind"])] = true
			}
			need(equal(kinds, targets), "grant_target_invalid")
		}
		low, high := times(f)
		receiptGate(f, low, high)
		for _, b := range bs {
			a, z := effective(b)
			need(high < z, "expired")
			need(low >= a, "not_yet_valid")
		}
		keys := []string{}
		for _, b := range bs {
			keys = append(keys, str(b["issuer"]), str(b["subject"]))
		}
		revocation(f, nil, ids, keys)
		need(target(req["target"], false, false), "request_target_invalid")
		k := actionKind(str(req["action"]))
		need(k != "", "action_unregistered")
		leaf := bs[0]
		covered := false
		for _, t := range array(leaf["targets"]) {
			covered = covered || contained(obj(t), obj(req["target"]))
		}
		need(req["key"] == leaf["subject"] && includes(array(leaf["actions"]), req["action"]) && k == str(obj(req["target"])["kind"]) && covered, "grant_not_authorized")
		minimum, presence := assurance(leaf["min_assurance"], "envelope_malformed")
		established, present := assurance(f["assurance"], "grant_assurance_unavailable")
		need(established < 3, "grant_assurance_unavailable")
		need(established >= minimum && (!presence || present), "grant_assurance_insufficient")
		return plan(es, f)
	})
}
