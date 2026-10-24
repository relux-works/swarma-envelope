package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func defaultAttestationID(idx int) string {
	if idx >= 6 {
		idx = 0
	} // Invalid P-256 agent profiles still reach E6.
	f := context()
	b := makeAttestation(keys[idx].ID, f["agent_evidence"].(M)[keys[idx].ID].(M), 1000+idx)
	return decode(evidenceWire(b, keys[5]))["id"].(string)
}

// Accepted fixtures that deliberately change agent evidence must sign its exact
// id. Negative evidence retains its earlier failure before the final id check.
func bindAcceptedMessage(v *Vector) {
	if v.Mode != "envelope" || v.Expected["code"] != "accept" {
		return
	}
	e := decode(v.Input["envelope"].(string))
	b := e["body"].(M)
	records, ok := v.Fixture["attestations"].(M)
	if !ok {
		return
	}
	raw, ok := records[b["author"].(string)].(string)
	if !ok {
		return
	}
	id := decode(raw)["id"]
	if b["author_attestation"] == id {
		return
	}
	b["author_attestation"] = id
	e["id"] = digest(append([]byte(domain("message/1")+"\n"), canonical(b)...))
	for _, value := range e["signatures"].([]any) {
		s := value.(M)
		for _, k := range keys {
			if k.ID == s["key"] {
				s["sig"] = b64(sign(k, sigPre(b, s["role"].(string), k.ID, "message/1")))
			}
		}
	}
	v.Input["envelope"] = wire(e)
	v.Expected["plan"].(M)["ids"] = []any{e["id"]}
}

// Fixture adapter implements content-addressed lookup. A returned record is
// still checked against the requested address; a dictionary key is no proof.
func indexAttestations(v *Vector) {
	records, ok := v.Fixture["attestations"].(M)
	if !ok {
		return
	}
	indexed, current := M{}, M{}
	var message M
	if v.Mode == "envelope" {
		var e M
		_ = json.Unmarshal(unb64(v.Input["envelope"].(string)), &e)
		message, _ = e["body"].(M)
	}
	for key, value := range records {
		idx := 0
		for i, k := range keys {
			if k.ID == key {
				idx = i
			}
		}
		lookup := defaultAttestationID(idx)
		if raw, ok := value.(string); ok {
			var e M
			decoded, err := base64.RawURLEncoding.DecodeString(raw)
			if err == nil && json.Unmarshal(decoded, &e) == nil {
				if id, ok := e["id"].(string); ok && len(id) == 71 {
					lookup = id
				}
			}
		}
		if message != nil && message["author"] == key {
			if id, ok := message["author_attestation"].(string); ok && len(id) == 71 {
				lookup = id
			}
		}
		indexed[lookup], current[key] = value, lookup
	}
	v.Fixture["attestations"], v.Fixture["agent_attestation_ids"] = indexed, current
}

func reviewSource(id string) Vector {
	for _, v := range cases {
		if v.ID == id {
			return copyVector(v)
		}
	}
	panic("missing content review source")
}
func authorRecord(v Vector) M {
	return decode(v.Fixture["attestations"].(M)[body(v)["author_attestation"].(string)].(string))
}
func replaceAuthorRecord(v *Vector, change func(M)) {
	ref := body(*v)["author_attestation"].(string)
	e := authorRecord(*v)
	change(e["body"].(M))
	v.Fixture["attestations"].(M)[ref] = evidenceWire(e["body"].(M), keys[5])
}
func reviewSnapshot(v *Vector, change func(M)) {
	orderSnapshot(v, 7, false, change)
}

// Claims: exact signed attestation identity survives stable-key registration
// changes and concurrent certificates; earlier evidence failures still win.
// These synthetic current-context witnesses do not prove real creation time.
func contentReviewVectors() {
	add("PW-binding", "The signed g0 message accepts with its exact g0 attestation and current binding.", "", "accept", reviewSource("PE1"))
	for _, field := range []string{"generation", "registration_number", "master_epoch"} {
		v := reviewSource("PE1")
		value := any("other-" + field)
		if field == "registration_number" {
			value = 2
		}
		replaceAuthorRecord(&v, func(b M) { b["binding"].(M)[field] = value })
		v.Fixture["active_generations"].(M)[keys[0].ID].(M)[field] = value
		v.Fixture["agent_attestation_ids"].(M)[keys[0].ID] = authorRecord(v)["id"]
		add("W-substitute-"+field, "A fully valid current attestation for the same stable key cannot replace the signed reference after changing "+field+".", "PW-binding", "author_attestation_mismatch", v)
	}
	v := reviewSource("W-substitute-generation")
	ref := body(v)["author_attestation"].(string)
	records := v.Fixture["attestations"].(M)
	other := records[ref].(string)
	delete(records, ref)
	records[decode(other)["id"].(string)] = other
	add("W-only-newer", "Lookup by signed content id never falls back to the current attestation of the same key.", "PW-binding", "key_binding_unavailable", v)
	v = reviewSource("PE1")
	f := context()
	other = evidenceWire(makeAttestation(keys[2].ID, f["agent_evidence"].(M)[keys[2].ID].(M), 1002), keys[5])
	otherID := decode(other)["id"].(string)
	v.Fixture["attestations"].(M)[otherID] = other
	v.Fixture["active_generations"].(M)[keys[2].ID] = bindingRecord(f["agent_expected"].(M)[keys[2].ID], 1002)
	v.Fixture["active_generations"].(M)[keys[2].ID].(M)["active"] = true
	resign(&v, 0, func(b M) { b["author_attestation"] = otherID })
	add("W-other-key", "A fully verified referenced attestation of another key cannot attest the signed author.", "PW-binding", "author_attestation_mismatch", v)
	v = reviewSource("PE1")
	replaceAuthorRecord(&v, func(b M) { b["exp"] = v.Fixture["now"] })
	expired := authorRecord(v)
	expiredID := expired["id"].(string)
	v.Fixture["attestations"].(M)[expiredID] = v.Fixture["attestations"].(M)[body(v)["author_attestation"].(string)]
	resign(&v, 0, func(b M) { b["author_attestation"] = expiredID })
	add("W-expired-reference", "The exact referenced attestation must still be unexpired.", "PW-binding", "key_binding_invalid", v)
	v = reviewSource("PE1")
	reviewSnapshot(&v, func(b M) {
		b["entries"] = []any{M{"kind": "record", "id": body(v)["author_attestation"], "from": v.Fixture["now"]}}
	})
	add("W-revoked-reference", "Revocation of the exact referenced attestation refuses even with a live stable key.", "PW-binding", "revoked", v)
	for _, tc := range []struct {
		name    string
		value   any
		missing bool
	}{
		{"missing", nil, true}, {"null", nil, false}, {"short", "sha256:x", false}, {"uppercase", "sha256:" + strings.Repeat("A", 64), false}, {"boolean", true, false},
	} {
		v := reviewSource("PE1")
		resign(&v, 0, func(b M) {
			if tc.missing {
				delete(b, "author_attestation")
			} else {
				b["author_attestation"] = tc.value
			}
		})
		add("W-reference-"+tc.name, "The required signed author_attestation rejects "+tc.name+" at E2.", "PW-binding", "envelope_malformed", v)
	}
	v = reviewSource("PE1")
	e := authorRecord(v)
	e["body"].(M)["iat"] = "2026-01-01T00:00:01Z"
	other = evidenceWire(e["body"].(M), keys[5])
	otherID = decode(other)["id"].(string)
	v.Fixture["attestations"].(M)[otherID] = other
	add("PW-concurrent-first", "Two concurrent valid attestations of one key/generation do not interfere with the referenced first record.", "", "accept", v)
	w := copyVector(v)
	w.Fixture["attestations"].(M)[body(w)["author_attestation"].(string)] = other
	add("W-concurrent-substitute", "The other concurrent valid attestation cannot replace the exact signed record.", "PW-concurrent-first", "author_attestation_mismatch", w)
	v = copyVector(v)
	resign(&v, 0, func(b M) { b["author_attestation"] = otherID })
	add("PW-concurrent-second", "The second concurrent attestation accepts when its own id is signed.", "", "accept", v)

	for _, tc := range []struct {
		name, code string
		apply      func(*Vector)
	}{
		{"E6-signature", "envelope_signature_invalid", func(v *Vector) {
			edit(v, func(e M) {
				s := e["signatures"].([]any)[0].(M)
				raw := unb64(s["sig"].(string))
				raw[5] ^= 1
				s["sig"] = b64(raw)
			})
		}},
		{"E7-audience", "audience_mismatch", func(v *Vector) { v.Fixture["audience"] = "other-service" }},
		{"T2-expiry", "expired", func(v *Vector) { v.Fixture["watermark"] = "2026-01-01T00:02:00Z" }},
		{"K1-root-signature", "key_binding_invalid", func(v *Vector) {
			ref := body(*v)["author_attestation"].(string)
			e := authorRecord(*v)
			s := e["signatures"].([]any)[0].(M)
			raw := unb64(s["sig"].(string))
			raw[5] ^= 1
			s["sig"] = b64(raw)
			v.Fixture["attestations"].(M)[ref] = wire(e)
		}},
		{"K1-revoked", "revoked", func(v *Vector) {
			reviewSnapshot(v, func(b M) {
				b["entries"] = []any{M{"kind": "key", "id": authorRecord(*v)["body"].(M)["subject"].(M)["key_id"], "from": v.Fixture["now"]}}
			})
		}},
	} {
		for _, source := range []string{"W-substitute-generation", "W-substitute-registration_number", "W-concurrent-substitute", "W-other-key"} {
			v := reviewSource(source)
			tc.apply(&v)
			add("U-reference-"+tc.name+"-"+source, "Earlier "+tc.name+" wins before the final fully-verified author/reference equality.", "PW-binding", tc.code, v)
		}
	}
	// A separately scoped raw device signer signs the exact S0 preimage.
	v = reviewSource("PO1")
	edit(&v, func(e M) {
		s := e["signatures"].([]any)[0].(M)
		s["authenticatorData"] = "AA"
		s["clientDataJSON"] = "e30"
	})
	add("W-assertion-wrapper", "Assertion wrapper members are forbidden by the closed signature-entry schema.", "PO1", "envelope_malformed", v)
	v = reviewSource("PO1")
	e = decode(v.Input["envelope"].(string))
	rp := sha256.Sum256([]byte("test.invalid"))
	auth := append(append([]byte{}, rp[:]...), 1, 0, 0, 0, 1)
	client := canonical(M{"type": "webauthn.get", "challenge": b64([]byte(e["id"].(string))), "origin": "https://test.invalid", "crossOrigin": false})
	ch := sha256.Sum256(client)
	construction := append(append([]byte{}, auth...), ch[:]...)
	e["signatures"].([]any)[0].(M)["sig"] = b64(sign(keys[6], construction))
	v.Input["envelope"] = wire(e)
	v.Fixture["assertion_construction"] = M{"authenticator_data": b64(auth), "client_data_json": b64(client)}
	add("W-webauthn-signature", "A real low-S P-256 WebAuthn-construction signature with content-id challenge is not a raw-preimage signature.", "PO1", "envelope_signature_invalid", v)
	// Materialize this explicit agent-issuer control without changing its class.
	v = base("grant", 0)
	v.Input["chain"] = vertexChain([]int{0, 3, 2})
	v.ID = "W-agent-issuer"
	v.Expected = M{"code": "signature_profile_invalid", "plan": M{}}
	pruneAgentEvidence(&v)
	materializeEvidence(&v)
	indexAttestations(&v)
	add("W-agent-issuer", "A valid agent attestation grants message.sign only, never grant issuance.", "PG1", "signature_profile_invalid", v)
	for _, tc := range []struct {
		name, code string
		apply      func(*Vector)
	}{
		{"purpose5-snapshot", "key_binding_invalid", func(v *Vector) {
			r := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			b := decode(r["snapshot"].(string))["body"].(M)
			b["issuer"] = keys[5].ID
			r["snapshot"] = evidenceWire(b, keys[5])
		}},
		{"revoker-attestation", "key_binding_invalid", func(v *Vector) {
			ref := body(*v)["author_attestation"].(string)
			b := authorRecord(*v)["body"].(M)
			b["issuer"] = keys[7].ID
			raw := evidenceWire(b, keys[7])
			id := decode(raw)["id"].(string)
			delete(v.Fixture["attestations"].(M), ref)
			v.Fixture["attestations"].(M)[id] = raw
			resign(v, 0, func(body M) { body["author_attestation"] = id })
		}},
		{"revoker-scope", "key_binding_invalid", func(v *Vector) { v.Fixture["agent_revocation_root"].(M)["attestation_root"] = keys[4].ID }},
		{"revoker-purpose", "key_binding_invalid", func(v *Vector) { v.Fixture["agent_revocation_root"].(M)["purpose"] = 5 }},
		{"revoker-missing", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture, "agent_revocation_root") }},
	} {
		v := reviewSource("PE1")
		tc.apply(&v)
		add("W-"+tc.name, "Separately pinned registry revocation authority rejects "+tc.name+".", "PW-binding", tc.code, v)
	}
	v = base("grant", 0)
	v.Input["chain"] = vertexChain([]int{5, 2})
	v.Fixture["root"] = keys[5].ID
	v.Expected = M{"code": "signature_profile_invalid", "plan": M{}}
	pruneAgentEvidence(&v)
	materializeEvidence(&v)
	indexAttestations(&v)
	add("W-purpose5-grant", "A conflicting grant root pin cannot widen the purpose-5 key's attestation-only signing language.", "PG1", "signature_profile_invalid", v)
	revocationBoundVectors()
	signerAttestationVectors()
}

// Claims: the exact third signer identity path is mandatory under narrowing;
// caller-context resolution wins before path shape, which wins before equality.
func signerAttestationVectors() {
	change := func(v *Vector, fn func(M)) {
		raw := unb64(v.Input["preimage"].(string))
		p := decode(b64(bytes.SplitN(raw, []byte{'\n'}, 2)[1]))
		fn(p)
		v.Input["preimage"] = b64(tagged("swarma-msg/2", canonical(p)))
	}
	for _, tc := range []struct {
		name, code string
		apply      func(*Vector)
	}{
		{"missing", "signer_identity_malformed", func(v *Vector) { change(v, func(p M) { delete(p["body"].(M), "author_attestation") }) }},
		{"alias", "signer_identity_malformed", func(v *Vector) {
			change(v, func(p M) {
				b := p["body"].(M)
				b["attestation"] = b["author_attestation"]
				delete(b, "author_attestation")
			})
		}},
		{"null", "signer_identity_malformed", func(v *Vector) { change(v, func(p M) { p["body"].(M)["author_attestation"] = nil }) }},
		{"boolean", "signer_identity_malformed", func(v *Vector) { change(v, func(p M) { p["body"].(M)["author_attestation"] = true }) }},
		{"number", "signer_identity_malformed", func(v *Vector) { change(v, func(p M) { p["body"].(M)["author_attestation"] = 1 }) }},
		{"object", "signer_identity_malformed", func(v *Vector) { change(v, func(p M) { p["body"].(M)["author_attestation"] = M{} }) }},
		{"both-missing", "signer_identity_unavailable", func(v *Vector) {
			delete(v.Fixture, "caller_attestation_id")
			change(v, func(p M) { delete(p["body"].(M), "author_attestation") })
		}},
		{"multi-agent", "signer_identity_mismatch", func(v *Vector) {
			v.Fixture["identity_check"] = false
			change(v, func(p M) { p["body"].(M)["author_attestation"] = "other-attestation" })
		}},
		{"duplicate-escaped", "signer_payload_invalid", func(v *Vector) {
			raw := unb64(v.Input["preimage"].(string))
			v.Input["preimage"] = b64(bytes.Replace(raw, []byte(`"author_attestation":`), []byte(`"author_\u0061ttestation":"x","author_attestation":`), 1))
		}},
		{"array", "signer_identity_malformed", func(v *Vector) { change(v, func(p M) { p["body"].(M)["author_attestation"] = []any{} }) }},
		{"other", "signer_identity_mismatch", func(v *Vector) {
			change(v, func(p M) { p["body"].(M)["author_attestation"] = "sha256:" + strings.Repeat("0", 64) })
		}},
		{"caller-missing", "signer_identity_unavailable", func(v *Vector) { delete(v.Fixture, "caller_attestation_id") }},
		{"caller-invalid", "signer_identity_unavailable", func(v *Vector) { v.Fixture["caller_attestation_id"] = "sha256:x" }},
		{"duplicate", "signer_payload_invalid", func(v *Vector) {
			raw := unb64(v.Input["preimage"].(string))
			v.Input["preimage"] = b64(bytes.Replace(raw, []byte(`"author_attestation":`), []byte(`"author_attestation":"x","author_attestation":`), 1))
		}},
	} {
		v := reviewSource("PI1")
		tc.apply(&v)
		add("I-attestation-"+tc.name, "Signer third identity path rejects "+tc.name+" without signing.", "PI1", tc.code, v)
	}
}

// Claims: omitting snapshots expire by the first-containing deadline; future
// entries remain inactive until from, then refuse in a fresh cumulative record.
// Issuer publication and cross-process continuity are external obligations.
func revocationBoundVectors() {
	for _, tc := range []struct {
		name, now, issued, from, code string
		entry                         bool
	}{
		{"before-deadline", "2026-01-01T00:01:59Z", "2026-01-01T00:00:59Z", "", "accept", false},
		{"deadline-stale", "2026-01-01T00:02:00Z", "2026-01-01T00:00:59Z", "", "key_binding_unavailable", false},
		{"deadline-containing", "2026-01-01T00:02:00Z", "2026-01-01T00:01:00Z", "2026-01-01T00:01:00Z", "revoked", true},
		{"future-before", "2026-01-01T00:02:00Z", "2026-01-01T00:01:00Z", "2026-01-01T00:02:01Z", "accept", true},
		{"future-at", "2026-01-01T00:02:01Z", "2026-01-01T00:01:01Z", "2026-01-01T00:02:01Z", "revoked", true},
	} {
		v := reviewSource("PE1")
		resign(&v, 0, func(b M) { b["iat"] = "2026-01-01T00:00:30Z"; b["exp"] = "2026-01-01T00:02:30Z" })
		v.Fixture["now"], v.Fixture["watermark"] = tc.now, tc.now
		reviewSnapshot(&v, func(b M) {
			b["issued_at"] = tc.issued
			b["entries"] = []any{}
			if tc.entry {
				b["entries"] = []any{M{"kind": "key", "id": keys[0].ID, "from": tc.from}}
			}
		})
		prefix, pair := "W-", "PW-bound-before-deadline"
		if tc.code == "accept" {
			prefix, pair = "PW-", ""
		}
		add(prefix+"bound-"+tc.name, "Snapshot distribution boundary: "+tc.name+"; this does not simulate an issuer or continuity witness.", pair, tc.code, v)
	}
}
