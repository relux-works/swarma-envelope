package main

import "strings"

// Claims: absent protected members become explicit ordered refusals, never a
// lookup/attribute exception. Null and malformed neighbors prevent defaulting
// missing policy to a permissive value. Every row retains a valid source.
// Q06 has valid widening evidence but reaches the deliberately closed O5 gate;
// PO1 is its accepted narrowing neighbor, never an invented widening success.
func contextVectors() {
	type field struct {
		name, source, positive, missing, malformed string
		path                                       []any
		bad                                        any
	}
	fields := []field{
		{"grant-root", "PR-root-only-grant", "PR-root-only-grant", "key_binding_unavailable", "key_binding_invalid", []any{"root"}, []any{}},
		{"message-role-policy", "PE1", "PE1", "signer_unavailable", "envelope_role_invalid", []any{"required_roles"}, M{}},
		{"act-role-policy", "PO1", "PO1", "signer_unavailable", "envelope_role_invalid", []any{"required_roles"}, M{}},
		{"known-keys", "PE1", "PE1", "signer_unavailable", "signer_unknown", []any{"known_keys"}, 1},
		{"message-id-availability", "PE1", "PE1", "id_journal_unavailable", "id_journal_unavailable", []any{"id_journal_available"}, "true"},
		{"grant-id-availability", "PG1", "PG1", "id_journal_unavailable", "id_journal_unavailable", []any{"id_journal_available"}, "true"},
		{"act-id-availability", "PO1", "PO1", "id_journal_unavailable", "id_journal_unavailable", []any{"id_journal_available"}, "true"},
		{"message-id-state", "PE1", "PE1", "id_journal_unavailable", "id_journal_unavailable", []any{"seen"}, []any{}},
		{"grant-id-state", "PG1", "PG1", "id_journal_unavailable", "id_journal_unavailable", []any{"seen"}, []any{}},
		{"act-id-state", "PO1", "PO1", "id_journal_unavailable", "id_journal_unavailable", []any{"seen"}, []any{}},
		{"grant-request", "PG1", "PG1", "grant_chain_malformed", "grant_chain_malformed", []any{"request"}, []any{}},
		{"replay-availability", "PO1", "PO1", "replay_unavailable", "replay_unavailable", []any{"replay_available"}, "true"},
		{"replay-state", "PO1", "PO1", "replay_unavailable", "replay_unavailable", []any{"used_actions"}, M{}},
		{"act-signer-facts", "PO1", "PO1", "key_binding_unavailable", "key_binding_invalid", []any{"signer_facts"}, []any{}},
		{"approver-signer-facts", "PE5", "PE5", "key_binding_unavailable", "key_binding_invalid", []any{"signer_facts"}, []any{}},
		{"grant-signer-facts", "PG1", "PG1", "key_binding_unavailable", "key_binding_invalid", []any{"signer_facts"}, []any{}},
		{"current-authority", "PO1", "PO1", "key_binding_unavailable", "key_binding_unavailable", []any{"signer_facts", "current"}, M{}},
		{"presence", "Q06", "PO1", "act_presence_required", "act_presence_required", []any{"signer_facts", "presence"}, M{}},
		{"presence-currency", "Q06", "PO1", "act_presence_required", "act_presence_required", []any{"signer_facts", "presence_current"}, M{}},
		{"configured-domain", "PD7", "PD7", "domain_unknown", "domain_unknown", []any{"expected_tag"}, []any{}},
	}
	for _, f := range fields {
		for _, variant := range []string{"missing", "null", "malformed"} {
			v := reviewSource(f.source)
			code := f.missing
			switch variant {
			case "missing":
				deletePath(v.Fixture, f.path)
			case "null":
				setPath(v.Fixture, f.path, nil)
			case "malformed":
				setPath(v.Fixture, f.path, f.bad)
				code = f.malformed
			}
			// Apply faults after signed evidence construction; no builder may
			// refill the deliberately absent protected context.
			add("Y-context-"+f.name+"-"+variant, "Protected "+f.name+" "+variant+" refuses at its own consumption step with an empty plan.", f.positive, code, v)
		}
	}
	// Claims: required context is read only at its specified row; earlier wire,
	// evidence and operator gates still win. Same-row unavailable states are
	// not evidence of relative order when their codes coincide.
	for _, tc := range []struct {
		name, source, positive, code string
		apply                        func(*Vector)
	}{
		{"signature-before-root", "Y-context-grant-root-missing", "PR-root-only-grant", "envelope_signature_invalid", func(v *Vector) {
			a := v.Input["chain"].([]any)
			e := decode(a[0].(string))
			s := e["signatures"].([]any)[0].(M)
			raw := unb64(s["sig"].(string))
			raw[5] ^= 1
			s["sig"] = b64(raw)
			a[0] = wire(e)
		}},
		{"request-before-root", "Y-context-grant-root-missing", "PR-root-only-grant", "grant_chain_malformed", func(v *Vector) { delete(v.Fixture, "request") }},
		{"root-before-journal", "Y-context-grant-root-missing", "PR-root-only-grant", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture, "id_journal_available") }},
		{"roles-before-id", "Y-context-message-role-policy-missing", "PE1", "signer_unavailable", func(v *Vector) { edit(v, func(e M) { e["id"] = "sha256:" + strings.Repeat("0", 64) }) }},
		{"known-before-audience", "Y-context-known-keys-missing", "PE1", "signer_unavailable", func(v *Vector) { v.Fixture["audience"] = "other" }},
		{"reference-before-journal", "W-substitute-generation", "PW-binding", "author_attestation_mismatch", func(v *Vector) { delete(v.Fixture, "id_journal_available") }},
		{"operation-before-facts", "O16", "PO1", "act_operation_unknown", func(v *Vector) { delete(v.Fixture, "signer_facts") }},
		{"current-before-device", "Y-context-act-signer-facts-null", "PO1", "key_binding_unavailable", func(v *Vector) {
			e := decode(v.Fixture["operator_attestations"].(M)[keys[6].ID].(string))
			s := e["signatures"].([]any)[0].(M)
			raw := unb64(s["sig"].(string))
			raw[5] ^= 1
			s["sig"] = b64(raw)
			v.Fixture["operator_attestations"].(M)[keys[6].ID] = wire(e)
		}},
	} {
		v := reviewSource(tc.source)
		tc.apply(&v)
		add("Y-context-order-"+tc.name, "Earlier "+tc.name+" remains an explicit ordered refusal despite a second absent context member.", tc.positive, tc.code, v)
	}
}
