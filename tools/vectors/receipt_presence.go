package main

import "strings"

// Each compound preserves a missing required R2 binding and independently
// malformed syntax. The spec orders every required presence check first.
func receiptPresenceVectors() {
	const control = "P-RC-R2-presence-control"
	add(control, "Unchanged real F mint and current receipt use accept.", "", "accept", receiptBase("attestation", false))
	missingSnapshot := func(v *Vector) {
		rows := decode(wire(v.Fixture["revocations"].(M)))
		delete(rows[keys[7].ID].(M), "snapshot")
		receiptUse(v)["revocations"] = rows
	}
	for _, tc := range []struct {
		id, code         string
		missing, badRead bool
	}{
		{"snapshot-missing", "freshness_receipt_unavailable", true, false},
		{"read-invalid", "freshness_receipt_invalid", false, true},
		{"presence-before-syntax", "freshness_receipt_unavailable", true, true},
	} {
		v := receiptBase("attestation", false)
		if tc.missing {
			missingSnapshot(&v)
		}
		if tc.badRead {
			receiptUse(&v)["witness_read_at"] = true
		}
		add("N-RC-R2-"+tc.id, "Required nested snapshot presence precedes read syntax, with independent controls.", control, tc.code, v)
	}
	for _, name := range []string{"bound-row-missing", "bound-row-null", "snapshot-null"} {
		v := receiptBase("attestation", false)
		rows := decode(wire(v.Fixture["revocations"].(M)))
		switch name {
		case "bound-row-missing":
			delete(rows, keys[7].ID)
		case "bound-row-null":
			rows[keys[7].ID] = nil
		case "snapshot-null":
			rows[keys[7].ID].(M)["snapshot"] = nil
		}
		receiptUse(&v)["revocations"] = rows
		receiptUse(&v)["witness_read_at"] = true
		add("N-RC-R2-"+name, "Absent bound registry row or snapshot wins over malformed read syntax.", control, "freshness_receipt_unavailable", v)
	}
	for _, name := range []string{"agent_revocation_root", "registry_owner", "journal_witness", "freshness_anchor", "witness_read_at", "revocations"} {
		v := receiptBase("attestation", false)
		receiptUse(&v)[name] = nil
		bad := "agent_revocation_root"
		if name == bad {
			bad = "journal_witness"
		}
		receiptUse(&v)[bad] = true
		add("N-RC-R2-absent-"+strings.ReplaceAll(name, "_", "-"), "Missing top-level binding/read wins over malformed independent policy or witness syntax.", control, "freshness_receipt_unavailable", v)
	}
	for _, scope := range []struct{ name, fields, bad string }{
		{"agent_revocation_root", "key purpose attestation_root", "witness_read_at"},
		{"journal_witness", "registry_id owner registry_seq registry_head checkpoint_id previous_checkpoint_id", "agent_revocation_root"},
		{"freshness_anchor", "registry_id owner publication_seq freshness_id issued_at snapshot registry_seq checkpoint_id", "journal_witness"},
	} {
		for _, field := range strings.Fields(scope.fields) {
			v := receiptBase("attestation", false)
			source := v.Fixture[scope.name].(M)
			if scope.name == "freshness_anchor" {
				chain := receiptMint(&v)["chain"].([]any)
				source = freshnessFact(decode(chain[len(chain)-1].(string)))
			}
			row := decode(wire(source))
			delete(row, field)
			receiptUse(&v)[scope.name] = row
			receiptUse(&v)[scope.bad] = true
			add("N-RC-R2-absent-"+strings.ReplaceAll(scope.name+"-"+field, "_", "-"), "Missing required nested binding member wins over malformed independent syntax.", control, "freshness_receipt_unavailable", v)
		}
	}
	for _, name := range []string{"agent_revocation_root", "journal_witness", "freshness_anchor"} {
		v := receiptBase("attestation", false)
		missingSnapshot(&v)
		receiptUse(&v)[name] = true
		add("N-RC-R2-snapshot-before-"+strings.ReplaceAll(name, "_", "-"), "Missing nested snapshot wins over a malformed policy, witness or anchor container.", control, "freshness_receipt_unavailable", v)
	}
}
