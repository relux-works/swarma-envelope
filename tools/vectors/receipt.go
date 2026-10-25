package main

// Receipt vectors carry signed producer inputs and an operation, never receipt
// fields. Runners must admit F themselves and share its opaque result in memory.
func receiptBase(operation string, current bool) Vector {
	v := freshnessBase()
	if current {
		freshnessChanged(&v, []any{})
		row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
		b := decode(row["snapshot"].(string))["body"].(M)
		b["issued_at"] = "2026-01-01T00:03:00Z"
		row["snapshot"] = evidenceWire(b, keys[7])
		sid := decode(row["snapshot"].(string))["id"]
		journalCheckpoint(&v, func(b M) { b["at"], b["snapshot"] = "2026-01-01T00:03:00Z", sid })
		cp := decode(v.Input["checkpoint"].(string))
		v.Fixture["journal_witness"].(M)["checkpoint_id"] = cp["id"]
		freshnessEdit(&v, func(b M) { b["snapshot"], b["checkpoint_id"] = sid, cp["id"] })
	}
	mint := M{"mode": v.Mode, "input": v.Input}
	consume := M{"mode": operation, "input": M{}}
	switch operation {
	case "attestation", "device", "revocation":
		in := consume["input"].(M)
		if operation == "device" {
			in["key"] = keys[6].ID
			in["reference"] = ""
		} else {
			in["key"] = keys[2].ID
			in["reference"] = defaultAttestationID(2)
		}
		in["root"], in["ids"], in["keys"] = keys[7].ID, []any{}, []any{keys[2].ID}
	case "message", "operator":
		c := base(operation, 2)
		if operation == "operator" {
			c = base(operation, 6)
		}
		resign(&c, map[bool]int{true: 6, false: 2}[operation == "operator"], func(b M) { b["iat"], b["exp"] = "2026-01-01T00:03:00Z", "2026-01-01T00:05:00Z" })
		consume["input"] = c.Input
		v.Fixture["required_roles"] = c.Fixture["required_roles"]
	case "grant":
		c := base("grant", 0)
		link(&c, 0, 1, func(b M) { b["exp"], b["expires"] = "2026-01-01T00:05:00Z", "2026-01-01T00:05:00Z" })
		consume["input"] = c.Input
	}
	// Other authority domains remain independently current in positive controls.
	for _, i := range []int{0, 4} {
		row := v.Fixture["revocations"].(M)[keys[i].ID].(M)
		b := decode(row["snapshot"].(string))["body"].(M)
		b["issued_at"] = "2026-01-01T00:03:00Z"
		row["snapshot"] = evidenceWire(b, keys[i])
	}
	v.Mode = "receipt"
	v.Input = M{"mint": mint, "consume": consume, "use": M{}, "attach": true, "require": true, "margin": 0, "renew_evidence": false}
	return v
}
func receiptUse(v *Vector) M  { return v.Input["use"].(M) }
func receiptMint(v *Vector) M { return v.Input["mint"].(M)["input"].(M) }
func receiptVectors() {
	for _, operation := range []string{"attestation", "device", "revocation", "message", "grant", "operator"} {
		add("P-RC-"+operation, "Real F admission composes into the consuming operation without changing its plan.", "", "accept", receiptBase(operation, false))
		v := receiptBase(operation, false)
		v.Input["attach"] = false
		add("N-RC-required-"+operation, "A required receipt is never silently omitted.", "P-RC-"+operation, "freshness_receipt_unavailable", v)
		v = receiptBase(operation, true)
		v.Input["renew_evidence"] = true
		v.Input["require"] = false
		add("N-RC-no-fallback-"+operation, "A changed evidence identity refuses even when snapshot own-age passes.", "P-RC-current", "freshness_receipt_binding_mismatch", v)
	}
	for _, operation := range []string{"attestation", "device", "revocation", "message", "grant", "operator"} {
		v := receiptBase(operation, true)
		v.Input["require"] = false
		receiptUse(&v)["now"], receiptUse(&v)["watermark"], receiptUse(&v)["witness_read_at"] = "2026-01-01T00:04:00Z", "2026-01-01T00:04:00Z", "2026-01-01T00:04:00Z"
		add("N-RC-expired-"+operation, "Optional supplied receipts refuse at exclusive expiry even when own-age passes.", "P-RC-"+operation, "freshness_receipt_expired", v)
	}

	add("P-RC-current", "A receipt also accepts a current bound snapshot.", "", "accept", receiptBase("attestation", true))
	for _, tc := range []struct {
		id, code string
		edit     func(*Vector)
	}{
		{"expiry", "freshness_receipt_expired", func(v *Vector) {
			receiptUse(v)["now"] = "2026-01-01T00:04:00Z"
			receiptUse(v)["watermark"] = "2026-01-01T00:04:00Z"
		}},
		{"margin", "freshness_receipt_expired", func(v *Vector) {
			v.Input["margin"] = 1
			receiptUse(v)["now"] = "2026-01-01T00:03:59Z"
			receiptUse(v)["watermark"] = "2026-01-01T00:03:59Z"
		}},
		{"negative-margin", "freshness_receipt_invalid", func(v *Vector) { v.Input["margin"] = -1 }},
		{"large-margin", "freshness_receipt_invalid", func(v *Vector) { v.Input["margin"] = 61 }},
		{"premise", "freshness_receipt_binding_mismatch", func(v *Vector) { v.Input["renew_evidence"] = true }},
		{"owner", "freshness_receipt_binding_mismatch", func(v *Vector) { receiptUse(v)["registry_owner"] = "other-owner" }},
		{"root", "freshness_receipt_binding_mismatch", func(v *Vector) {
			p := decode(wire(v.Fixture["agent_revocation_root"].(M)))
			p["key"] = keys[2].ID
			receiptUse(v)["agent_revocation_root"] = p
		}},
		{"checkpoint", "freshness_receipt_binding_mismatch", func(v *Vector) {
			w := decode(wire(v.Fixture["journal_witness"].(M)))
			w["checkpoint_id"] = digest([]byte("foreign checkpoint"))
			receiptUse(v)["journal_witness"] = w
		}},
		{"head", "freshness_receipt_binding_mismatch", func(v *Vector) {
			w := decode(wire(v.Fixture["journal_witness"].(M)))
			w["registry_head"] = digest([]byte("foreign head"))
			receiptUse(v)["journal_witness"] = w
		}},
		{"sequence", "freshness_receipt_binding_mismatch", func(v *Vector) {
			w := decode(wire(v.Fixture["journal_witness"].(M)))
			w["registry_seq"] = 3
			receiptUse(v)["journal_witness"] = w
		}},
		{"anchor", "freshness_receipt_binding_mismatch", func(v *Vector) { receiptUse(v)["freshness_anchor"] = v.Fixture["freshness_anchor"] }},
		{"read-missing", "freshness_receipt_unavailable", func(v *Vector) { receiptUse(v)["witness_read_at"] = nil }},
		{"read-invalid", "freshness_receipt_invalid", func(v *Vector) { receiptUse(v)["witness_read_at"] = true }},
		{"read-future", "freshness_receipt_invalid", func(v *Vector) { receiptUse(v)["witness_read_at"] = "2026-01-01T00:03:01Z" }},
		{"read-older", "freshness_receipt_binding_mismatch", func(v *Vector) { receiptUse(v)["witness_read_at"] = "2026-01-01T00:02:59Z" }},
		{"witness-missing", "freshness_receipt_unavailable", func(v *Vector) { receiptUse(v)["journal_witness"] = nil }},
		{"witness-invalid", "freshness_receipt_invalid", func(v *Vector) { receiptUse(v)["journal_witness"] = true }},
		{"snapshot-missing", "freshness_receipt_unavailable", func(v *Vector) { receiptUse(v)["revocations"] = nil }},
		{"time-first", "time_unavailable", func(v *Vector) { v.Input["renew_evidence"] = true; receiptUse(v)["time"] = nil }},
		{"watermark-first", "watermark_unavailable", func(v *Vector) { v.Input["renew_evidence"] = true; receiptUse(v)["watermark_available"] = false }},
	} {
		v := receiptBase("attestation", false)
		tc.edit(&v)
		add("N-RC-"+tc.id, "Receipt refusal preserves the ordered R contract with a real signed positive neighbor.", "P-RC-attestation", tc.code, v)
	}
	for _, op := range []string{"attestation", "device", "revocation"} {
		v := receiptBase(op, false)
		in := v.Input["consume"].(M)["input"].(M)
		if op == "attestation" {
			in["key"] = keys[6].ID
		} else if op == "device" {
			in["reference"] = digest([]byte("foreign device reference"))
		} else {
			p := decode(wire(v.Fixture["service_root"].(M)))
			p["purpose"] = 4
			receiptUse(&v)["service_root"] = p
		}
		add("N-RC-direct-"+op, "Direct APIs retain exact identity and root-policy checks when a valid receipt is attached.", "P-RC-"+op, "key_binding_invalid", v)
	}

	for _, tc := range []struct {
		id, code string
		records  any
	}{
		{"snapshot-map", "freshness_receipt_invalid", true},
		{"snapshot-root-missing", "freshness_receipt_unavailable", M{}},
		{"snapshot-row", "freshness_receipt_invalid", M{keys[7].ID: true}},
		{"snapshot-bytes", "freshness_receipt_invalid", M{keys[7].ID: M{"snapshot": true}}},
	} {
		v := receiptBase("attestation", false)
		receiptUse(&v)["revocations"] = tc.records
		add("N-RC-"+tc.id, "R2 distinguishes absent and malformed current bindings before Evidence identity mismatch.", "P-RC-attestation", tc.code, v)
	}

	// Snapshot substitution cannot use another signed F candidate's receipt.
	v := receiptBase("attestation", true)
	other := receiptBase("attestation", false)
	receiptUse(&v)["revocations"] = other.Fixture["revocations"]
	add("N-RC-snapshot", "A receipt never renews different signed snapshot bytes.", "P-RC-current", "freshness_receipt_binding_mismatch", v)
	for _, op := range []string{"device", "operator", "grant"} {
		v := receiptBase(op, false)
		i := 4
		if op == "grant" {
			i = 0
		}
		row := v.Fixture["revocations"].(M)[keys[i].ID].(M)
		b := decode(row["snapshot"].(string))["body"].(M)
		b["issued_at"] = "2026-01-01T00:01:00Z"
		row["snapshot"] = evidenceWire(b, keys[i])
		code := "key_binding_unavailable"
		if op != "device" {
			code = "revocation_unavailable"
		}
		add("N-RC-domain-age-"+op, "Registry currency never renews another authority domain's own-age bound.", "P-RC-"+op, code, v)
	}
	v = receiptBase("revocation", false)
	v.Input["consume"].(M)["input"].(M)["root"] = keys[4].ID
	add("N-RC-explicit-root", "CheckRevocation requires the receipt's exact root.", "P-RC-revocation", "freshness_receipt_binding_mismatch", v)
	for _, tc := range []struct {
		id, at, read string
		margin       int
	}{
		{"before-expiry", "2026-01-01T00:03:59Z", "2026-01-01T00:03:00Z", 0},
		{"new-read", "2026-01-01T00:03:59Z", "2026-01-01T00:03:59Z", 0},
		{"margin-before", "2026-01-01T00:03:58Z", "2026-01-01T00:03:00Z", 1},
	} {
		v := receiptBase("attestation", false)
		receiptUse(&v)["now"], receiptUse(&v)["watermark"], receiptUse(&v)["witness_read_at"] = tc.at, tc.at, tc.read
		v.Input["margin"] = tc.margin
		add("P-RC-"+tc.id, "Fixed exclusive expiry accepts only its strict interior.", "", "accept", v)
	}
	v = receiptBase("attestation", true)
	receiptUse(&v)["now"] = "2026-01-01T00:04:00Z"
	receiptUse(&v)["watermark"] = "2026-01-01T00:04:00Z"
	receiptUse(&v)["witness_read_at"] = "2026-01-01T00:04:00Z"
	add("N-RC-new-read-expiry", "A newer authenticated read cannot extend a minted expiry, even while own age still passes.", "P-RC-current", "freshness_receipt_expired", v)
	// Future-effective entries are checked again at use, not frozen at mint.
	v = receiptBase("attestation", false)
	f := Vector{Mode: "freshness", Fixture: v.Fixture, Input: receiptMint(&v)}
	freshnessChanged(&f, []any{M{"kind": "key", "id": keys[2].ID, "from": "2026-01-01T00:03:30Z"}})
	v.Input["mint"].(M)["input"] = f.Input
	receiptUse(&v)["now"] = "2026-01-01T00:03:30Z"
	receiptUse(&v)["watermark"] = "2026-01-01T00:03:30Z"
	add("N-RC-effective", "A fresh receipt never masks a newly effective revocation.", "P-RC-current", "revoked", v)
	// Explicit recovery also issues; a missing read must fail actual F first.
	v = receiptBase("attestation", false)
	r := freshnessReanchorBase()
	v.Input["mint"] = M{"mode": r.Mode, "input": r.Input}
	v.Fixture["freshness_anchor"] = r.Fixture["freshness_anchor"]
	add("P-RC-reanchor", "A successful explicit recovery issues the same scoped receipt.", "", "accept", v)
	noRead := receiptBase("attestation", false)
	noRead.Input["mint"] = v.Input["mint"]
	noRead.Fixture["freshness_anchor"] = v.Fixture["freshness_anchor"]
	receiptUse(&noRead)["witness_read_at"] = nil
	add("N-RC-reanchor-use-no-read", "A minted recovery receipt still requires current authenticated read evidence at use.", "P-RC-reanchor", "freshness_receipt_unavailable", noRead)

	v.Fixture = decode(wire(v.Fixture))
	delete(v.Fixture, "witness_read_at")
	add("N-RC-reanchor-no-read", "Recovery cannot mint a receipt without authenticated read currency.", "P-RC-reanchor", "freshness_unavailable", v)
	receiptPresenceVectors()
	receiptNullableVectors()
	receiptServiceVectors()
}
