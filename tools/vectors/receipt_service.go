package main

// Service identity validates the registry receipt without renewing grant-root
// age. Keep protected protocol-key roles separate in the signed fixture.
func receiptService() Vector {
	v := receiptBase("revocation", false)
	svc := serviceBase()
	delete(v.Fixture, "enrollment_publisher")
	v.Fixture["service_authority"], v.Fixture["service_attestations"] = svc.Fixture["service_authority"], svc.Fixture["service_attestations"]
	v.Input["consume"] = M{"mode": "service", "input": M{"key": keys[3].ID}}
	return v
}

// Each refusal keeps a current accepting service control and real F mint.
// Required/optional receipt policy never waives service validity or grant age.
func receiptServiceVectors() {
	add("P-RC-service", "A valid original registry receipt and current grant-root snapshot admit the exact service identity.", "", "accept", receiptService())
	v := receiptService()
	v.Input["attach"], v.Input["require"] = false, false
	add("P-RC-service-optional-absence", "Optional absent receipts retain current service own-age admission.", "", "accept", v)
	for _, tc := range []struct {
		id, code string
		edit     func(*Vector)
	}{
		{"invalid", "freshness_receipt_invalid", func(v *Vector) { v.Input["margin"], v.Input["require"] = 61, false }},
		{"required", "freshness_receipt_unavailable", func(v *Vector) { v.Input["attach"] = false }},
		{"binding", "freshness_receipt_binding_mismatch", func(v *Vector) { v.Input["renew_evidence"], v.Input["require"] = true, false }},
		{"expired", "freshness_receipt_expired", func(v *Vector) {
			receiptUse(v)["now"], receiptUse(v)["watermark"], receiptUse(v)["witness_read_at"] = "2026-01-01T00:04:00Z", "2026-01-01T00:04:00Z", "2026-01-01T00:04:00Z"
		}},
		{"grant-age", "key_binding_unavailable", func(v *Vector) {
			row := v.Fixture["revocations"].(M)[keys[0].ID].(M)
			b := decode(row["snapshot"].(string))["body"].(M)
			b["issued_at"] = "2026-01-01T00:01:00Z"
			row["snapshot"] = evidenceWire(b, keys[0])
		}},
		{"legacy-age", "key_binding_unavailable", func(v *Vector) {
			v.Input["attach"], v.Input["require"] = false, false
			row := v.Fixture["revocations"].(M)[keys[0].ID].(M)
			b := decode(row["snapshot"].(string))["body"].(M)
			b["issued_at"] = "2026-01-01T00:01:00Z"
			row["snapshot"] = evidenceWire(b, keys[0])
		}},
		{"validity-order", "freshness_receipt_invalid", func(v *Vector) {
			v.Input["margin"], v.Input["require"] = 61, false
			serviceRecord(v, func(b M) { b["exp"] = v.Fixture["now"] })
		}},
		{"identity-expired", "key_binding_invalid", func(v *Vector) { serviceRecord(v, func(b M) { b["exp"] = v.Fixture["now"] }) }},
		{"time-order", "time_unavailable", func(v *Vector) { v.Input["margin"] = 61; receiptUse(v)["time"] = nil }},
		{"revoked", "revoked", func(v *Vector) {
			row := v.Fixture["revocations"].(M)[keys[0].ID].(M)
			b := decode(row["snapshot"].(string))["body"].(M)
			b["entries"] = []any{M{"kind": "key", "id": keys[3].ID, "from": v.Fixture["now"]}}
			row["snapshot"] = evidenceWire(b, keys[0])
		}},
	} {
		v := receiptService()
		tc.edit(&v)
		add("N-RC-service-"+tc.id, "Service receipt validation preserves R ordering, zero refused identity, and independent grant-root admission.", "P-RC-service", tc.code, v)
	}
}
