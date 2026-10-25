package main

import "strings"

// Authorized checkpoint genesis has a present null predecessor. Consuming its
// real F receipt through CheckRevocation needs no epoch-valid agent identity.
func receiptGenesis() Vector {
	v := freshnessEpoch("1970-01-01T00:00:00Z")
	mint := M{"mode": v.Mode, "input": v.Input}
	consume := M{"mode": "revocation", "input": M{"root": keys[7].ID, "ids": []any{}, "keys": []any{keys[2].ID}}}
	v.Mode = "receipt"
	v.Input = M{"mint": mint, "consume": consume, "use": M{}, "attach": true, "require": true, "margin": 0, "renew_evidence": false}
	return v
}

// Explicit null is present, not a blanket valid value: each projection's
// conditional syntax decides, then exact admitted-anchor matching still runs.
func receiptNullableVectors() {
	const genesis = "P-RC-null-witness-genesis"
	add(genesis, "Authorized genesis predecessor null survives syntax and the real receipt accepts CheckRevocation.", "", "accept", receiptGenesis())
	for _, state := range []string{"absent", "malformed"} {
		v := receiptGenesis()
		w := decode(wire(v.Fixture["journal_witness"].(M)))
		code := "freshness_receipt_unavailable"
		if state == "absent" {
			delete(w, "previous_checkpoint_id")
		} else {
			w["previous_checkpoint_id"] = true
			code = "freshness_receipt_invalid"
		}
		receiptUse(&v)["journal_witness"] = w
		add("N-RC-null-witness-"+state, "An absent genesis predecessor is unavailable; malformed syntax is invalid, alongside a valid null control.", genesis, code, v)
	}
	foreignGenesis := func() Vector {
		v := receiptBase("revocation", false)
		a := decode(wire(v.Fixture["freshness_anchor"].(M)))
		a["publication_seq"], a["freshness_id"], a["issued_at"] = 0, nil, nil
		receiptUse(&v)["freshness_anchor"] = a
		return v
	}
	add("N-RC-null-anchor-genesis", "Present publication-genesis nulls have valid syntax, but differ from the receipt's admitted anchor.", "P-RC-revocation", "freshness_receipt_binding_mismatch", foreignGenesis())
	for _, field := range []string{"freshness_id", "issued_at"} {
		for _, state := range []string{"absent", "malformed", "positive-null"} {
			v := foreignGenesis()
			a := receiptUse(&v)["freshness_anchor"].(M)
			code := "freshness_receipt_invalid"
			switch state {
			case "absent":
				delete(a, field)
				code = "freshness_receipt_unavailable"
			case "malformed":
				a[field] = true
			case "positive-null":
				chain := receiptMint(&v)["chain"].([]any)
				a = freshnessFact(decode(chain[len(chain)-1].(string)))
				a[field] = nil
				receiptUse(&v)["freshness_anchor"] = a
			}
			add("N-RC-null-anchor-"+strings.ReplaceAll(field, "_", "-")+"-"+state, "Required anchor members distinguish absence from conditional null or malformed syntax before exact matching.", "P-RC-revocation", code, v)
		}
	}
}
