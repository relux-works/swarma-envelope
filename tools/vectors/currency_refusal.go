package main

import "fmt"

// These cases pin the current-candidate/profile boundary independently of
// archival predecessor acceptance and distinguish state errors from wire errors.
func currencyRefusalVectors() {
	for _, version := range []int{0, 1} {
		pair := fmt.Sprintf("P-CU-version%d", version)
		for _, position := range []string{"first", "tail"} {
			v := reviewSource(pair)
			candidate := currencyBase2().Input["chain"].([]any)[0]
			if position == "first" {
				v.Input["chain"] = []any{candidate}
			} else {
				v.Input["chain"] = append(v.Input["chain"].([]any), candidate)
			}
			add(fmt.Sprintf("N-CU-r1-profile-%s-v%d", position, version), "Every received publication must match the protected currency profile, regardless of position.", pair, "registry_currency_version_mismatch", v)
		}
		v := reviewSource("P-JRN-genesis")
		v.Fixture["registry_currency_version"] = version
		pair = fmt.Sprintf("P-CU-r1-journal-v%d", version)
		add(pair, "An unchanged legacy journal remains valid at the default or explicit legacy profile.", "", "accept", v)
		v = copyVector(v)
		v.Input["conflict"] = currencyBase2().Input["checkpoint"]
		add(fmt.Sprintf("N-CU-r1-profile-conflict-v%d", version), "The conflict checkpoint is a current candidate too; it cannot bypass profile validation.", pair, "registry_currency_version_mismatch", v)
	}
	for _, field := range []string{"root_key_id", "snapshot_id"} {
		for _, shape := range []string{"string", "array"} {
			v := currencyBase2()
			var bad any = "bad"
			if shape == "array" {
				bad = []any{}
			}
			v.Fixture["freshness_anchor"].(M)["snapshots"].([]any)[0].(M)[field] = bad
			add("N-CU-r1-anchor-"+field+"-"+shape, "Every scalar in the retained snapshot list belongs to the freshness state refusal domain.", "P-CU-genesis", "freshness_state_invalid", v)
		}
	}
	// Malformed original bytes remain invalid state, never a host-language exception.
	for _, shape := range []string{"body-array", "missing-body", "envelope-array", "envelope-null", "body-null", "issuer-array"} {
		v := currencyBase2()
		id := currencySet(v)[0].(M)["snapshot_id"].(string)
		e := decode(v.Fixture["seen"].(M)[id].(string))
		var value any = e
		switch shape {
		case "body-array":
			e["body"] = []any{}
		case "missing-body":
			delete(e, "body")
		case "envelope-array":
			value = []any{}
		case "envelope-null":
			value = nil
		case "body-null":
			e["body"] = nil
		case "issuer-array":
			e["body"].(M)["issuer"] = []any{}
		}
		v.Fixture["seen"].(M)[id] = b64(canonical(value))
		add("N-CU-r1-original-"+shape, "Malformed referenced originals must return a structured state refusal without aborting the corpus.", "P-CU-genesis", "freshness_state_invalid", v)
	}
	for _, position := range []string{"checkpoint", "publication"} {
		v := currencyBase2()
		raw := v.Input["checkpoint"].(string)
		if position == "publication" {
			raw = v.Input["chain"].([]any)[0].(string)
		}
		e := decode(raw)
		e["body"].(M)["type"] = []any{}
		if position == "checkpoint" {
			v.Input["checkpoint"] = wire(e)
		} else {
			v.Input["chain"] = []any{wire(e)}
		}
		add("N-CU-r1-type-array-"+position, "Profile probing cannot treat an untyped type member as a hashable discriminator.", "P-CU-genesis", "freshness_malformed", v)
	}
	for _, shape := range []string{"array", "object"} {
		v := reviewSource("P-CU-check-registry-owner")
		p := decode(wire(v.Fixture["snapshot_journal"].(M)))
		var key any = []any{}
		if shape == "object" {
			key = M{}
		}
		p["anchor"].(M)["latest"].([]any)[0].(M)["root_key_id"] = key
		v.Input["use"].(M)["snapshot_journal"] = p
		add("N-CU-r1-receipt-index-key-"+shape, "Receipt index keys must be typed before duplicate-set lookup, returning an invalid-receipt refusal.", "P-CU-check-registry-owner", "freshness_receipt_invalid", v)
	}
	v := reviewSource("P-CU-journal-same")
	e := decode(v.Input["checkpoint"].(string))
	e["body"].(M)["owner"] = true
	v.Input["checkpoint"] = wire(e)
	add("N-CU-r1-checkpoint-owner", "A malformed current-profile checkpoint remains a wire-shape refusal.", "P-CU-journal-same", "journal_malformed", v)
	v = copyVector(v)
	v.Input["conflict"] = reviewSource("P-JRN-genesis").Input["checkpoint"]
	add("N-CU-r1-conflict-order", "Both checkpoint versions are preflighted before either closed body is parsed.", "P-CU-journal-same", "registry_currency_version_mismatch", v)
}
