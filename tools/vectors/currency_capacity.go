package main

import "fmt"

// Individually bounded retained copies exceed the shared charge. The extra
// rows are unused; disabling only the aggregate gate must restore acceptance.
func currencyCapacityLoad(v *Vector) {
	seen := v.Fixture["seen"].(M)
	snapshots := v.Fixture["revocations"].(M)
	template := snapshots[keys[7].ID].(M)
	raw := currencyPadded(template["snapshot"].(string), 8192)
	for i := 0; i < 124; i++ {
		name := fmt.Sprintf("capacity-%03d", i)
		seen[name] = raw
		row := decode(wire(template))
		row["snapshot"] = raw
		snapshots[name] = row
	}
}

// The three APIs must check the whole-call charge before candidate profiles.
// Each compound has an otherwise-valid same-profile capacity-only control.
func currencyCapacityVectors() {
	for _, tc := range []struct{ name, control, code string }{
		{"freshness", "P-CU-genesis", "freshness_malformed"},
		{"reanchor", "P-CU-reanchor-same", "freshness_malformed"},
		{"journal", "P-CU-journal-same", "journal_malformed"},
	} {
		v := reviewSource(tc.control)
		currencyCapacityLoad(&v)
		add("N-CU-r3-capacity-"+tc.name, "The aggregate charge refuses otherwise-valid current-profile evidence without a candidate plan.", tc.control, tc.code, v)
		v = copyVector(v)
		v.Input["checkpoint"] = reviewSource("P-CU-version1").Input["checkpoint"]
		add("N-CU-r3-profile-"+tc.name, "The aggregate capacity refusal precedes an opposite-profile checkpoint for this entry point.", tc.control, tc.code, v)
	}
}
