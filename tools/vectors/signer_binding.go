package main

// A valid signature by one admitted key cannot authenticate another signed
// author/issuer. Both neighbors retain valid evidence and signature math, so
// these witnesses isolate the E6 identity join (G2 for a grant link).
func signerBindingVectors() {
	v := reviewSource("PE2")
	other := reviewSource("PE1")
	for _, collection := range []string{"attestations", "agent_attestation_ids", "active_generations"} {
		for k, value := range other.Fixture[collection].(M) {
			v.Fixture[collection].(M)[k] = value
		}
	}
	add("PN02", "An attested admitted agent signs its own author identity and exact attestation reference.", "", "accept", copyVector(v))
	v.Input["envelope"] = wire(envelope(body(v), keys[0], "author"))
	add("N02", "A valid signature by admitted attested agent A cannot authenticate signed author B, also valid and attested; E6 refuses signer_unknown.", "PN02", "signer_unknown", v)

	v = reviewSource("PG1")
	add("PN02-grant", "Each valid grant link is signed by its exact issuer with complete authority provenance.", "", "accept", copyVector(v))
	links := v.Input["chain"].([]any)
	b := decode(links[0].(string))["body"].(M)
	links[0] = wire(envelope(b, keys[0], "author"))
	add("N02-grant", "A valid authority-root signature cannot replace the distinct delegated issuer of the leaf; G2/E6 refuses signer_unknown.", "PN02-grant", "signer_unknown", v)
}
