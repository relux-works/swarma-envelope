package main

import "crypto/elliptic"

// E6 orders issuer matching and profile admission before strict crypto, for
// every grant link at G2. Correct signatures isolate the earlier failures.
// Subject-only operands ensure moving point admission never removes it.
func e6OrderVectors() {
	points := []struct{ name, key string }{
		{"ed25519", "ed25519:" + b64(append([]byte{1}, make([]byte, 31)...))},
		{"p256", "p256:" + b64(append([]byte{2}, elliptic.P256().Params().P.FillBytes(make([]byte, 32))...))},
	}
	for _, point := range points {
		v := reviewSource("N02-grant")
		e6Subject(&v, point.key)
		add("N-E6-issuer-before-subject-"+point.name, "E6 issuer matching precedes strict "+point.name+" subject-point validation, with a valid signature by the mismatching signer.", "PN02-grant", "signer_unknown", v)
		v = reviewSource("PN02-grant")
		e6Subject(&v, point.key)
		add("N-E6-subject-only-"+point.name, "After a matching issuer and valid signing profile, strict "+point.name+" subject-point validation still refuses an invalid point.", "PN02-grant", "envelope_signature_invalid", v)
	}
	v := reviewSource("W-purpose5-grant")
	e6Subject(&v, points[0].key)
	add("N-E6-profile-before-subject", "E6 refuses the disallowed purpose-5 grant signing profile before strict subject-point crypto; issuer matching and signature math hold.", "PG1", "signature_profile_invalid", v)
}

func e6Subject(v *Vector, subject string) {
	links := v.Input["chain"].([]any)
	e := decode(links[0].(string))
	b := e["body"].(M)
	b["subject"] = subject
	s := e["signatures"].([]any)[0].(M)
	for _, k := range keys {
		if k.ID == s["key"] {
			links[0] = wire(envelope(b, k, s["role"].(string)))
			return
		}
	}
	panic("missing test signer")
}
