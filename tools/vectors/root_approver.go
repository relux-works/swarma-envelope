package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
)

// Claims: all six protected root-role pairs refuse on each evidence intake;
// distinct roles accept, including the operator root's two record languages.
// These fixtures qualify offline policy admission, not live root provisioning.
func rootAndApproverVectors() {
	roles := []string{"service", "registry", "operator", "grant"}
	for _, mode := range []struct{ source, name string }{{"PE5", "message"}, {"PO1", "act"}, {"PG1", "grant"}} {
		positive := "PR-distinct-" + mode.name
		add(positive, "Four distinct root-role pins admit the existing valid "+mode.name+" evidence.", "", "accept", reviewSource(mode.source))
		for i := 0; i < len(roles); i++ {
			for j := i + 1; j < len(roles); j++ {
				v := reviewSource(mode.source)
				pins := []string{v.Fixture["service_root"].(M)["key"].(string), v.Fixture["agent_revocation_root"].(M)["key"].(string), v.Fixture["operator_root"].(string), v.Fixture["root"].(string)}
				pins[j] = pins[i]
				v.Fixture["agent_revocation_root"].(M)["key"] = pins[1]
				v.Fixture["operator_root"], v.Fixture["root"] = pins[2], pins[3]
				// The service/operator overlap includes correctly signed device
				// attestation and snapshot bytes: rejection must be policy-based.
				if i == 0 && j == 2 {
					repinOperator(&v, 5)
				}
				add("R-overlap-"+roles[i]+"-"+roles[j]+"-"+mode.name, "Protected "+roles[i]+" and "+roles[j]+" root roles cannot share a key, before signed evidence consumption.", positive, "key_binding_invalid", v)
			}
		}
	}

	// Root-only grant links consume no attestation: root policy must also run
	// when the first signed evidence intake is the grant snapshot at G7.
	g := reviewSource("PG1")
	g.Input["chain"] = vertexChain([]int{0, 0})
	g.Fixture["request"].(M)["key"] = keys[0].ID
	add("PR-root-only-grant", "A valid root-only grant reaches its distinct-domain snapshot without attestation intake.", "", "accept", g)
	for _, pair := range []string{"service-registry", "service-operator", "registry-operator"} {
		v := copyVector(g)
		switch pair {
		case "service-registry":
			v.Fixture["agent_revocation_root"].(M)["key"] = keys[5].ID
		case "service-operator":
			v.Fixture["operator_root"] = keys[5].ID
		case "registry-operator":
			v.Fixture["operator_root"] = keys[7].ID
		}
		add("R-overlap-G7-"+pair, "Root-only grant rejects overlapping protected roles at first signed evidence intake, G7.", "PR-root-only-grant", "revocation_invalid", v)
	}
	// Claims: each independent approver refusal wins over each otherwise valid
	// author/reference mismatch, including later approvers in signature order.
	// Operand controls isolate both sides; E8 remains later than equality.
	extra := secondApproverKey()
	two := reviewSource("PE5")
	attachSecondApprover(&two, extra)
	add("PR-two-approvers", "Both distinct approvers carry current valid evidence.", "", "accept", two)
	faults := []struct {
		name, code string
		apply      func(*Vector)
	}{
		{"currency", "key_binding_invalid", func(v *Vector) { v.Fixture["signer_facts"].(M)["current"] = false }},
		{"missing", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture["operator_attestations"].(M), keys[6].ID) }},
		{"signature", "key_binding_invalid", func(v *Vector) {
			e := decode(v.Fixture["operator_attestations"].(M)[keys[6].ID].(string))
			s := e["signatures"].([]any)[0].(M)
			raw := unb64(s["sig"].(string))
			raw[5] ^= 1
			s["sig"] = b64(raw)
			v.Fixture["operator_attestations"].(M)[keys[6].ID] = wire(e)
		}},
		{"snapshot", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture["revocations"].(M), keys[4].ID) }},
		{"revoked", "revoked", func(v *Vector) {
			orderSnapshot(v, 4, false, func(b M) { b["entries"] = []any{M{"kind": "key", "id": keys[6].ID, "from": v.Fixture["now"]}} })
		}},
	}
	faults = append(faults, struct {
		name, code string
		apply      func(*Vector)
	}{
		"later-missing", "key_binding_unavailable", func(v *Vector) {
			attachSecondApprover(v, extra)
			delete(v.Fixture["operator_attestations"].(M), extra.ID)
		}}, struct {
		name, code string
		apply      func(*Vector)
	}{
		"later-revoked", "revoked", func(v *Vector) {
			attachSecondApprover(v, extra)
			orderSnapshot(v, 4, false, func(b M) { b["entries"] = []any{M{"kind": "key", "id": extra.ID, "from": v.Fixture["now"]}} })
		}})

	for _, source := range []string{"W-substitute-generation", "W-substitute-registration_number", "W-concurrent-substitute", "W-other-key"} {
		v := reviewSource(source)
		attachApprover(&v)
		add("R-reference-only-"+source, "Valid author and approver evidence precedes final reference equality.", "PR-distinct-message", "author_attestation_mismatch", v)
		for _, fault := range faults {
			w := copyVector(v)
			fault.apply(&w)
			add("U-approver-"+fault.name+"-"+source, "Approver "+fault.name+" wins before final message author/reference equality.", "PR-distinct-message", fault.code, w)
		}
	}
	beforeJournal := reviewSource("R-reference-only-W-substitute-generation")
	beforeJournal.Fixture["id_journal_available"] = false
	add("R-reference-before-journal", "Final K1 reference equality still precedes unavailable E8 journal.", "PR-distinct-message", "author_attestation_mismatch", beforeJournal)
	for _, fault := range faults {
		v := reviewSource("PE5")
		fault.apply(&v)
		add("R-approver-only-"+fault.name, "Approver "+fault.name+" refuses independently of reference equality.", "PR-distinct-message", fault.code, v)
	}
}

func repinOperator(v *Vector, idx int) {
	v.Fixture["operator_root"] = keys[idx].ID
	for key, value := range v.Fixture["operator_attestations"].(M) {
		b := decode(value.(string))["body"].(M)
		b["issuer"] = keys[idx].ID
		v.Fixture["operator_attestations"].(M)[key] = evidenceWire(b, keys[idx])
	}
	r := v.Fixture["revocations"].(M)[keys[4].ID].(M)
	b := decode(r["snapshot"].(string))["body"].(M)
	b["issuer"] = keys[idx].ID
	r["snapshot"] = evidenceWire(b, keys[idx])
	delete(v.Fixture["revocations"].(M), keys[4].ID)
	v.Fixture["revocations"].(M)[keys[idx].ID] = r
}

func attachApprover(v *Vector) {
	control := reviewSource("PE5")
	v.Fixture["operator_attestations"] = control.Fixture["operator_attestations"]
	v.Fixture["signer_facts"] = control.Fixture["signer_facts"]
	v.Fixture["required_roles"] = []any{"approver"}
	v.Fixture["revocations"].(M)[keys[4].ID] = control.Fixture["revocations"].(M)[keys[4].ID]
	e := decode(v.Input["envelope"].(string))
	b := e["body"].(M)
	e["signatures"] = append(e["signatures"].([]any), M{"role": "approver", "key": keys[6].ID, "sig": b64(sign(keys[6], sigPre(b, "approver", keys[6].ID, "message/1")))})
	v.Input["envelope"] = wire(e)
}

// A separate public deterministic test key permits two different approver pairs;
// it is fixture-only and never enters configured production key material.
func secondApproverKey() Key {
	seed := sha256.Sum256([]byte("waggle public second approver seed"))
	c := elliptic.P256()
	d := new(big.Int).SetBytes(seed[:])
	d.Mod(d, new(big.Int).Sub(c.Params().N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	x, y := c.ScalarBaseMult(d.Bytes())
	return Key{ID: "p256:" + b64(elliptic.MarshalCompressed(c, x, y)), Seed: seed[:], EC: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}}
}
func attachSecondApprover(v *Vector, k Key) {
	v.Fixture["operator_attestations"].(M)[k.ID] = evidenceWire(deviceAttestation(k.ID), keys[4])
	e := decode(v.Input["envelope"].(string))
	b := e["body"].(M)
	e["signatures"] = append(e["signatures"].([]any), M{"role": "approver", "key": k.ID, "sig": b64(sign(k, sigPre(b, "approver", k.ID, "message/1")))})
	v.Input["envelope"] = wire(e)
}
