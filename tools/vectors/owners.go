package main

import "strings"

// Claims: each device intake rejects equal invalid owners and unavailable
// protected owners, while admitting both inclusive byte bounds. Act cases
// retain an independently valid registration/act binding to reach this gate.
func ownerVectors() {
	for _, use := range []string{"message", "grant", "act"} {
		makeVector := func(owner string) Vector {
			v := base("envelope", 0)
			if use == "message" {
				extraSignature(&v, false)
			}
			if use == "grant" {
				v = base("grant", 0)
				v.Input["chain"] = vertexChain([]int{0, 6, 2})
			}
			if use == "act" {
				v = base("operator", 6)
				v.Fixture["binding"].(M)["owner"] = owner
				resign(&v, 6, func(b M) { b["owner"] = owner })
			}
			v.Fixture["record_mutation"] = M{"collection": "operator_attestations", "key": keys[6].ID, "device": true, "path": []any{"binding", "owner"}, "value": owner}
			v.Fixture["context_edits"] = M{"operator_owner": owner}
			return v
		}
		pair := "PV-" + use + "-owner-one"
		for _, row := range []struct{ name, value string }{
			{"one", "x"}, {"255-ascii", strings.Repeat("x", 255)},
			{"255-multibyte", strings.Repeat("é", 127) + "x"},
		} {
			add("PV-"+use+"-owner-"+row.name, "Device "+use+" admits the inclusive owner byte bound: "+row.name+".", "", "accept", makeVector(row.value))
		}
		for _, row := range []struct{ name, value string }{
			{"empty", ""}, {"256-ascii", strings.Repeat("x", 256)}, {"128-two-byte", strings.Repeat("é", 128)},
		} {
			v := makeVector("owner-a")
			v.Fixture["record_mutation"].(M)["value"] = row.value
			v.Fixture["context_edits"].(M)["operator_owner"] = row.value
			add("V-"+use+"-owner-"+row.name, "Device "+use+" rejects equal signed and protected "+row.name+" owners independently of equality.", pair, "key_binding_invalid", v)
		}
		for _, side := range []string{"signed", "protected"} {
			for _, state := range []string{"missing", "null", "wrong-type"} {
				v := makeVector("owner-a")
				value := any(nil)
				code := "key_binding_unavailable"
				if state == "wrong-type" {
					value = true
					code = "key_binding_invalid"
				}
				if side == "signed" {
					mutation := v.Fixture["record_mutation"].(M)
					mutation["value"] = value
					if state == "missing" {
						mutation["remove"] = true
					}
				} else {
					v.Fixture["context_edits"].(M)["operator_owner"] = value
					if state == "missing" {
						v.Fixture["context_remove"] = []any{"operator_owner"}
					}
				}
				add("V-"+use+"-owner-"+side+"-"+state, "Device "+use+" classifies "+side+" owner "+state+" before equality.", pair, code, v)
			}
		}
		for _, state := range []string{"missing", "null"} {
			v := makeVector("owner-a")
			v.Fixture["record_mutation"].(M)["value"] = ""
			v.Fixture["context_edits"].(M)["operator_owner"] = nil
			if state == "missing" {
				v.Fixture["context_remove"] = []any{"operator_owner"}
			}
			add("V-"+use+"-owner-priority-"+state, "Device "+use+" checks protected owner "+state+" before an empty signed owner.", pair, "key_binding_unavailable", v)
		}
	}
}
