package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Claims: bounded signed/current members are checked independently, not made
// valid by agreeing. Snapshot controls exercise inclusive age/list bounds and
// malformed nonmatching entries; these remain offline provider witnesses.
func boundVectors() {
	for _, field := range []string{"owner", "path", "generation", "master_epoch"} {
		for _, row := range []struct {
			name, value string
			valid       bool
		}{
			{"one", "x", true}, {"255", strings.Repeat("é", 127) + "x", true},
			{"empty", "", false}, {"256", strings.Repeat("é", 128), false},
		} {
			v := base("envelope", 0)
			name := field
			if name == "master_epoch" {
				name = "epoch"
			}
			v.Fixture["agent_evidence"].(M)[keys[0].ID].(M)["binding"].(M)[name] = row.value
			v.Fixture["agent_expected"].(M)[keys[0].ID].(M)[name] = row.value
			prefix, code, pair := "H-", "key_binding_invalid", "PH-principal-"+field+"-one"
			if row.valid {
				prefix, code, pair = "PH-", "accept", ""
			}
			add(prefix+"principal-"+field+"-"+row.name, "Signed and protected principal "+field+" independently enforce the "+row.name+" UTF-8 byte boundary.", pair, code, v)
		}
	}
	for _, row := range []struct {
		name  string
		value any
		valid bool
	}{
		{"zero", 0, true}, {"maximum", 4294967294, true}, {"negative", -1, false}, {"above-maximum", 4294967295, false}, {"boolean", true, false},
	} {
		v := base("envelope", 0)
		current := bindingRecord(v.Fixture["agent_expected"].(M)[keys[0].ID], 1000).(M)
		current["active"], current["uid"] = true, row.value
		v.Fixture["context_edits"] = M{"active_generations": M{keys[0].ID: current}}
		v.Fixture["record_mutation"] = M{"collection": "attestations", "key": keys[0].ID, "path": []any{"binding", "uid"}, "value": row.value}
		prefix, code, pair := "H-", "key_binding_invalid", "PH-uid-zero"
		if row.valid {
			prefix, code, pair = "PH-", "accept", ""
		}
		add(prefix+"uid-"+row.name, "Signed and protected UID independently enforce "+row.name+" integer boundary.", pair, code, v)
	}
	for _, row := range []struct {
		name  string
		value any
		valid bool
	}{
		{"one", 1, true}, {"sixty", 60, true}, {"zero", 0, false}, {"sixty-one", 61, false}, {"boolean", true, false}, {"float", 1.0, false},
	} {
		v := base("envelope", 0)
		value := row.value
		// Preserve a JSON floating-point token instead of Go's integral float output.
		if row.name == "float" {
			value = json.RawMessage("1.0")
		}
		v.Fixture["snapshot_fault"] = M{"max_age": value}
		prefix, code, pair := "H-", "key_binding_invalid", "PH-age-one"
		if row.valid {
			prefix, code, pair = "PH-", "accept", ""
		}
		add(prefix+"age-"+row.name, "Protected snapshot maximum age independently enforces "+row.name+" integer boundary.", pair, code, v)
	}
	for _, size := range []int{0, 64, 65} {
		entries := []any{}
		for i := 0; i < size; i++ {
			entries = append(entries, M{"kind": "key", "id": keys[1].ID, "from": "2026-01-01T00:01:00Z"})
		}
		v := base("envelope", 0)
		v.Fixture["snapshot_fault"] = M{"entries": entries}
		prefix, code, pair := "PH-", "accept", ""
		if size == 65 {
			prefix, code, pair = "H-", "key_binding_invalid", "PH-entries-64"
		}
		add(prefix+"entries-"+strconv.Itoa(size), "Complete signed snapshot independently enforces the "+strconv.Itoa(size)+" entry boundary, including nonmatching keys.", pair, code, v)
	}
	for _, row := range []struct {
		name, code string
		fault      M
	}{
		{"complete-integer", "key_binding_invalid", M{"complete": 1}},
		{"incomplete", "key_binding_unavailable", M{"complete": false}},
		{"rollback-integer", "key_binding_invalid", M{"rollback_safe": 1}},
		{"rollback-false", "key_binding_unavailable", M{"rollback_safe": false}},
		{"issued-invalid", "key_binding_invalid", M{"issued_at": "2026-02-30T00:01:00Z"}},
		{"issued-future", "key_binding_unavailable", M{"issued_at": "2026-01-01T00:01:01Z"}},
		{"age-expired", "key_binding_unavailable", M{"issued_at": "2025-12-31T23:59:59Z"}},
		{"entry-key-invalid", "key_binding_invalid", M{"entries": []any{M{"kind": "key", "id": "ed25519:x", "from": "2026-01-01T00:01:00Z"}}}},
		{"entry-record-invalid", "key_binding_invalid", M{"entries": []any{M{"kind": "record", "id": "sha256:x", "from": "2026-01-01T00:01:00Z"}}}},
		{"entry-time-invalid", "key_binding_invalid", M{"entries": []any{M{"kind": "key", "id": keys[1].ID, "from": "yesterday"}}}},
	} {
		v := base("envelope", 0)
		v.Fixture["snapshot_fault"] = row.fault
		add("H-snapshot-"+row.name, "Signed snapshot rejects "+row.name+" independently of a revocation match.", "PH-entries-64", row.code, v)
	}
	for _, name := range []string{"room", "to"} {
		v := base("envelope", 0)
		v.Fixture["delivery"].(M)[name] = strings.Repeat("x", 256)
		add("H-delivery-"+name, "Protected delivery "+name+" has its own 255-byte printable identifier bound.", "PC4", "message_context_unavailable", v)
	}
	for _, field := range []string{"owner", "epoch", "target"} {
		v := base("operator", 6)
		value := any(strings.Repeat("x", 256))
		if field == "target" {
			value = M{"kind": "registration", "id": true}
		}
		v.Fixture["binding"].(M)[field] = value
		add("H-act-binding-"+field, "Protected act binding "+field+" is independently typed and bounded before equality.", "PO1", "act_binding_mismatch", v)
	}
	for _, row := range []struct {
		name, code string
		edit       func(*Vector)
	}{
		{"now-invalid", "time_unavailable", func(v *Vector) { v.Fixture["now"] = "invalid" }},
		{"authority-invalid", "time_unavailable", func(v *Vector) { v.Fixture["time"].(M)["authority_until"] = 1 }},
		{"authority-expired", "time_unavailable", func(v *Vector) { v.Fixture["time"].(M)["authority_until"] = v.Fixture["now"] }},
		{"watermark-invalid", "watermark_unavailable", func(v *Vector) { v.Fixture["watermark"] = nil }},
	} {
		v := base("envelope", 0)
		row.edit(&v)
		add("H-time-"+row.name, "Protected time rejects "+row.name+" with an explicit unavailable decision.", "PE1", row.code, v)
	}
	for _, collection := range []string{"attestations", "revocations"} {
		for _, size := range []int{8192, 8193} {
			key := keys[0].ID
			if collection == "revocations" {
				key = keys[5].ID
			}
			v := base("envelope", 0)
			v.Fixture["record_mutation"] = M{"collection": collection, "key": key, "pad_to": size}
			prefix, code, pair := "PH-", "accept", ""
			if size == 8193 {
				prefix, code, pair = "H-", "key_binding_invalid", "PH-"+collection+"-bytes-8192"
			}
			add(prefix+collection+"-bytes-"+strconv.Itoa(size), "Received signed "+collection+" bytes enforce the inclusive "+strconv.Itoa(size)+" evidence limit before parsing.", pair, code, v)
		}
	}
	for _, row := range []struct {
		name  string
		value any
	}{
		{"overlong", strings.Repeat("x", 256)}, {"surrogate", json.RawMessage(`"\ud800"`)},
	} {
		v := base("grant", 0)
		v.Fixture["request"].(M)["target"].(M)["id"] = row.value
		add("H-request-target-"+row.name, "Protected request target rejects "+row.name+" identifier without an encoding exception.", "PG1", "request_target_invalid", v)
	}

}
