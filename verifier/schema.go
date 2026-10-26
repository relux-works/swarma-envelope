package verifier

import (
	"bytes"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
)

func exact(v any, names, code string) map[string]any {
	m, ok := v.(map[string]any)
	parts := strings.Fields(names)
	need(ok && len(m) == len(parts), code)
	for _, n := range parts {
		_, ok := m[n]
		need(ok, code)
	}
	return m
}
func evidence(v any, names string) map[string]any {
	need(v != nil, "key_binding_unavailable")
	m, ok := v.(map[string]any)
	need(ok, "key_binding_invalid")
	for _, n := range strings.Fields(names) {
		need(m[n] != nil, "key_binding_unavailable")
	}
	return m
}
func evidenceExact(v any, names string) map[string]any {
	m := evidence(v, names)
	return exact(m, names, "key_binding_invalid")
}
func ascii(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) < 1 || len(s) > 255 {
		return false
	}
	for _, c := range []byte(s) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func text(v any, code string) string {
	s, ok := v.(string)
	need(ok && utf8.ValidString(s) && len(s) >= 1 && len(s) <= 255, code)
	return s
}
func stamp(v any) int64 {
	s, ok := v.(string)
	need(ok && len(s) == 20, "envelope_malformed")
	t, e := time.Parse("2006-01-02T15:04:05Z", s)
	need(e == nil && t.Year() >= 1970 && t.Format("2006-01-02T15:04:05Z") == s, "envelope_malformed")
	return t.Unix()
}
func key(v any) (string, []byte) {
	s, ok := v.(string)
	need(ok, "envelope_malformed")
	a, b, e := record.KeyBytes(s)
	if e != nil {
		panic(refusal(errorCode(e)))
	}
	return a, b
}
func hashID(v any)           { need(isString(v) && record.IsContentID(str(v)), "envelope_malformed") }
func equal(a, b any) bool    { return reflect.DeepEqual(a, b) }
func canonical(v any) []byte { return must(record.Canonical(v)) }
func ident(v any, pattern, single bool) bool {
	s, ok := v.(string)
	if !ok || len(s) < 1 || len(s) > 255 {
		return false
	}
	if pattern {
		s = strings.TrimSuffix(s, "/*")
	}
	if len(s) == 0 {
		return false
	}
	parts := strings.Split(s, "/")
	if single && len(parts) != 1 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range []byte(p) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func target(v any, pattern, operator bool) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	kind := str(m["kind"])
	n := 2
	if kind == "credential" {
		n = 4
	}
	if len(m) != n {
		return false
	}
	if _, ok := m["id"]; !ok {
		return false
	}
	if operator {
		if kind != "registration" && kind != "account" {
			return false
		}
	} else if kind != "credential" && kind != "station" {
		return false
	}
	if kind == "registration" {
		return isInt(m["id"]) && num(m["id"]) >= 1 && num(m["id"]) <= 9007199254740991
	}
	if !ident(m["id"], pattern, false) {
		return false
	}
	return kind != "credential" || ident(m["harness"], false, true) && ident(m["profile"], false, true)
}
func assurance(v any, code string) (int, bool) {
	m := exact(v, "level presence", code)
	need(isString(m["level"]) && isBool(m["presence"]), code)
	level := 0
	switch m["level"] {
	case "A1":
		level = 1
	case "A2":
		level = 2
	case "A3":
		level = 3
	}
	need(level > 0, code)
	return level, m["presence"] == true
}
func stringsArray(v any) ([]any, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	for _, x := range a {
		if !isString(x) {
			return nil, false
		}
	}
	return a, true
}
func includes(a []any, s any) bool {
	for _, v := range a {
		if equal(v, s) {
			return true
		}
	}
	return false
}
func schema(e map[string]any, kind string) {
	exact(e, "version body id signatures", "envelope_malformed")
	need(isString(e["version"]), "envelope_malformed")
	hashID(e["id"])
	extra := ""
	switch kind {
	case "message/1":
		extra = "author author_attestation action target arguments room to body_sha256"
	case "grant/1":
		extra = "issuer subject actions targets not_before expires depth parent caveats min_assurance"
	case "operator-act/1":
		extra = "operation target owner epoch action_id arguments_digest confirmed"
	default:
		panic(refusal("envelope_type_mismatch"))
	}
	b := exact(e["body"], "type aud nonce iat exp "+extra, "envelope_malformed")
	need(isString(b["type"]) && ascii(b["aud"]), "envelope_malformed")
	must(record.DecodeBase64(str(b["nonce"]), 16))
	need(isString(b["nonce"]), "envelope_malformed")
	start, end := stamp(b["iat"]), stamp(b["exp"])
	need(start < end && (kind == "grant/1" || end-start <= 120), "envelope_malformed")
	sigs, ok := e["signatures"].([]any)
	need(ok && len(sigs) >= 1 && len(sigs) <= 8, "envelope_malformed")
	for _, s := range sigs {
		m := exact(s, "role key sig", "envelope_malformed")
		need(isString(m["role"]) && isString(m["sig"]), "envelope_malformed")
		key(m["key"])
		must(record.DecodeBase64(str(m["sig"]), 64))
	}
	switch kind {
	case "message/1":
		need(ascii(b["room"]) && ascii(b["to"]), "envelope_malformed")
		need(record.IsContentID("sha256:"+str(b["body_sha256"])), "envelope_malformed")
		key(b["author"])
		hashID(b["author_attestation"])
		need(isString(b["action"]) && target(b["target"], false, false) && obj(b["arguments"]) != nil, "envelope_malformed")
	case "operator-act/1":
		need(isString(b["operation"]) && ident(strings.ReplaceAll(str(b["operation"]), ".", "/"), false, false) && target(b["target"], false, true), "envelope_malformed")
		text(b["owner"], "envelope_malformed")
		need(ascii(b["epoch"]) && isString(b["action_id"]), "envelope_malformed")
		must(record.DecodeBase64(str(b["action_id"]), 16))
		hashID(b["arguments_digest"])
		need(isBool(b["confirmed"]), "envelope_malformed")
	case "grant/1":
		assurance(b["min_assurance"], "envelope_malformed")
		key(b["issuer"])
		key(b["subject"])
		acts, ok := stringsArray(b["actions"])
		need(ok && len(acts) > 0 && len(acts) <= 64, "envelope_malformed")
		last := ""
		for i, a := range acts {
			need(i == 0 || str(a) > last, "envelope_malformed")
			last = str(a)
		}
		targets, ok := b["targets"].([]any)
		need(ok && len(targets) > 0 && len(targets) <= 64, "envelope_malformed")
		seen := map[string]bool{}
		for _, t := range targets {
			need(target(t, true, false), "envelope_malformed")
			c := string(canonical(t))
			need(!seen[c], "envelope_malformed")
			seen[c] = true
		}
		need(isInt(b["depth"]) && num(b["depth"]) >= 0 && num(b["depth"]) <= 3, "envelope_malformed")
		if b["parent"] != nil {
			hashID(b["parent"])
		}
		need(equal(b["iat"], b["not_before"]) && equal(b["exp"], b["expires"]), "envelope_malformed")
		if b["caveats"] != nil {
			c := exact(b["caveats"], "lang not_before expires", "envelope_malformed")
			a, z := stamp(c["not_before"]), stamp(c["expires"])
			need(c["lang"] == "caveats/v1" && start <= a && a < z && z <= end, "envelope_malformed")
		}
	}
}
func times(f facts) (int64, int64) {
	t := obj(f["time"])
	need(t != nil && t["trusted"] == true && t["fresh"] == true, "time_unavailable")
	var now, authority int64
	mapped(func() bool { now, authority = stamp(f["now"]), stamp(t["authority_until"]); return true }, "*", "time_unavailable")
	need(now < authority, "time_unavailable")
	need(f["watermark_available"] == true, "watermark_unavailable")
	w := mapped(func() int64 { return stamp(f["watermark"]) }, "*", "watermark_unavailable")
	return min(now, w), max(now, w)
}
func window(b map[string]any, low, high int64) {
	need(high < stamp(b["exp"]), "expired")
	need(low >= stamp(b["iat"]), "not_yet_valid")
}
func delivery(b map[string]any, f facts) {
	d := obj(f["delivery"])
	need(d != nil && ascii(d["room"]) && ascii(d["to"]), "message_context_unavailable")
	need(equal(b["room"], d["room"]), "message_room_mismatch")
	need(equal(b["to"], d["to"]), "message_recipient_mismatch")
	need(d["text"] != nil, "message_text_unavailable")
	txt, ok := d["text"].([]byte)
	need(ok && utf8.Valid(txt), "message_text_invalid")
	need(record.Digest(txt) == "sha256:"+str(b["body_sha256"]), "message_text_mismatch")
}
func journal(e map[string]any, raw []byte, f facts) {
	need(f["id_journal_available"] == true, "id_journal_unavailable")
	seen, ok := f["seen"].(map[string]any)
	need(ok, "id_journal_unavailable")
	if v, ok := seen[str(e["id"])]; ok {
		b, ok := v.([]byte)
		need(ok, "envelope_malformed")
		need(bytes.Equal(b, raw), "envelope_conflict")
	}
}
