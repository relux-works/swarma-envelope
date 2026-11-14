// Command bip340check is an independent, test-only checker for the separately
// generated BIP-340 corpus. It imports no production parsing/crypto/verifier
// helpers. Its protocol scope is the explicit fixture modes below, not a
// replacement general platform verifier or deployment qualification.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/relux-works/swarma-envelope/tools/bip340check/oracle"
)

type object = map[string]any
type vector struct {
	ID       string `json:"id"`
	Claim    string `json:"claim"`
	Positive string `json:"positive_control"`
	Mode     string `json:"mode"`
	Input    object `json:"input"`
	Fixture  object `json:"fixture"`
	Expected struct {
		Code string `json:"code"`
		Plan object `json:"plan"`
	} `json:"expected"`
}
type refusal string

func need(ok bool, code string) {
	if !ok {
		panic(refusal(code))
	}
}
func obj(v any) object  { m, _ := v.(map[string]any); return m }
func text(v any) string { s, _ := v.(string); return s }
func list(v any) []any  { a, _ := v.([]any); return a }
func b64(v any, n int) []byte {
	s, ok := v.(string)
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	need(ok && e == nil && (n < 0 || len(b) == n) && base64.RawURLEncoding.EncodeToString(b) == s, "envelope_malformed")
	return b
}
func parse(b []byte) object {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m object
	need(d.Decode(&m) == nil, "envelope_malformed")
	var tail any
	need(d.Decode(&tail) == io.EOF, "envelope_malformed")
	return m
}

// The generated operands contain ASCII object keys/strings and integral JSON
// numbers. Marshal's sorted ASCII keys match CCJ here; reject unsupported
// operands rather than claim general Unicode/duplicate-member codec coverage.
func canon(v any) []byte {
	var check func(any)
	check = func(x any) {
		switch a := x.(type) {
		case string:
			for _, r := range a {
				need(r >= 32 && r <= 126, "checker_operand_unsupported")
			}
		case object:
			for k, v := range a {
				check(k)
				check(v)
			}
		case []any:
			for _, v := range a {
				check(v)
			}
		case json.Number:
			_, e := a.Int64()
			need(e == nil, "checker_operand_unsupported")
		case bool, nil:
		default:
			panic(refusal("checker_operand_unsupported"))
		}
	}
	check(v)
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	need(e.Encode(v) == nil, "checker_operand_unsupported")
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func tag(kind string) string {
	switch kind {
	case "message/1":
		return "swarma-msg/2"
	case "attestation/1", "revocation/1":
		return "swarma-attestation " + kind
	case "grant/1", "operator-act/1":
		return "swarma-waggle " + kind
	}
	panic(refusal("checker_operand_unsupported"))
}
func preimage(kind, key, role string, b object) []byte {
	return append([]byte(tag(kind)+"\n"), canon(object{"version": "swarm-envelope/2", "body": b, "key": key, "role": role})...)
}
func contentID(kind string, b object) string {
	return digest(append([]byte(tag(kind)+"\n"), canon(b)...))
}
func key(id string) (string, []byte) {
	alg, s, ok := strings.Cut(id, ":")
	need(ok && (alg == "bip340" || alg == "ed25519"), "envelope_malformed")
	return alg, b64(s, 32)
}
func signature(id string, sig, pre []byte) bool {
	alg, pub := key(id)
	if alg == "bip340" {
		h := sha256.Sum256(pre)
		return oracle.Verify(pub, h[:], sig)
	}
	return len(sig) == 64 && ed25519.Verify(pub, pre, sig)
}
func stamp(s any) time.Time {
	v, e := time.Parse("2006-01-02T15:04:05Z", text(s))
	need(e == nil, "key_binding_invalid")
	return v
}
func exact(m object, names string, code string) {
	fields := strings.Fields(names)
	need(m != nil && len(m) == len(fields), code)
	for _, n := range fields {
		_, ok := m[n]
		need(ok, code)
	}
}
func signed(raw any, kind, root string) object {
	e := parse(b64(raw, -1))
	b := obj(e["body"])
	ss := list(e["signatures"])
	need(len(ss) == 1, "key_binding_invalid")
	s := obj(ss[0])
	alg, _ := key(root)
	need(alg != "bip340" && e["version"] == "swarm-envelope/2" && b["type"] == kind && b["issuer"] == root && s["key"] == root && s["role"] == "author" && e["id"] == contentID(kind, b), "key_binding_invalid")
	need(signature(root, b64(s["sig"], 64), preimage(kind, root, "author", b)), "key_binding_invalid")
	return e
}
func mappedInvalid(f func()) {
	defer func() {
		if x := recover(); x != nil {
			if _, ok := x.(refusal); !ok {
				panic(x)
			}
			panic(refusal("key_binding_invalid"))
		}
	}()
	f()
}
func evaluate(v vector) (code string, plan object) {
	code, plan = "accept", object{}
	defer func() {
		if x := recover(); x != nil {
			if c, ok := x.(refusal); ok {
				code = string(c)
				plan = object{}
			} else {
				panic(x)
			}
		}
	}()
	f, in := v.Fixture, v.Input
	if v.Mode == "domain" {
		raw := b64(in["preimage"], -1)
		expected := text(f["expected_tag"])
		i := bytes.IndexByte(raw, '\n')
		need(i > 0 && i <= 96, "domain_tag_malformed")
		need(string(raw[:i]) == expected, "domain_mismatch")
		b := parse(raw[i+1:])
		need(bytes.Equal(canon(b), raw[i+1:]), "envelope_malformed")
		need(signature(text(in["key"]), b64(in["sig"], -1), raw), "envelope_signature_invalid")
		return code, object{"tag": expected, "key": in["key"]}
	}
	need(v.Mode == "envelope", "checker_operand_unsupported")
	raw := b64(in["envelope"], -1)
	e := parse(raw)
	b := obj(e["body"])
	ss := list(e["signatures"])
	exact(e, "version body id signatures", "envelope_malformed")
	exact(b, "type aud nonce iat exp room to body_sha256 author author_attestation action target arguments", "envelope_malformed")
	// Wire key grammar belongs before version/type/profile, as in the protocol.
	key(text(b["author"]))
	for _, x := range ss {
		exact(obj(x), "role key sig", "envelope_malformed")
		key(text(obj(x)["key"]))
	}
	need(e["version"] == "swarm-envelope/2", "envelope_version_unsupported")
	need(b["type"] == "message/1", "envelope_type_mismatch")
	hasAuthor := false
	seen := map[string]bool{}
	for _, x := range ss {
		s := obj(x)
		r, k := text(s["role"]), text(s["key"])
		need(r == "author" || r == "approver" || r == "delegate", "envelope_role_invalid")
		pair := r + "\x00" + k
		need(!seen[pair], "envelope_role_invalid")
		seen[pair] = true
		hasAuthor = hasAuthor || r == "author"
	}
	need(hasAuthor, "envelope_role_invalid")
	need(e["id"] == contentID("message/1", b), "envelope_id_mismatch")
	for _, x := range ss {
		s := obj(x)
		k, r := text(s["key"]), text(s["role"])
		if r == "author" {
			known := false
			for _, a := range list(f["known_keys"]) {
				known = known || a == k
			}
			need(known && k == b["author"], "signer_unknown")
		}
		alg, _ := key(k)
		need(r == "author" && (alg == "bip340" || alg == "ed25519"), "signature_profile_invalid")
		need(signature(k, b64(s["sig"], 64), preimage("message/1", k, r, b)), "envelope_signature_invalid")
	}
	need(f["audience"] == b["aud"], "audience_mismatch")
	d := obj(f["delivery"])
	need(d["room"] == b["room"] && d["to"] == b["to"], "message_delivery_mismatch")
	need(digest(b64(d["text"], -1)) == "sha256:"+text(b["body_sha256"]), "message_text_mismatch")
	now := stamp(f["now"])
	tm := obj(f["time"])
	need(tm["trusted"] == true && tm["fresh"] == true && now.Before(stamp(tm["authority_until"])), "time_unavailable")
	need(f["watermark_available"] == true, "watermark_unavailable")
	low, high := now, now
	w := stamp(f["watermark"])
	if w.Before(low) {
		low = w
	}
	if w.After(high) {
		high = w
	}
	need(high.Before(stamp(b["exp"])), "expired")
	need(!low.Before(stamp(b["iat"])), "not_yet_valid")
	rootPolicy := obj(f["service_root"])
	root := text(rootPolicy["key"])
	need(rootPolicy["purpose"] == json.Number("5"), "key_binding_invalid")
	reference := text(b["author_attestation"])
	aRaw := obj(f["attestations"])[reference]
	need(aRaw != nil, "key_binding_unavailable")
	var a object
	mappedInvalid(func() { a = signed(aRaw, "attestation/1", root) })
	ab := obj(a["body"])
	subject := obj(ab["subject"])
	keyID := text(subject["key_id"])
	mappedInvalid(func() {
		alg, pub := key(keyID)
		need(alg == "bip340" && oracle.ValidKey(pub) && subject["algorithm"] == "BIP-340" && bytes.Equal(b64(subject["public_bytes"], 32), pub), "key_binding_invalid")
	})
	need(ab["key_class"] == "agent" && ab["purpose"] == "swarma-msg" && reflect.DeepEqual(ab["roles"], []any{"author"}) && reflect.DeepEqual(ab["actions"], []any{"message.sign"}), "key_binding_invalid")
	current := obj(obj(f["active_generations"])[keyID])
	need(current != nil, "key_binding_unavailable")
	need(current["active"] == true, "key_binding_invalid")
	binding := obj(ab["binding"])
	exact(binding, "owner path generation registration_number master_epoch uid", "key_binding_invalid")
	for k, value := range binding {
		need(reflect.DeepEqual(current[k], value), "key_binding_invalid")
	}
	start, end := stamp(ab["iat"]), stamp(ab["exp"])
	need(end.After(start) && end.Sub(start) <= 24*time.Hour && !low.Before(start) && high.Before(end), "key_binding_invalid")
	rp := obj(f["agent_revocation_root"])
	revoker := text(rp["key"])
	need(rp["purpose"] == "registry-revocation" && rp["attestation_root"] == root && revoker != root, "key_binding_invalid")
	row := obj(obj(f["revocations"])[revoker])
	need(row != nil && row["availability"] == "available", "key_binding_unavailable")
	var snap object
	mappedInvalid(func() { snap = signed(row["snapshot"], "revocation/1", revoker) })
	sb := obj(snap["body"])
	need(sb["complete"] == true && row["rollback_safe"] == true, "key_binding_unavailable")
	issued := stamp(sb["issued_at"])
	maxAge, err := row["max_age"].(json.Number).Int64()
	need(err == nil && maxAge > 0 && maxAge <= 60, "key_binding_invalid")
	need(!issued.After(low) && high.Sub(issued) <= time.Duration(maxAge)*time.Second, "key_binding_unavailable")
	for _, x := range list(sb["entries"]) {
		entry := obj(x)
		if stamp(entry["from"]).After(high) {
			continue
		}
		need(!(entry["kind"] == "key" && entry["id"] == keyID || entry["kind"] == "record" && entry["id"] == a["id"]), "revoked")
	}
	need(a["id"] == reference && keyID == b["author"], "author_attestation_mismatch")
	need(f["id_journal_available"] == true && obj(f["seen"]) != nil, "envelope_state_unavailable")
	need(len(obj(f["seen"])) == 0, "checker_operand_unsupported")
	return code, object{"ids": []any{e["id"]}, "watermark": high.UTC().Format("2006-01-02T15:04:05Z")}
}

const officialHash = "34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d"

func checkOfficial(path, plant string, w io.Writer) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if digest(raw) != "sha256:"+officialHash {
		return errors.New("official CSV hash mismatch")
	}
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		return err
	}
	applied := plant == ""
	mismatches := 0
	for _, row := range rows[1:] {
		decode := func(s string) []byte {
			b, e := hex.DecodeString(s)
			if e != nil {
				panic(e)
			}
			return b
		}
		got := oracle.Verify(decode(row[2]), decode(row[4]), decode(row[5]))
		want := row[6] == "TRUE"
		if plant == "valid-refused" && row[0] == "0" {
			got = false
			applied = true
			fmt.Fprintln(w, "control applied: valid-refused official=0")
		}
		if plant == "invalid-accepted" && row[0] == "5" {
			got = true
			applied = true
			fmt.Fprintln(w, "control applied: invalid-accepted official=5")
		}
		if got != want {
			fmt.Fprintf(w, "official verdict mismatch: index=%s expected=%t observed=%t\n", row[0], want, got)
			mismatches++
		}
	}
	if !applied {
		return errors.New("control not applied")
	}
	if mismatches != 0 {
		return fmt.Errorf("%d official verdict mismatches", mismatches)
	}
	fmt.Fprintf(w, "oracle: %d official expected results matched, including original arbitrary-length messages\n", len(rows)-1)
	return nil
}
func checkVectors(dir string, w io.Writer) error {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("empty BIP-340 corpus")
	}
	loaded := map[string]vector{}
	for _, path := range paths {
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		d.DisallowUnknownFields()
		var v vector
		if e = d.Decode(&v); e != nil {
			return e
		}
		if _, ok := loaded[v.ID]; ok {
			return errors.New("duplicate vector id")
		}
		loaded[v.ID] = v
		got, plan := evaluate(v)
		if got != v.Expected.Code || !reflect.DeepEqual(plan, v.Expected.Plan) {
			return fmt.Errorf("protocol verdict mismatch: %s got=%s plan=%v expected=%s plan=%v", v.ID, got, plan, v.Expected.Code, v.Expected.Plan)
		}
	}
	for _, v := range loaded {
		if v.Expected.Code != "accept" {
			p, ok := loaded[v.Positive]
			if !ok || p.Expected.Code != "accept" {
				return fmt.Errorf("missing valid control: %s", v.ID)
			}
		}
	}
	fmt.Fprintf(w, "independent protocol/hash/domain checker: %d BIP-340 vectors matched\n", len(paths))
	return nil
}
func main() {
	official := flag.String("official", "tools/bip340check/testdata/official/test-vectors.csv", "pinned official CSV")
	vectors := flag.String("vectors", "vectors/bip340", "separate profile corpus")
	plant := flag.String("plant", "", "isolated control: valid-refused or invalid-accepted")
	flag.Parse()
	if *plant != "" && *plant != "valid-refused" && *plant != "invalid-accepted" {
		fmt.Fprintln(os.Stderr, "unknown control")
		os.Exit(2)
	}
	if e := checkOfficial(*official, *plant, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if e := checkVectors(*vectors, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
