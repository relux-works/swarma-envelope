// Command vectors creates test-only fixtures, never deployment keys or authority.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
)

type M = map[string]any
type Key struct {
	ID   string
	Seed []byte
	Ed   ed25519.PrivateKey
	EC   *ecdsa.PrivateKey
}
type Vector struct {
	ID       string `json:"id"`
	Claim    string `json:"claim"`
	Positive string `json:"positive_control"`
	Mode     string `json:"mode"`
	Input    M      `json:"input"`
	Fixture  M      `json:"fixture"`
	Expected M      `json:"expected"`
}

var keys []Key
var cases []Vector

func b64(b []byte) string   { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) []byte { b, e := base64.RawURLEncoding.DecodeString(s); must(e); return b }
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func canonical(v any) []byte {
	b, e := json.Marshal(v)
	must(e)
	p, e := ccj.Parse(b, ccj.RegistrationMalformed)
	must(e)
	b, e = ccj.Marshal(p, ccj.RegistrationMalformed)
	must(e)
	return b
}

func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func wire(m M) string        { return b64(canonical(m)) }
func decode(s string) M      { var m M; must(json.Unmarshal(unb64(s), &m)); return m }
func body(v Vector) M        { return decode(v.Input["envelope"].(string))["body"].(map[string]any) }
func domain(t string) string {
	switch t {
	case "message/1":
		return "swarma-msg/2"
	case "grant/1":
		return "swarma-waggle grant/1"
	case "operator-act/1":
		return "swarma-waggle operator-act/1"
	default:
		panic("unregistered type")
	}
}
func sigPre(b M, role, key, t string) []byte {
	return append([]byte(domain(t)+"\n"), canonical(M{"version": "swarm-envelope/2", "body": b, "key": key, "role": role})...)
}
func sign(k Key, p []byte) []byte {
	if k.Ed != nil {
		return ed25519.Sign(k.Ed, p)
	}
	// Deterministic test-only ECDSA: NOT a production signing implementation.
	h := sha256.Sum256(append(append([]byte{}, k.Seed...), p...))
	n := k.EC.Curve.Params().N
	nonce := new(big.Int).SetBytes(h[:])
	nonce.Mod(nonce, new(big.Int).Sub(n, big.NewInt(1)))
	nonce.Add(nonce, big.NewInt(1))
	x, _ := k.EC.Curve.ScalarBaseMult(nonce.Bytes())
	r := new(big.Int).Mod(x, n)
	z := sha256.Sum256(p)
	s := new(big.Int).Mul(r, k.EC.D)
	s.Add(s, new(big.Int).SetBytes(z[:]))
	s.Mul(s, new(big.Int).ModInverse(nonce, n))
	s.Mod(s, n)
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}
func envelope(b M, k Key, role string) M {
	return signed(b, k, role, b["type"].(string), domain(b["type"].(string)))
}
func signed(b M, k Key, role, t, d string) M {
	return M{"version": "swarm-envelope/2", "body": b, "id": digest(append([]byte(d+"\n"), canonical(b)...)), "signatures": []any{M{"role": role, "key": k.ID, "sig": b64(sign(k, sigPre(b, role, k.ID, t)))}}}
}
func common(t string) M {
	return M{"type": t, "aud": "service-a", "nonce": b64(bytes.Repeat([]byte{7}, 16)), "iat": "2026-01-01T00:00:00Z", "exp": "2026-01-01T00:02:00Z"}
}
func target(id string) M {
	return M{"kind": "credential", "id": id, "harness": "model-cli", "profile": "dev"}
}
func context() M {
	f := M{"now": "2026-01-01T00:01:00Z", "watermark": "2026-01-01T00:01:00Z", "time": M{"trusted": true, "fresh": true, "authority_until": "2026-01-01T00:06:00Z"}, "watermark_available": true, "audience": "service-a", "known_keys": []any{keys[0].ID, keys[1].ID, keys[2].ID, keys[6].ID}, "required_roles": []any{"author"}, "id_journal_available": true, "seen": M{}, "root": keys[0].ID, "revocation": M{"verdict": "not_revoked", "issued_at": "2026-01-01T00:01:00Z", "max_age": 60, "complete": true, "rollback_safe": true, "revoked_ids": []any{}, "revoked_keys": []any{}}, "replay_available": true, "used_actions": []any{}, "signer_facts": M{"presence": true, "current": true, "presence_current": true}, "binding": M{"operation": "revoke", "target": M{"kind": "registration", "id": 1}, "owner": "owner-a", "epoch": "epoch-1", "arguments": M{"registration_number": 1, "mode": "operator"}}, "request": M{"key": keys[2].ID, "action": "credential.lease", "target": target("team/member")}}
	expected, evidence := M{}, M{}
	for i, k := range keys[:6] {
		binding := M{"owner": "owner-a", "path": fmt.Sprintf("message/agent-%d", i), "generation": fmt.Sprintf("generation-%d", i), "registration_number": i + 1, "epoch": "epoch-1"}
		expected[k.ID] = binding
		evidence[k.ID] = M{"binding": binding, "class": "agent", "key": k.ID, "public_bytes": b64(k.Ed.Public().(ed25519.PublicKey)), "purpose": "message-signing", "not_before": "2025-12-01T00:00:00Z", "not_after": "2026-02-01T00:00:00Z", "attestation": "valid", "revocation": "not_revoked", "active": true}
	}
	f["agent_expected"], f["agent_evidence"] = expected, evidence
	f["operator_pins"] = []any{keys[6].ID}
	return f
}

func base(mode string, idx int) Vector {
	if mode == "operator" && idx == 0 {
		idx = 6
	}
	f := context()
	v := Vector{Mode: mode, Input: M{}, Fixture: f}
	if mode == "grant" {
		v.Input["chain"] = chain(2)
		return v
	}
	t, role := "message/1", "author"
	if mode == "operator" {
		t, role = "operator-act/1", "approver"
		f["required_roles"] = []any{"approver"}
	}
	b := common(t)
	if mode == "operator" {
		for k, val := range (M{"operation": "revoke", "target": M{"kind": "registration", "id": 1}, "owner": "owner-a", "epoch": "epoch-1", "action_id": b64(bytes.Repeat([]byte{8}, 16)), "arguments_digest": digest(canonical(f["binding"].(M)["arguments"])), "confirmed": false}) {
			b[k] = val
		}
	} else {
		b["author"] = keys[idx].ID
		b["action"] = "message.deliver"
		b["target"] = M{"kind": "station", "id": "team/member"}
		b["arguments"] = M{"text": "hello"}
	}
	v.Input["envelope"] = wire(envelope(b, keys[idx], role))
	return v
}
func chain(n int) []any {
	var out []any
	parent := any(nil)
	for i := 0; i < n; i++ {
		b := common("grant/1")
		b["issuer"] = keys[i].ID
		b["subject"] = keys[i+1].ID
		b["actions"] = []any{"credential.lease"}
		b["targets"] = []any{target("team/*")}
		b["depth"] = max(3-i, 0)
		b["parent"] = parent
		b["caveats"] = nil
		if i == 0 {
			b["iat"] = "2025-12-31T00:00:00Z"
			b["exp"] = "2026-01-02T00:00:00Z"
		}
		b["not_before"] = b["iat"]
		b["expires"] = b["exp"]
		e := envelope(b, keys[i], "author")
		parent = e["id"]
		out = append([]any{wire(e)}, out...)
	}
	return out
}
func edit(v *Vector, fn func(M)) {
	e := decode(v.Input["envelope"].(string))
	fn(e)
	v.Input["envelope"] = wire(e)
}
func resign(v *Vector, idx int, fn func(M)) {
	if v.Mode == "operator" && idx == 0 {
		idx = 6
	}
	b := body(*v)
	fn(b)
	role := "author"
	if v.Mode == "operator" {
		role = "approver"
	}
	v.Input["envelope"] = wire(envelope(b, keys[idx], role))
}
func link(v *Vector, i, idx int, fn func(M)) {
	a := v.Input["chain"].([]any)
	b := decode(a[i].(string))["body"].(map[string]any)
	fn(b)
	a[i] = wire(envelope(b, keys[idx], "author"))
}
func add(id, claim, pair, code string, v Vector) {
	pruneAgentEvidence(&v)
	v.ID = id
	v.Claim = claim
	v.Positive = pair
	v.Expected = M{"code": code, "plan": M{}}
	if code == "accept" && v.Mode == "signer" {
		v.Expected["plan"] = M{"tag": "swarma-msg/2", "preimage_sha256": digest(unb64(v.Input["preimage"].(string)))}
	} else if code == "accept" && v.Mode == "domain" {
		v.Expected["plan"] = M{"tag": v.Fixture["expected_tag"], "key": v.Input["key"]}
	} else if code == "accept" {
		ids := []any{}
		if v.Mode == "grant" {
			for _, raw := range v.Input["chain"].([]any) {
				ids = append(ids, decode(raw.(string))["id"])
			}
		} else {
			ids = append(ids, decode(v.Input["envelope"].(string))["id"])
		}
		p := M{"watermark": v.Fixture["now"], "ids": ids}
		if v.Fixture["watermark"].(string) > v.Fixture["now"].(string) {
			p["watermark"] = v.Fixture["watermark"]
		}
		if v.Mode == "operator" {
			p["action_id"] = body(v)["action_id"]
		}
		v.Expected["plan"] = p
	}
	cases = append(cases, v)
}
func neg(id, claim, pair, code, mode string, fn func(*Vector)) {
	v := base(mode, 0)
	fn(&v)
	add(id, claim, pair, code, v)
}
func main() {
	out := flag.String("out", "vectors", "fixture root")
	check := flag.Bool("check", false, "compare all generated bytes without writing")
	flag.Parse()
	for i := 0; i < 6; i++ {
		seed := sha256.Sum256([]byte(fmt.Sprintf("waggle public test seed %d", i)))
		private := ed25519.NewKeyFromSeed(seed[:])
		keys = append(keys, Key{ID: "ed25519:" + b64(private.Public().(ed25519.PublicKey)), Seed: seed[:], Ed: private})
	}
	seed := sha256.Sum256([]byte("waggle public test p256 seed"))
	c := elliptic.P256()
	d := new(big.Int).SetBytes(seed[:])
	d.Mod(d, new(big.Int).Sub(c.Params().N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	x, y := c.ScalarBaseMult(d.Bytes())
	keys = append(keys, Key{ID: "p256:" + b64(elliptic.MarshalCompressed(c, x, y)), Seed: seed[:], EC: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: d}})
	// Each negative states its specific claim and names a valid neighboring control.
	neg("E01", "Duplicate decoded member names refuse before hashing.", "PE1", "envelope_malformed", "envelope", func(v *Vector) {
		raw := unb64(v.Input["envelope"].(string))
		v.Input["envelope"] = b64(bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"swarm-envelope/2","ver\u0073ion":`), 1))
	})
	lexical := []struct{ id, claim, old, new string }{
		{"E02", "Floats refuse the codec.", `"text":"hello"`, `"text":1.0`}, {"E03", "Exponents refuse the codec.", `"text":"hello"`, `"text":1e0`}, {"E04", "Negative zero refuses the codec.", `"text":"hello"`, `"text":-0`}, {"E05", "Unsafe integers refuse the codec.", `"text":"hello"`, `"text":9007199254740992`}, {"E06", "Lone surrogate refuses the codec.", `"text":"hello"`, `"text":"\ud800"`}}
	for _, a := range lexical {
		neg(a.id, a.claim, "PE1", "envelope_malformed", "envelope", func(v *Vector) {
			v.Input["envelope"] = b64(bytes.Replace(unb64(v.Input["envelope"].(string)), []byte(a.old), []byte(a.new), 1))
		})
	}
	neg("E07", "Invalid UTF-8 refuses.", "PE1", "envelope_malformed", "envelope", func(v *Vector) {
		v.Input["envelope"] = b64(append([]byte{255}, unb64(v.Input["envelope"].(string))...))
	})
	neg("E08", "Unknown fields refuse.", "PE1", "envelope_malformed", "envelope", func(v *Vector) { edit(v, func(e M) { e["extra"] = true }) })
	neg("E09", "Unknown versions refuse without fallback.", "PE1", "envelope_version_unsupported", "envelope", func(v *Vector) { edit(v, func(e M) { e["version"] = "swarm-envelope/3" }) })
	neg("E10", "Channel selects type, not signed body.", "PE1", "envelope_type_mismatch", "envelope", func(v *Vector) { resign(v, 0, func(b M) { b["type"] = "grant/1" }) })
	neg("E11", "Wrong id refuses before crypto.", "PE1", "envelope_id_mismatch", "envelope", func(v *Vector) { edit(v, func(e M) { e["id"] = "sha256:" + strings.Repeat("0", 64) }) })
	neg("E12", "Invalid equation refuses.", "PE1", "envelope_signature_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) {
			s := e["signatures"].([]any)[0].(map[string]any)
			raw := unb64(s["sig"].(string))
			raw[5] ^= 1
			s["sig"] = b64(raw)
		})
	})
	neg("E13", "An agent author signature cannot count as an operator approver.", "PE1", "signature_profile_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) {
			a := e["signatures"].([]any)
			old := a[0].(map[string]any)
			e["signatures"] = append(a, M{"role": "approver", "key": old["key"], "sig": old["sig"]})
		})
		v.Fixture["required_roles"] = []any{"author", "approver"}
	})
	neg("E14", "Type-domain signature transplant fails after expected id repair.", "PE1", "envelope_signature_invalid", "envelope", func(v *Vector) {
		b := body(*v)
		v.Input["envelope"] = wire(signed(b, keys[0], "author", "grant/1", domain("message/1")))
	})
	neg("E15", "Foreign id domain refuses.", "PE1", "envelope_id_mismatch", "envelope", func(v *Vector) {
		b := body(*v)
		v.Input["envelope"] = wire(signed(b, keys[0], "author", "message/1", "foreign message/1"))
	})
	neg("E16", "Reserved role refuses.", "PE1", "envelope_role_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) { e["signatures"].([]any)[0].(map[string]any)["role"] = "endorser" })
	})
	neg("E17", "Missing required role refuses.", "PE1", "envelope_role_invalid", "envelope", func(v *Vector) { v.Fixture["required_roles"] = []any{"approver"} })
	neg("E18", "Duplicate signature pair refuses.", "PE1", "envelope_role_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) { a := e["signatures"].([]any); e["signatures"] = append(a, a[0]) })
	})
	neg("E19", "Oversize received bytes refuse before parsing.", "PE1", "envelope_too_large", "envelope", func(v *Vector) {
		v.Input["envelope"] = b64(append(unb64(v.Input["envelope"].(string)), bytes.Repeat([]byte{' '}, 65536)...))
	})
	neg("E20", "Depth 17 refuses.", "PE1", "envelope_malformed", "envelope", func(v *Vector) {
		raw := unb64(v.Input["envelope"].(string))
		deep := strings.Repeat("[", 14) + `"hello"` + strings.Repeat("]", 14)
		v.Input["envelope"] = b64(bytes.Replace(raw, []byte(`"hello"`), []byte(deep), 1))
	})
	neg("E21", "Padded base64 refuses.", "PE1", "envelope_malformed", "envelope", func(v *Vector) {
		edit(v, func(e M) { s := e["signatures"].([]any)[0].(map[string]any); s["sig"] = s["sig"].(string) + "=" })
	})
	neg("E22", "Unknown signer is not trusted.", "PE1", "signer_unknown", "envelope", func(v *Vector) { v.Fixture["known_keys"] = []any{keys[1].ID} })
	neg("E23", "Same id with other received bytes conflicts.", "PE1", "envelope_conflict", "envelope", func(v *Vector) {
		e := decode(v.Input["envelope"].(string))
		v.Fixture["seen"] = M{e["id"].(string): b64(append(unb64(v.Input["envelope"].(string)), ' '))}
	})
	neg("E24", "Unavailable id journal refuses.", "PE1", "id_journal_unavailable", "envelope", func(v *Vector) { v.Fixture["id_journal_available"] = false })
	neg("E25", "Untrusted clock refuses.", "PE1", "time_unavailable", "envelope", func(v *Vector) { v.Fixture["time"].(M)["trusted"] = false })
	neg("E26", "Unavailable watermark refuses.", "PE1", "watermark_unavailable", "envelope", func(v *Vector) { v.Fixture["watermark_available"] = false })
	neg("E27", "High-S P-256 twin refuses.", "PO1", "signature_high_s", "operator", func(v *Vector) {
		*v = base("operator", 6)
		edit(v, func(e M) {
			s := e["signatures"].([]any)[0].(map[string]any)
			r := unb64(s["sig"].(string))
			hi := new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(r[32:]))
			hi.FillBytes(r[32:])
			s["sig"] = b64(r)
		})
	})
	neg("E28", "Ed25519 noncanonical scalar refuses.", "PE1", "envelope_signature_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) {
			s := e["signatures"].([]any)[0].(map[string]any)
			r := unb64(s["sig"].(string))
			for i := 32; i < 64; i++ {
				r[i] = 255
			}
			s["sig"] = b64(r)
		})
	})
	neg("E29", "Ed25519 identity point refuses.", "PE1", "envelope_signature_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) {
			s := e["signatures"].([]any)[0].(map[string]any)
			r := unb64(s["sig"].(string))
			for i := 0; i < 32; i++ {
				r[i] = 0
			}
			r[0] = 1
			s["sig"] = b64(r)
		})
	})
	neg("E30", "Changed body with repaired id still fails signature.", "PE1", "envelope_signature_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) {
			b := e["body"].(map[string]any)
			b["arguments"].(map[string]any)["text"] = "changed"
			e["id"] = digest(append([]byte("swarma-msg/2\n"), canonical(b)...))
		})
	})
	neg("E31", "Wrong audience refuses.", "PE1", "audience_mismatch", "envelope", func(v *Vector) { v.Fixture["audience"] = "service-b" })
	// Grant witnesses modify signed records, so failures must reach authority checks.
	neg("G01", "Action widening refuses.", "PG1", "grant_not_narrowing", "grant", func(v *Vector) { link(v, 0, 1, func(b M) { b["actions"] = []any{"agent.spawn", "credential.lease"} }) })
	neg("G02", "Target widening refuses.", "PG1", "grant_not_narrowing", "grant", func(v *Vector) { link(v, 0, 1, func(b M) { b["targets"] = []any{target("other/*")} }) })
	neg("G03", "Earlier start widens raw lifetime.", "PG1", "grant_not_narrowing", "grant", func(v *Vector) {
		link(v, 0, 1, func(b M) { b["not_before"] = "2025-12-30T00:00:00Z"; b["iat"] = b["not_before"] })
	})
	neg("G04", "Later expiry widens lifetime.", "PG1", "grant_not_narrowing", "grant", func(v *Vector) {
		link(v, 0, 1, func(b M) { b["expires"] = "2026-01-03T00:00:00Z"; b["exp"] = b["expires"] })
	})
	neg("G05", "Delegation depth must decrease.", "PG1", "grant_not_narrowing", "grant", func(v *Vector) { link(v, 0, 1, func(b M) { b["depth"] = 3 }) })
	neg("G06", "Five-link chain refuses before link verification.", "PG4", "grant_chain_malformed", "grant", func(v *Vector) { v.Input["chain"] = chain(5) })
	neg("G07", "Broken leaf parent reference refuses.", "PG1", "grant_chain_broken", "grant", func(v *Vector) { link(v, 0, 1, func(b M) { b["parent"] = "sha256:" + strings.Repeat("0", 64) }) })
	neg("G08", "Child issuer must equal parent subject.", "PG1", "grant_chain_broken", "grant", func(v *Vector) { link(v, 0, 0, func(b M) { b["issuer"] = keys[0].ID }) })
	neg("G09", "Root must be pinned.", "PG1", "grant_root_unknown", "grant", func(v *Vector) { v.Fixture["root"] = keys[3].ID })
	neg("G10", "Expiry is exclusive.", "PG1", "expired", "grant", func(v *Vector) { v.Fixture["now"] = "2026-01-01T00:02:00Z" })
	neg("G11", "Future grant refuses.", "PG1", "not_yet_valid", "grant", func(v *Vector) { v.Fixture["now"] = "2025-12-31T23:59:59Z" })
	neg("G12", "Watermark rollback cannot revive expired leaf.", "PG1", "expired", "grant", func(v *Vector) { v.Fixture["watermark"] = "2026-01-01T00:02:00Z" })
	neg("G13", "Root revocation invalidates leaf.", "PG1", "revoked", "grant", func(v *Vector) {
		v.Fixture["revocation"].(M)["revoked_ids"] = []any{decode(v.Input["chain"].([]any)[1].(string))["id"]}
	})
	neg("G14", "Unavailable revocation refuses.", "PG1", "revocation_unavailable", "grant", func(v *Vector) { v.Fixture["revocation"].(M)["verdict"] = "unavailable" })
	neg("G15", "Unregistered action refuses even on pinned root.", "PG2", "action_unregistered", "grant", func(v *Vector) {
		v.Input["chain"] = chain(1)
		v.Fixture["request"].(M)["key"] = keys[1].ID
		link(v, 0, 0, func(b M) { b["actions"] = []any{"unknown.action"} })
	})
	neg("G16", "Pattern in concrete request refuses.", "PG1", "request_target_invalid", "grant", func(v *Vector) { v.Fixture["request"].(M)["target"] = target("team/*") })
	neg("G17", "Wrong requesting key refuses.", "PG1", "grant_not_authorized", "grant", func(v *Vector) { v.Fixture["request"].(M)["key"] = keys[1].ID })
	neg("G18", "Wrong target refuses.", "PG1", "grant_not_authorized", "grant", func(v *Vector) { v.Fixture["request"].(M)["target"] = target("other/member") })
	neg("G19", "Credential tuple cannot change harness.", "PG1", "grant_not_narrowing", "grant", func(v *Vector) {
		link(v, 0, 1, func(b M) { b["targets"].([]any)[0].(map[string]any)["harness"] = "other" })
	})
	neg("G20", "Credential tuple cannot change profile.", "PG1", "grant_not_narrowing", "grant", func(v *Vector) {
		link(v, 0, 1, func(b M) { b["targets"].([]any)[0].(map[string]any)["profile"] = "other" })
	})
	neg("G21", "Caveat expiry refuses.", "PG3", "expired", "grant", func(v *Vector) {
		link(v, 0, 1, func(b M) {
			b["caveats"] = M{"lang": "caveats/v1", "not_before": b["iat"], "expires": "2026-01-01T00:01:00Z"}
		})
	})
	neg("G22", "Stale revocation evidence refuses.", "PG1", "revocation_unavailable", "grant", func(v *Vector) { v.Fixture["revocation"].(M)["issued_at"] = "2025-12-31T23:59:59Z" })
	neg("G23", "Revoked subject key refuses.", "PG1", "revoked", "grant", func(v *Vector) { v.Fixture["revocation"].(M)["revoked_keys"] = []any{keys[2].ID} })
	neg("G24", "Unknown caveat language refuses.", "PG3", "envelope_malformed", "grant", func(v *Vector) {
		link(v, 0, 1, func(b M) { b["caveats"] = M{"lang": "rules/v1", "not_before": b["iat"], "expires": b["exp"]} })
	})
	neg("G25", "Roles are not v0 key subjects.", "PG1", "envelope_malformed", "grant", func(v *Vector) { link(v, 0, 1, func(b M) { b["subject"] = "role:developer" }) })
	neg("G26", "Repeated chain records refuse.", "PG1", "grant_chain_malformed", "grant", func(v *Vector) { a := v.Input["chain"].([]any); a[1] = a[0] })
	neg("G27", "Prefix does not match its bare parent.", "PG1", "grant_not_authorized", "grant", func(v *Vector) { v.Fixture["request"].(M)["target"] = target("team") })
	neg("G28", "Future watermark cannot bypass start.", "PG1", "not_yet_valid", "grant", func(v *Vector) { v.Fixture["watermark"] = "2025-12-31T23:59:59Z" })
	// Operator cases bind an independent protected target/epoch/argument fixture.
	neg("O01", "Consumer audience is exact.", "PO1", "audience_mismatch", "operator", func(v *Vector) { v.Fixture["audience"] = "service-b" })
	neg("O02", "Changed arguments refuse despite a valid signature.", "PO1", "act_binding_mismatch", "operator", func(v *Vector) { v.Fixture["binding"].(M)["arguments"].(M)["mode"] = "ephemeral" })
	neg("O03", "Consumed action id refuses without a second plan.", "PO1", "act_replay", "operator", func(v *Vector) { v.Fixture["used_actions"] = []any{body(*v)["action_id"]} })
	neg("O04", "Wrong epoch refuses.", "PO1", "act_binding_mismatch", "operator", func(v *Vector) { v.Fixture["binding"].(M)["epoch"] = "epoch-2" })
	neg("O05", "Unknown operator device refuses.", "PO1", "signer_unknown", "operator", func(v *Vector) { v.Fixture["known_keys"] = []any{keys[1].ID} })
	neg("O06", "Stale act refuses.", "PO1", "expired", "operator", func(v *Vector) { v.Fixture["now"] = "2026-01-01T00:02:00Z" })
	neg("O07", "Future act refuses.", "PO1", "not_yet_valid", "operator", func(v *Vector) { v.Fixture["now"] = "2025-12-31T23:59:59Z" })
	neg("O08", "Widening without signed confirmation refuses.", "PO3", "act_confirmation_required", "operator", func(v *Vector) { widen(v, false) })
	neg("O09", "Self-asserted confirmation cannot replace presence evidence.", "PO3", "act_presence_required", "operator", func(v *Vector) { widen(v, true); v.Fixture["signer_facts"].(M)["presence"] = false })
	neg("O10", "Replay journal outage refuses.", "PO1", "replay_unavailable", "operator", func(v *Vector) { v.Fixture["replay_available"] = false })
	neg("O11", "Wrong owner refuses.", "PO1", "act_binding_mismatch", "operator", func(v *Vector) { v.Fixture["binding"].(M)["owner"] = "owner-b" })
	neg("O12", "Wrong registration target refuses.", "PO1", "act_binding_mismatch", "operator", func(v *Vector) { v.Fixture["binding"].(M)["target"] = M{"kind": "registration", "id": 2} })
	neg("O13", "Revocation outage maps to unavailable.", "PO1", "revocation_unavailable", "operator", func(v *Vector) { v.Fixture["revocation"].(M)["complete"] = false })
	neg("O14", "Revoked device refuses.", "PO1", "revoked", "operator", func(v *Vector) { v.Fixture["revocation"].(M)["revoked_keys"] = []any{keys[6].ID} })
	neg("O15", "Operator record has its own 8192-byte bound.", "PO1", "envelope_too_large", "operator", func(v *Vector) {
		v.Input["envelope"] = b64(append(unb64(v.Input["envelope"].(string)), bytes.Repeat([]byte{' '}, 8192)...))
	})
	neg("E32", "Malformed P-256 compressed point refuses.", "PO1", "envelope_signature_invalid", "operator", func(v *Vector) {
		*v = base("operator", 6)
		raw := make([]byte, 33)
		raw[0] = 2
		for i := 1; i < 33; i++ {
			raw[i] = 255
		}
		bad := "p256:" + b64(raw)
		v.Fixture["known_keys"] = []any{bad}
		edit(v, func(e M) {
			// Operator signer key is the protected known pin, not a body author field.
			e["signatures"].([]any)[0].(map[string]any)["key"] = bad
			e["id"] = digest(append([]byte("swarma-waggle operator-act/1\n"), canonical(e["body"])...))
		})
	})
	neg("E33", "Small-order Ed25519 public key refuses.", "PE1", "envelope_signature_invalid", "envelope", func(v *Vector) {
		bad := "ed25519:" + b64(make([]byte, 32))
		v.Fixture["known_keys"] = []any{bad}
		edit(v, func(e M) {
			e["body"].(map[string]any)["author"] = bad
			e["signatures"].([]any)[0].(map[string]any)["key"] = bad
			e["id"] = digest(append([]byte("swarma-msg/2\n"), canonical(e["body"])...))
		})
	})
	neg("E34", "Noncanonical point R refuses.", "PE1", "envelope_signature_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) {
			sig := e["signatures"].([]any)[0].(map[string]any)
			raw := unb64(sig["sig"].(string))
			for i := 0; i < 32; i++ {
				raw[i] = 255
			}
			sig["sig"] = b64(raw)
		})
	})
	neg("E35", "P-256 zero scalar refuses.", "PO1", "envelope_signature_invalid", "operator", func(v *Vector) {
		*v = base("operator", 6)
		edit(v, func(e M) {
			sig := e["signatures"].([]any)[0].(map[string]any)
			raw := unb64(sig["sig"].(string))
			for i := 0; i < 32; i++ {
				raw[i] = 0
			}
			sig["sig"] = b64(raw)
		})
	})
	neg("E36", "Nonzero base64 trailing bits refuse before crypto.", "PE1", "envelope_malformed", "envelope", func(v *Vector) {
		edit(v, func(e M) {
			sig := e["signatures"].([]any)[0].(map[string]any)
			raw := sig["sig"].(string)
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			j := strings.IndexByte(alphabet, raw[len(raw)-1])
			sig["sig"] = raw[:len(raw)-1] + string(alphabet[j+1])
		})
	})
	neg("E37", "Expired provider authority refuses.", "PE1", "time_unavailable", "envelope", func(v *Vector) { v.Fixture["time"].(M)["authority_until"] = v.Fixture["now"] })
	neg("E38", "Invalid nested schema refuses.", "PE1", "envelope_malformed", "envelope", func(v *Vector) { resign(v, 0, func(b M) { b["target"].(map[string]any)["extra"] = true }) })
	neg("E39", "120-second act limit is inclusive; 121 refuses.", "PO1", "envelope_malformed", "operator", func(v *Vector) { resign(v, 0, func(b M) { b["exp"] = "2026-01-01T00:02:01Z" }) })
	neg("E40", "A bad extra signature is never silently dropped.", "PE5", "envelope_signature_invalid", "envelope", func(v *Vector) { extraSignature(v, true) })
	neg("G29", "Leaf signature cannot be skipped.", "PG1", "envelope_signature_invalid", "grant", func(v *Vector) {
		a := v.Input["chain"].([]any)
		e := decode(a[0].(string))
		sig := e["signatures"].([]any)[0].(map[string]any)
		raw := unb64(sig["sig"].(string))
		raw[6] ^= 1
		sig["sig"] = b64(raw)
		a[0] = wire(e)
	})
	neg("G30", "Dropping a parent's earlier expiry caveat widens authority.", "PG6", "grant_not_narrowing", "grant", func(v *Vector) { rootCaveat(v, "2026-01-01T00:00:00Z", "2026-01-01T00:01:30Z") })
	neg("G31", "Dropping a parent's later start caveat widens authority.", "PG6", "grant_not_narrowing", "grant", func(v *Vector) { rootCaveat(v, "2026-01-01T00:00:30Z", "2026-01-02T00:00:00Z") })
	neg("G32", "Audience change in any link refuses.", "PG1", "audience_mismatch", "grant", func(v *Vector) { link(v, 0, 1, func(b M) { b["aud"] = "service-b" }) })
	neg("G33", "Unavailable clock also refuses grants.", "PG1", "time_unavailable", "grant", func(v *Vector) { v.Fixture["time"].(M)["fresh"] = false })
	neg("G34", "Snapshot without rollback evidence refuses.", "PG1", "revocation_unavailable", "grant", func(v *Vector) { v.Fixture["revocation"].(M)["rollback_safe"] = false })
	neg("G35", "Future snapshot refuses.", "PG1", "revocation_unavailable", "grant", func(v *Vector) { v.Fixture["revocation"].(M)["issued_at"] = "2026-01-01T00:01:01Z" })
	neg("G36", "Unknown request action refuses.", "PG1", "action_unregistered", "grant", func(v *Vector) { v.Fixture["request"].(M)["action"] = "unknown.action" })
	neg("G37", "Registered action with incompatible target kind refuses.", "PG2", "grant_target_invalid", "grant", func(v *Vector) {
		v.Input["chain"] = chain(1)
		link(v, 0, 0, func(b M) { b["targets"] = []any{M{"kind": "station", "id": "team/*"}} })
	})
	neg("O16", "Unknown act operation has no guessed authority.", "PO1", "act_operation_unknown", "operator", func(v *Vector) { resign(v, 0, func(b M) { b["operation"] = "unknown.operation" }) })
	neg("O17", "Provider current-presence facts cannot be stale for widening.", "PO3", "act_presence_required", "operator", func(v *Vector) { widen(v, true); v.Fixture["signer_facts"].(M)["presence_current"] = false })

	neg("E41", "Mixed-order Ed25519 public key refuses.", "PE1", "envelope_signature_invalid", "envelope", func(v *Vector) {
		// Standard base point plus the order-four point encoded as 32 zero bytes.
		bad := "ed25519:UlLMCn8ggTO2IKy9RTfroqQSO_CowuT5gMOzG7aXZeo"
		v.Fixture["known_keys"] = []any{bad}
		edit(v, func(e M) {
			e["body"].(map[string]any)["author"] = bad
			e["signatures"].([]any)[0].(map[string]any)["key"] = bad
			e["id"] = digest(append([]byte("swarma-msg/2\n"), canonical(e["body"])...))
		})
	})
	neg("O18", "Unavailable operator key policy refuses as unavailable evidence.", "PO1", "signer_unavailable", "operator", func(v *Vector) { v.Fixture["known_keys"] = nil })

	addendumVectors()

	// Positive controls prohibit an implementation that simply rejects everything.
	add("PE1", "Valid Ed25519 message bytes authenticate; authority is separate.", "", "accept", base("envelope", 0))
	add("PE2", "A distinct attested Ed25519 agent key authenticates its message.", "", "accept", base("envelope", 1))
	v := base("envelope", 0)
	v.Input["envelope"] = b64(append([]byte(" \n"), unb64(v.Input["envelope"].(string))...))
	add("PE3", "Noncanonical wire whitespace canonicalizes without changing preimages.", "", "accept", v)
	v = base("envelope", 0)
	resign(&v, 0, func(b M) { b["arguments"] = M{"text": "<>&/é", "sequence": []any{2, 1}} })
	add("PE4", "CCJ preserves Unicode, minimal escapes and array order.", "", "accept", v)
	add("PG1", "Two-link chain authorizes exact correlated credential tuple.", "", "accept", base("grant", 0))
	v = base("grant", 0)
	v.Input["chain"] = chain(1)
	v.Fixture["request"].(M)["key"] = keys[1].ID
	add("PG2", "Pinned single-link root is a valid grant.", "", "accept", v)
	v = base("grant", 0)
	link(&v, 0, 1, func(b M) { b["caveats"] = M{"lang": "caveats/v1", "not_before": b["iat"], "expires": b["exp"]} })
	add("PG3", "Time-only caveat inside grant interval authorizes.", "", "accept", v)
	v = base("grant", 0)
	v.Input["chain"] = chain(4)
	v.Fixture["request"].(M)["key"] = keys[4].ID
	add("PG4", "Four-link chain checks every decreasing edge including leaf.", "", "accept", v)
	v = base("grant", 0)
	link(&v, 0, 1, func(b M) { b["targets"] = []any{target("team/member")} })
	add("PG5", "Exact child target attenuates a prefix parent.", "", "accept", v)
	add("PO1", "Narrowing persistent revoke permits confirmed=false with valid pin.", "", "accept", base("operator", 0))
	v = base("operator", 6)
	resign(&v, 6, func(b M) { b["confirmed"] = true })
	add("PO2", "A confirmed P-256 narrowing act remains narrowing.", "", "accept", v)
	v = base("operator", 0)
	widen(&v, true)
	add("PO3", "Widening needs both exact-content assertion and qualified provider.", "", "accept", v)
	v = base("envelope", 0)
	extraSignature(&v, false)
	add("PE5", "Two distinct valid roles sign the same body.", "", "accept", v)
	v = base("envelope", 0)
	raw := unb64(v.Input["envelope"].(string))
	v.Input["envelope"] = b64(append(raw, bytes.Repeat([]byte{' '}, 65536-len(raw))...))
	add("PE6", "Exactly 65536 received bytes accept.", "", "accept", v)
	v = base("operator", 0)
	raw = unb64(v.Input["envelope"].(string))
	v.Input["envelope"] = b64(append(raw, bytes.Repeat([]byte{' '}, 8192-len(raw))...))
	add("PO4", "Exactly 8192 received operator bytes accept before embedding.", "", "accept", v)
	v = base("grant", 0)
	rootCaveat(&v, "2026-01-01T00:00:00Z", "2026-01-01T00:01:30Z")
	link(&v, 0, 1, func(b M) {
		b["caveats"] = M{"lang": "caveats/v1", "not_before": "2026-01-01T00:00:30Z", "expires": "2026-01-01T00:01:20Z"}
	})
	add("PG6", "Child effective caveat interval narrows parent caveat.", "", "accept", v)
	v = base("grant", 0)
	v.Fixture["revocation"].(M)["issued_at"] = "2026-01-01T00:00:00Z"
	add("PG7", "Snapshot age of exactly 60 seconds is within the bound.", "", "accept", v)

	files := map[string][]byte{}
	reworkVectors()
	typeSweep()
	attestationVectors()
	seeds, pubs := M{}, M{}
	for i, k := range keys {
		name := fmt.Sprintf("test-%d", i)
		seeds[name] = hex.EncodeToString(k.Seed)
		pubs[name] = k.ID
	}
	put := func(path string, v any) {
		b, e := json.MarshalIndent(v, "", "  ")
		must(e)
		files[path] = append(b, '\n')
	}
	put("keys/seeds.json", M{"warning": "PUBLIC TEST-ONLY SEEDS; never deploy", "seeds": seeds})
	put("keys/public-keys.json", pubs)
	for _, v := range cases {
		dir := "0-negative"
		if v.Expected["code"] == "accept" {
			dir = "1-positive"
		}
		put("swarm-envelope-2/"+dir+"/"+v.ID+".json", v)
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	failures := 0
	for _, p := range paths {
		dest := filepath.Join(*out, p)
		if *check {
			got, e := os.ReadFile(dest)
			if e != nil || !bytes.Equal(got, files[p]) {
				fmt.Fprintln(os.Stderr, "byte mismatch:", p)
				failures++
			}
		} else {
			must(os.MkdirAll(filepath.Dir(dest), 0755))
			must(os.WriteFile(dest, files[p], 0644))
		}
	}
	if *check {
		for _, root := range []string{"swarm-envelope-2", "keys"} {
			must(filepath.WalkDir(filepath.Join(*out, root), func(p string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if !d.IsDir() && strings.HasSuffix(p, ".json") {
					rel, e := filepath.Rel(*out, p)
					if e != nil {
						return e
					}
					if _, ok := files[rel]; !ok {
						fmt.Fprintln(os.Stderr, "unexpected vector:", rel)
						failures++
					}
				}
				return nil
			}))
		}
	}
	if failures > 0 {
		os.Exit(1)
	}
	fmt.Printf("%d vectors (%d files), check=%v\n", len(cases), len(files), *check)
}
func widen(v *Vector, confirmed bool) {
	v.Fixture["binding"].(M)["operation"] = "grant.issue"
	v.Fixture["binding"].(M)["target"] = M{"kind": "account", "id": "account-1"}
	v.Fixture["binding"].(M)["arguments"] = M{"account": "account-1"}
	resign(v, 0, func(b M) {
		b["operation"] = "grant.issue"
		b["target"] = M{"kind": "account", "id": "account-1"}
		b["arguments_digest"] = digest(canonical(v.Fixture["binding"].(M)["arguments"]))
		b["confirmed"] = confirmed
	})
}

func rootCaveat(v *Vector, start, end string) {
	link(v, 1, 0, func(b M) { b["caveats"] = M{"lang": "caveats/v1", "not_before": start, "expires": end} })
	parent := decode(v.Input["chain"].([]any)[1].(string))["id"]
	link(v, 0, 1, func(b M) { b["parent"] = parent })
}
func extraSignature(v *Vector, bad bool) {
	b := body(*v)
	p := sigPre(b, "approver", keys[6].ID, "message/1")
	sig := sign(keys[6], p)
	if bad {
		sig[4] ^= 1
	}
	edit(v, func(e M) {
		e["signatures"] = append(e["signatures"].([]any), M{"role": "approver", "key": keys[6].ID, "sig": b64(sig)})
	})
}

// Boundary controls prove the message signer checks bytes and codec limits only.
func signerVector(raw []byte) Vector {
	return Vector{Mode: "signer", Input: M{"preimage": b64(raw)}, Fixture: M{}}
}
func tagged(tag string, payload []byte) []byte { return append([]byte(tag+"\n"), payload...) }
func signerSized(n int) []byte {
	payload := M{"chunks": []any{"", strings.Repeat("x", 8192), strings.Repeat("x", 8192)}}
	initial := tagged("swarma-msg/2", canonical(payload))
	payload["chunks"].([]any)[0] = strings.Repeat("x", n-len(initial))
	result := tagged("swarma-msg/2", canonical(payload))
	if len(result) != n {
		panic("wrong preimage boundary")
	}
	return result
}
func messageSized(n int) Vector {
	v := base("envelope", 0)
	b := body(v)
	b["arguments"] = M{"chunks": []any{"", strings.Repeat("x", 8192), strings.Repeat("x", 8192)}}
	pre := sigPre(b, "author", keys[0].ID, "message/1")
	b["arguments"].(M)["chunks"].([]any)[0] = strings.Repeat("x", n-len(pre))
	if len(sigPre(b, "author", keys[0].ID, "message/1")) != n {
		panic("wrong message boundary")
	}
	v.Input["envelope"] = wire(envelope(b, keys[0], "author"))
	return v
}
func domainVector(expected, source string, payload M) Vector {
	bytes := canonical(payload)
	return Vector{Mode: "domain", Input: M{"preimage": b64(tagged(expected, bytes)), "key": keys[0].ID, "sig": b64(sign(keys[0], tagged(source, bytes)))}, Fixture: M{"expected_tag": expected}}
}
func agentEvidence(v *Vector, i int) M { return v.Fixture["agent_evidence"].(M)[keys[i].ID].(M) }
func addendumVectors() {
	// Each ordered pair isolates domain separation: id/body and target tag are valid.
	tags := []string{"swarma-msg/2", "swarma-waggle grant/1", "swarma-waggle operator-act/1", "swarma-registrar registration/1", "swarma-registrar enrollment/1", "swarma-credential-broker grant/1", "swarma-credential-broker revocation/1"}
	payload := M{"version": "swarm-envelope/2", "role": "author", "key": keys[0].ID, "body": common("message/1")}
	number := 0
	for i, expected := range tags {
		for _, source := range tags {
			if source == expected {
				continue
			}
			number++
			v := domainVector(expected, source, payload)
			add(fmt.Sprintf("D%02d", number), "A signature under "+source+" does not verify under "+expected+".", fmt.Sprintf("PD%d", i+1), "envelope_signature_invalid", v)
		}
	}
	v := domainVector(tags[0], tags[0], payload)
	altered := decode(b64(canonical(payload)))
	altered["role"] = "approver"
	v.Input["preimage"] = b64(tagged(tags[0], canonical(altered)))
	add("D43", "Role is cryptographically bound even when one tag covers all message roles.", "PD1", "envelope_signature_invalid", v)
	v = domainVector(tags[0], tags[0], payload)
	altered = decode(b64(canonical(payload)))
	altered["body"].(map[string]any)["type"] = "grant/1"
	v.Input["preimage"] = b64(tagged(tags[0], canonical(altered)))
	add("D44", "Body type is cryptographically bound independently of schema refusal.", "PD1", "envelope_signature_invalid", v)
	for i, a := range []struct{ tag, code string }{{"swarma-msg/2 ", "domain_mismatch"}, {"Swarma-msg/2", "domain_mismatch"}, {"swarma-msg/2\r", "domain_tag_malformed"}} {
		v = domainVector(tags[0], tags[0], payload)
		v.Input["preimage"] = b64(tagged(a.tag, canonical(payload)))
		add(fmt.Sprintf("D%d", 45+i), "A received tag is compared exactly; case, space or CR is not normalized.", "PD1", a.code, v)
	}
	// Known non-message domains and one unregistered future-service sentinel.
	for i, tag := range append(append([]string{}, tags[1:]...), "unregistered/1") {
		add(fmt.Sprintf("S%02d", i+1), "Message signer refuses non-message or unpublished service domains: "+tag+".", "PS1", "signer_domain_refused", signerVector(tagged(tag, []byte(`{}`))))
	}
	bad := []struct {
		id, claim, code string
		raw             []byte
	}{
		{"S08", "Trailing space is not stripped from a message tag.", "signer_domain_refused", tagged("swarma-msg/2 ", []byte(`{}`))},
		{"S09", "Tag case is not folded.", "signer_domain_refused", tagged("Swarma-msg/2", []byte(`{}`))},
		{"S10", "CR is a forbidden tag control byte.", "signer_tag_malformed", tagged("swarma-msg/2\r", []byte(`{}`))},
		{"S11", "A longer tag sharing the message prefix is not a member.", "signer_domain_refused", tagged("swarma-msg/20", []byte(`{}`))},
		{"S12", "A tag longer than 96 bytes refuses.", "signer_tag_malformed", tagged(strings.Repeat("x", 97), []byte(`{}`))},
		{"S13", "DEL is a forbidden tag byte.", "signer_tag_malformed", tagged("swarma-msg/2\x7f", []byte(`{}`))},
		{"S14", "Non-ASCII tag bytes refuse.", "signer_tag_malformed", tagged("swarma-msg/2\u00e9", []byte(`{}`))},
		{"S15", "A missing LF delimiter refuses.", "signer_tag_malformed", []byte("swarma-msg/2{}")},
		{"S16", "A signer requires canonical JSON, not just equivalent JSON.", "signer_payload_invalid", tagged(tags[0], []byte(` {}`))},
		{"S17", "Unsorted object keys refuse signer canonicality.", "signer_payload_invalid", tagged(tags[0], []byte(`{"b":1,"a":2}`))},
		{"S18", "A trailing newline is not signed CCJ-1.", "signer_payload_invalid", tagged(tags[0], []byte("{}\n"))},
		{"S19", "Duplicate JSON members refuse signer canonicality.", "signer_payload_invalid", tagged(tags[0], []byte(`{"a":1,"a":2}`))},
		{"S20", "Floating-point tokens refuse signer canonicality.", "signer_payload_invalid", tagged(tags[0], []byte(`{"a":1.0}`))},
		{"S21", "A canonical preimage one byte above 24576 refuses before signing.", "signer_preimage_too_large", signerSized(24577)},
		{"S22", "A canonical remainder of depth 13 refuses.", "signer_payload_invalid", tagged(tags[0], []byte(strings.Repeat("[", 13)+`0`+strings.Repeat("]", 13)))},
		{"S23", "BOM is not canonical UTF-8 JSON.", "signer_payload_invalid", tagged(tags[0], append([]byte{239, 187, 191}, []byte(`{}`)...))},
		{"S24", "Invalid UTF-8 is refused by the signer codec.", "signer_payload_invalid", tagged(tags[0], []byte{255})},
		{"S25", "Redundant JSON escaping refuses signer canonicality.", "signer_payload_invalid", tagged(tags[0], []byte(`{"a":"\u0061"}`))},
		{"S26", "Empty signed remainder refuses.", "signer_payload_invalid", tagged(tags[0], nil)},
	}
	for _, a := range bad {
		pair := "PS1"
		if a.id == "S21" {
			pair = "PS2"
		}
		if a.id == "S22" {
			pair = "PS3"
		}
		add(a.id, a.claim, pair, a.code, signerVector(a.raw))
	}
	neg("E42", "Ed25519 cannot produce an operator-device act.", "PO1", "signature_profile_invalid", "operator", func(v *Vector) { v.Input["envelope"] = wire(envelope(body(*v), keys[0], "approver")) })
	neg("E43", "P-256 cannot count as an agent author key.", "PE1", "signature_profile_invalid", "envelope", func(v *Vector) { *v = base("envelope", 6) })
	neg("E44", "An agent key has no delegate-role profile in this slice.", "PE1", "signature_profile_invalid", "envelope", func(v *Vector) {
		edit(v, func(e M) {
			e["signatures"] = append(e["signatures"].([]any), M{"role": "delegate", "key": keys[1].ID, "sig": b64(sign(keys[1], sigPre(body(*v), "delegate", keys[1].ID, "message/1")))})
		})
	})
	neg("E45", "An otherwise signed message exceeds the signer preimage budget by one byte.", "PE7", "signature_preimage_too_large", "envelope", func(v *Vector) { *v = messageSized(24577) })
	changes := []struct {
		id, claim, code string
		change          func(*Vector)
	}{
		{"K01", "Missing agent evidence is unavailable, not unrevoked.", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture["agent_evidence"].(M), keys[0].ID) }},
		{"K02", "Unavailable attestation evidence refuses.", "key_binding_unavailable", func(v *Vector) { agentEvidence(v, 0)["attestation"] = "unavailable" }},
		{"K03", "Invalid attestation is a definite invalid binding.", "key_binding_invalid", func(v *Vector) { agentEvidence(v, 0)["attestation"] = "invalid" }},
		{"K04", "Revoked attested agent key refuses.", "revoked", func(v *Vector) { agentEvidence(v, 0)["revocation"] = "revoked" }},
		{"K05", "Unavailable key revocation evidence refuses.", "key_binding_unavailable", func(v *Vector) { agentEvidence(v, 0)["revocation"] = "unavailable" }},
		{"K06", "A different attested purpose cannot authorize message signing.", "key_binding_invalid", func(v *Vector) { agentEvidence(v, 0)["purpose"] = "git-signing" }},
		{"K07", "Attested bytes must derive the exact declared key id.", "key_binding_invalid", func(v *Vector) { agentEvidence(v, 0)["public_bytes"] = b64(keys[1].Ed.Public().(ed25519.PublicKey)) }},
		{"K08", "Generation mismatch cannot authorize a recycled principal.", "key_binding_invalid", func(v *Vector) {
			agentEvidence(v, 0)["binding"].(M)["generation"] = "generation-old"
			v.Fixture["agent_expected"].(M)[keys[0].ID] = M{"owner": "owner-a", "path": "message/agent-0", "generation": "generation-0", "registration_number": 1, "epoch": "epoch-1"}
		}},
		{"K09", "Attestation validity is exclusive at expiry.", "key_binding_invalid", func(v *Vector) { agentEvidence(v, 0)["not_after"] = v.Fixture["now"] }},
		{"K10", "A future attestation refuses at the start boundary.", "key_binding_invalid", func(v *Vector) { agentEvidence(v, 0)["not_before"] = "2026-01-01T00:01:01Z" }},
		{"K11", "Protected owner binding cannot be replaced.", "key_binding_invalid", func(v *Vector) {
			v.Fixture["agent_expected"].(M)[keys[0].ID] = M{"owner": "owner-b", "path": "message/agent-0", "generation": "generation-0", "registration_number": 1, "epoch": "epoch-1"}
		}},
		{"K12", "Protected derivation path cannot be replaced.", "key_binding_invalid", func(v *Vector) {
			v.Fixture["agent_expected"].(M)[keys[0].ID] = M{"owner": "owner-a", "path": "message/other", "generation": "generation-0", "registration_number": 1, "epoch": "epoch-1"}
		}},
		{"K13", "Protected epoch cannot be replaced.", "key_binding_invalid", func(v *Vector) {
			v.Fixture["agent_expected"].(M)[keys[0].ID] = M{"owner": "owner-a", "path": "message/agent-0", "generation": "generation-0", "registration_number": 1, "epoch": "epoch-2"}
		}},
		{"K14", "Protected registration number cannot be replaced.", "key_binding_invalid", func(v *Vector) {
			v.Fixture["agent_expected"].(M)[keys[0].ID] = M{"owner": "owner-a", "path": "message/agent-0", "generation": "generation-0", "registration_number": 2, "epoch": "epoch-1"}
		}},
		{"K15", "An operator-class attestation cannot relabel an Ed25519 agent key.", "key_binding_invalid", func(v *Vector) { agentEvidence(v, 0)["class"] = "operator" }},
		{"K16", "An inactive generation is not current identity authority.", "key_binding_invalid", func(v *Vector) { agentEvidence(v, 0)["active"] = false }},
		{"K17", "Missing protected expected generation binding refuses.", "key_binding_unavailable", func(v *Vector) { delete(v.Fixture["agent_expected"].(M), keys[0].ID) }},
		{"K18", "Attested key id must equal the message author id.", "key_binding_invalid", func(v *Vector) { agentEvidence(v, 0)["key"] = keys[1].ID }},
	}
	for _, a := range changes {
		neg(a.id, a.claim, "PE1", a.code, "envelope", a.change)
	}
	neg("K19", "Grant leaf subject needs current attested agent binding.", "PG1", "key_binding_unavailable", "grant", func(v *Vector) { delete(v.Fixture["agent_evidence"].(M), keys[2].ID) })
	neg("K20", "Delegated agent grant issuer also needs current binding.", "PG1", "key_binding_unavailable", "grant", func(v *Vector) { delete(v.Fixture["agent_evidence"].(M), keys[1].ID) })
	for i, tag := range tags {
		add(fmt.Sprintf("PD%d", i+1), "The exact configured tag verifies its own signature without implying consumer admission: "+tag+".", "", "accept", domainVector(tag, tag, payload))
	}
	add("PS1", "A canonical object under the exact message tag is signer-admissible, without envelope parsing.", "", "accept", signerVector(tagged(tags[0], []byte(`{}`))))
	add("PS2", "Exactly 24576 canonical preimage bytes are signer-admissible.", "", "accept", signerVector(signerSized(24576)))
	add("PS3", "Exactly 12 container levels are signer-admissible.", "", "accept", signerVector(tagged(tags[0], []byte(strings.Repeat("[", 12)+`0`+strings.Repeat("]", 12)))))
	message := base("envelope", 0)
	add("PS4", "The constructed agent author preimage is directly signer-admissible.", "", "accept", signerVector(sigPre(body(message), "author", keys[0].ID, "message/1")))
	add("PS5", "The signer codec does not interpret a role; the recipient must reject an agent approver.", "", "accept", signerVector(sigPre(body(message), "approver", keys[0].ID, "message/1")))
	add("PE7", "An actual signed agent message at the 24576-byte preimage bound verifies.", "", "accept", messageSized(24576))
	v = base("grant", 0)
	v.Input["chain"] = chain(1)
	root := decode(v.Input["chain"].([]any)[0].(string))["body"].(map[string]any)
	root["issuer"] = keys[6].ID
	v.Input["chain"] = []any{wire(envelope(root, keys[6], "author"))}
	v.Fixture["root"] = keys[6].ID
	v.Fixture["request"].(M)["key"] = keys[1].ID
	add("PG8", "A pinned P-256 authority root may issue a grant to an attested Ed25519 subject.", "", "accept", v)

}

// Keep only relevant caller evidence; never fill a deliberately missing record.
func pruneAgentEvidence(v *Vector) {
	records, ok := v.Fixture["agent_evidence"].(M)
	if !ok {
		return
	}
	needed := map[string]bool{}
	collect := func(raw string, grant bool) {
		var e M
		if err := json.Unmarshal(unb64(raw), &e); err != nil {
			return
		}
		b, ok := e["body"].(map[string]any)
		if !ok {
			return
		}
		fields := []string{"author"}
		if grant {
			fields = []string{"issuer", "subject"}
		}
		for _, field := range fields {
			key, ok := b[field].(string)
			if ok && !(grant && key == v.Fixture["root"]) {
				needed[key] = true
			}
		}
	}
	if v.Mode == "grant" {
		for _, raw := range v.Input["chain"].([]any) {
			collect(raw.(string), true)
		}
	} else if raw, ok := v.Input["envelope"].(string); ok {
		collect(raw, false)
	}
	expected, _ := v.Fixture["agent_expected"].(M)
	for key := range records {
		if !needed[key] {
			delete(records, key)
		}
	}
	for key := range expected {
		if !needed[key] {
			delete(expected, key)
		}
	}
}

// Regressions isolate the review classes before the systematic wrong-type family.
func reworkVectors() {
	neg("R01", "Array target.kind refuses structurally before hashing an enum.", "PE1", "envelope_malformed", "envelope", func(v *Vector) {
		edit(v, func(e M) { e["body"].(map[string]any)["target"].(map[string]any)["kind"] = []any{} })
	})
	neg("R02", "Array request.action refuses at G1 without a plan or a hash-key exception.", "PG1", "grant_chain_malformed", "grant", func(v *Vector) { v.Fixture["request"].(M)["action"] = []any{} })
	for i, kind := range []string{"registration", "account"} {
		v := base("grant", 0)
		// Re-sign both links and their parent edge; the unsupported target is the only defect.
		for j := 1; j >= 0; j-- {
			link(&v, j, 1-j, func(b M) {
				id := any(1)
				if kind == "account" {
					id = "account-1"
				}
				b["targets"] = []any{M{"kind": kind, "id": id}}
				if j == 0 {
					b["parent"] = decode(v.Input["chain"].([]any)[1].(string))["id"]
				}
			})
		}
		add(fmt.Sprintf("R%02d", 3+i), "Signed two-link grant rejects operator-only "+kind+" targets at E2 before containment.", "PG1", "envelope_malformed", v)
	}
	neg("R05", "Object target.kind refuses structurally without an enum hash exception.", "PE1", "envelope_malformed", "envelope", func(v *Vector) {
		edit(v, func(e M) { e["body"].(map[string]any)["target"].(map[string]any)["kind"] = M{} })
	})
	neg("R06", "Object request.action refuses at G1 before vocabulary membership.", "PG1", "grant_chain_malformed", "grant", func(v *Vector) { v.Fixture["request"].(M)["action"] = M{} })
	neg("R07", "A non-current operator key refuses even a narrowing act.", "PO1", "key_binding_invalid", "operator", func(v *Vector) { v.Fixture["signer_facts"].(M)["current"] = false })
	neg("R08", "A non-current operator key refuses before widening presence checks.", "PO3", "key_binding_invalid", "operator", func(v *Vector) { widen(v, true); v.Fixture["signer_facts"].(M)["current"] = false })
	neg("R09", "An underscore harness needs an explicit versioned broker map, not implicit normalization.", "PG2", "envelope_malformed", "grant", func(v *Vector) {
		v.Input["chain"] = chain(1)
		v.Fixture["request"].(M)["key"] = keys[1].ID
		link(v, 0, 0, func(b M) { b["targets"].([]any)[0].(map[string]any)["harness"] = "claude_code" })
	})
	v := base("envelope", 0)
	extraSignature(&v, false)
	v.Fixture["signer_facts"].(M)["current"] = false
	add("R10", "Optional message approval also refuses a non-current operator key.", "PE5", "key_binding_invalid", v)
	neg("R11", "Missing operator key currency is unavailable even for narrowing.", "PO1", "key_binding_unavailable", "operator", func(v *Vector) { delete(v.Fixture["signer_facts"].(M), "current") })
	neg("R12", "Missing presence-enrollment currency refuses widening without changing key currency.", "PO3", "act_presence_required", "operator", func(v *Vector) { widen(v, true); delete(v.Fixture["signer_facts"].(M), "presence_current") })

	v = base("operator", 0)
	v.Fixture["signer_facts"].(M)["presence_current"] = false
	add("PR1", "Narrowing uses a current pinned key without claiming current presence enrollment or A3.", "", "accept", v)
	v = base("envelope", 0)
	resign(&v, 0, func(b M) { b["arguments"] = M{"unregistered-handler-field": true} })
	add("PR2", "Envelope-only verification authenticates arbitrary argument objects; consumer schema and authorization remain mandatory.", "", "accept", v)
	v = base("grant", 0)
	link(&v, 0, 1, func(b M) { b["caveats"] = M{"lang": "caveats/v1", "not_before": b["iat"], "expires": b["exp"]} })
	add("PR3", "A valid populated caveat provides the positive control for nested schema sweeps.", "", "accept", v)
	v = base("grant", 0)
	for j := 1; j >= 0; j-- {
		link(&v, j, 1-j, func(b M) {
			b["actions"] = []any{"agent.spawn"}
			b["targets"] = []any{M{"kind": "station", "id": "team/*"}}
			if j == 0 {
				b["parent"] = decode(v.Input["chain"].([]any)[1].(string))["id"]
			}
		})
	}
	v.Fixture["request"].(M)["action"] = "agent.spawn"
	v.Fixture["request"].(M)["target"] = M{"kind": "station", "id": "team/member"}
	add("PR4", "A correctly signed station-target chain authorizes agent.spawn alongside the credential control.", "", "accept", v)

}

func jsonKind(x any) string {
	switch x.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "integer"
	}
}
func copyVector(v Vector) Vector {
	b, e := json.Marshal(v)
	must(e)
	var out Vector
	must(json.Unmarshal(b, &out))
	return out
}
func setPath(root any, path []any, value any) {
	for _, p := range path[:len(path)-1] {
		if n, ok := p.(int); ok {
			root = root.([]any)[n]
		} else {
			root = root.(map[string]any)[p.(string)]
		}
	}
	last := path[len(path)-1]
	if n, ok := last.(int); ok {
		root.([]any)[n] = value
	} else {
		root.(map[string]any)[last.(string)] = value
	}
}

// Claims: every closed wire/request field rejects every other JSON type at its
// ordered structural gate. Opaque argument values have no application schema
// here; their object container is covered, their arbitrary JSON children are not.
func typeSweep() {
	n := 0
	for _, control := range []string{"PE1", "PE5", "PR3", "PO1", "PO3"} {
		var src Vector
		for _, c := range cases {
			if c.ID == control {
				src = c
				break
			}
		}
		var record M
		if src.Mode == "grant" {
			record = decode(src.Input["chain"].([]any)[0].(string))
		} else {
			record = decode(src.Input["envelope"].(string))
		}
		var walk func(any, []any, bool)
		walk = func(node any, path []any, request bool) {
			if len(path) > 0 {
				field, _ := path[len(path)-1].(string)
				for _, wrong := range []any{nil, false, 1, "x", []any{}, M{}} {
					if jsonKind(wrong) == jsonKind(node) || (wrong == nil && (field == "parent" || field == "caveats")) {
						continue
					}
					v := copyVector(src)
					if request {
						setPath(v.Fixture["request"], path, wrong)
					} else {
						var e M
						if v.Mode == "grant" {
							e = decode(v.Input["chain"].([]any)[0].(string))
						} else {
							e = decode(v.Input["envelope"].(string))
						}
						setPath(e, path, wrong)
						if v.Mode == "grant" {
							v.Input["chain"].([]any)[0] = wire(e)
						} else {
							v.Input["envelope"] = wire(e)
						}
					}
					n++
					code := "envelope_malformed"
					if request || (src.Mode == "grant" && len(path) == 1 && path[0] == "id") {
						code = "grant_chain_malformed"
					}
					add(fmt.Sprintf("T%04d", n), fmt.Sprintf("Wrong %s type at %s %v (request=%t) refuses at its structural gate.", jsonKind(wrong), control, path, request), control, code, v)
				}
				if field == "arguments" {
					return
				}
			}
			switch value := node.(type) {
			case map[string]any:
				fields := make([]string, 0, len(value))
				for k := range value {
					fields = append(fields, k)
				}
				sort.Strings(fields)
				for _, k := range fields {
					walk(value[k], append(append([]any{}, path...), k), request)
				}
			case []any:
				for i, child := range value {
					walk(child, append(append([]any{}, path...), i), request)
				}
			}
		}
		walk(record, nil, false)
		if src.Mode == "grant" {
			walk(src.Fixture["request"], nil, true)
		}
	}
}

// Caller evidence is not CCJ wire data. These fixtures retain JSON floats so
// integer/boolean/float equality cannot masquerade as a typed principal tuple.
func attestationVectors() {
	for i, mode := range []string{"envelope", "grant"} {
		idx, pair := 0, "PE1"
		if mode == "grant" {
			idx, pair = 2, "PG1"
		}
		v := copyVector(base(mode, 0))
		v.Fixture["agent_expected"].(M)[keys[idx].ID] = nil
		delete(agentEvidence(&v, idx), "binding")
		add(fmt.Sprintf("J%02d", i+1), "Absent protected and attested principal bindings cannot compare equal as null.", pair, "key_binding_unavailable", v)
	}
	neg("J03", "Attested boolean true is not the protected integer registration number 1.", "PE1", "key_binding_invalid", "envelope", func(v *Vector) { *v = copyVector(*v); agentEvidence(v, 0)["binding"].(M)["registration_number"] = true })
	neg("J04", "Null evidence is unavailable, never a dictionary dereference.", "PE1", "key_binding_unavailable", "envelope", func(v *Vector) { v.Fixture["agent_evidence"].(M)[keys[0].ID] = nil })
	neg("J05", "Protected boolean true is not an integer registration binding.", "PE1", "key_binding_invalid", "envelope", func(v *Vector) {
		*v = copyVector(*v)
		v.Fixture["agent_expected"].(M)[keys[0].ID].(M)["registration_number"] = true
	})
	for i, number := range []any{json.RawMessage("1.0"), -1, "1", true} {
		v := copyVector(base("envelope", 0))
		v.Fixture["agent_expected"].(M)[keys[0].ID].(M)["registration_number"] = number
		agentEvidence(&v, 0)["binding"].(M)["registration_number"] = number
		add(fmt.Sprintf("J%02d", 6+i), "Matching invalid registration values do not become a valid typed principal by equality.", "PE1", "key_binding_invalid", v)
	}
	neg("J10", "Two equally incomplete tuples are unavailable, not an authenticated binding.", "PE1", "key_binding_unavailable", "envelope", func(v *Vector) { delete(agentEvidence(v, 0)["binding"].(M), "owner") })
	neg("J11", "Malformed attestation validity is an invalid binding, not an envelope parsing failure.", "PE1", "key_binding_invalid", "envelope", func(v *Vector) { agentEvidence(v, 0)["not_after"] = "not-a-time" })
	neg("J12", "Missing required attestation purpose is unavailable evidence.", "PE1", "key_binding_unavailable", "envelope", func(v *Vector) { delete(agentEvidence(v, 0), "purpose") })
	v := copyVector(base("envelope", 0))
	v.Fixture["agent_expected"].(M)[keys[0].ID].(M)["registration_number"] = int64(9007199254740991)
	agentEvidence(&v, 0)["binding"].(M)["registration_number"] = int64(9007199254740991)
	add("PB1", "The maximum positive safe JSON integer remains a valid registration binding.", "", "accept", v)
	for i, value := range []any{"", strings.Repeat("x", 256), json.RawMessage(`"\ud800"`)} {
		v := copyVector(base("envelope", 0))
		v.Fixture["agent_expected"].(M)[keys[0].ID].(M)["owner"] = value
		agentEvidence(&v, 0)["binding"].(M)["owner"] = value
		add(fmt.Sprintf("J%02d", 13+i), "Matching empty, overlong or invalid UTF-8 principal text cannot authorize a binding.", "PE1", "key_binding_invalid", v)
	}
	v = copyVector(base("envelope", 0))
	for _, name := range []string{"owner", "path", "generation", "epoch"} {
		v.Fixture["agent_expected"].(M)[keys[0].ID].(M)[name] = strings.Repeat("x", 255)
		agentEvidence(&v, 0)["binding"].(M)[name] = strings.Repeat("x", 255)
	}
	add("PB2", "Valid principal text at the inclusive 255-byte interface bound compares without normalization.", "", "accept", v)
	evidenceSweep()
	provenanceMatrix()
}

func deletePath(root M, path []any) {
	for _, p := range path[:len(path)-1] {
		root = root[p.(string)].(M)
	}
	delete(root, path[len(path)-1].(string))
}
func atPath(root M, path []any) any {
	var value any = root
	for _, p := range path {
		value = value.(M)[p.(string)]
	}
	return value
}

// Claims: each required caller evidence/binding field rejects missing, null and
// every other JSON type before comparison, in author, delegated issuer and leaf
// subject intake. Positive controls retain all current, well-typed evidence.
func evidenceSweep() {
	n := 0
	for _, item := range []struct {
		mode, pair, use string
		idx             int
	}{{"envelope", "PE1", "author", 0}, {"grant", "PG1", "issuer", 1}, {"grant", "PG1", "leaf-subject", 2}} {
		src := copyVector(base(item.mode, 0))
		key := keys[item.idx].ID
		paths := [][]any{{"agent_evidence"}, {"agent_expected"}, {"agent_evidence", key}, {"agent_expected", key}}
		record := src.Fixture["agent_evidence"].(M)[key].(M)
		fields := make([]string, 0, len(record))
		for k := range record {
			fields = append(fields, k)
		}
		sort.Strings(fields)
		for _, name := range fields {
			paths = append(paths, []any{"agent_evidence", key, name})
		}
		for _, name := range []string{"owner", "path", "generation", "registration_number", "epoch"} {
			paths = append(paths, []any{"agent_evidence", key, "binding", name}, []any{"agent_expected", key, name})
		}
		for _, path := range paths {
			original := atPath(src.Fixture, path)
			variants := []struct {
				name    string
				value   any
				missing bool
			}{{name: "missing", missing: true}}
			for _, value := range []any{nil, true, 1, "x", []any{}, M{}} {
				if jsonKind(value) != jsonKind(original) {
					variants = append(variants, struct {
						name    string
						value   any
						missing bool
					}{jsonKind(value), value, false})
				}
			}
			if path[len(path)-1] == "registration_number" {
				for _, value := range []string{"1.0", "1.5", "-1", "0", "9007199254740992"} {
					variants = append(variants, struct {
						name    string
						value   any
						missing bool
					}{"invalid-number-" + value, json.RawMessage(value), false})
				}
			}
			for _, a := range variants {
				v := copyVector(src)
				if a.missing {
					deletePath(v.Fixture, path)
				} else {
					setPath(v.Fixture, path, a.value)
				}
				code := "key_binding_invalid"
				if a.missing || a.value == nil {
					code = "key_binding_unavailable"
				}
				n++
				add(fmt.Sprintf("B%04d", n), fmt.Sprintf("Caller %s evidence %v with %s yields an ordered binding refusal without a plan.", item.use, path, a.name), item.pair, code, v)
			}
		}
	}
}

// Generate a complete leaf-first narrowing chain over explicit key vertices.
func vertexChain(vertices []int) []any {
	var out []any
	parent := any(nil)
	for i := 0; i < len(vertices)-1; i++ {
		b := common("grant/1")
		b["nonce"] = b64(bytes.Repeat([]byte{byte(30 + i)}, 16))
		b["issuer"], b["subject"] = keys[vertices[i]].ID, keys[vertices[i+1]].ID
		b["actions"], b["targets"] = []any{"credential.lease"}, []any{target("team/*")}
		b["not_before"], b["expires"] = b["iat"], b["exp"]
		b["depth"], b["parent"], b["caveats"] = 3-i, parent, nil
		e := envelope(b, keys[vertices[i]], "author")
		parent = e["id"]
		out = append([]any{wire(e)}, out...)
	}
	return out
}

// Claims: pin/attestation provenance governs every chain position. Removing the
// required provenance fails closed; algorithm alone never supplies a class.
func provenanceMatrix() {
	n := 0
	for _, c := range []struct {
		name      string
		idx, root int
	}{{"pinned-authority-ed25519", 0, 0}, {"pinned-authority-p256", 6, 6}, {"pinned-operator-p256", 6, 0}, {"attested-agent-ed25519", 3, 0}} {
		for _, position := range []string{"issuer", "subject", "leaf-subject"} {
			vertices := []int{c.root, c.idx, 2}
			if position == "subject" {
				vertices = []int{c.root, 1, c.idx, 2}
			}
			if position == "leaf-subject" {
				vertices = []int{c.root, 1, c.idx}
			}
			v := base("grant", 0)
			v.Input["chain"] = vertexChain(vertices)
			v.Fixture["root"] = keys[c.root].ID
			v.Fixture["request"].(M)["key"] = keys[vertices[len(vertices)-1]].ID
			if c.root == 6 {
				v.Fixture["signer_facts"].(M)["current"] = false
			}
			n++
			pair := fmt.Sprintf("PM%02d", n)
			add(pair, c.name+" in "+position+" position retains protected provenance under a valid narrowing chain.", "", "accept", v)
			valid := copyVector(cases[len(cases)-1])
			v = copyVector(valid)
			switch c.name {
			case "pinned-authority-ed25519", "pinned-authority-p256":
				v.Fixture["root"] = keys[5].ID
				v.Fixture["operator_pins"] = []any{}
			case "pinned-operator-p256":
				v.Fixture["operator_pins"] = []any{}
			case "attested-agent-ed25519":
				delete(v.Fixture["agent_evidence"].(M), keys[c.idx].ID)
			}
			add(fmt.Sprintf("M%02d", n), "Removing protected provenance for "+c.name+" in "+position+" refuses even with valid signatures.", pair, "key_binding_unavailable", v)
			if c.name == "pinned-operator-p256" {
				v = copyVector(valid)
				v.Fixture["signer_facts"].(M)["current"] = false
				add(fmt.Sprintf("M%02d", n+12), "A non-current pinned operator device in "+position+" cannot exercise delegated authority.", pair, "key_binding_invalid", v)
			}
			if c.name == "pinned-operator-p256" {
				v = copyVector(valid)
				v.Fixture["operator_pins"] = []any{}
				t := context()
				r := t["agent_evidence"].(M)[keys[3].ID].(M)
				r["key"] = keys[6].ID
				v.Fixture["agent_evidence"].(M)[keys[6].ID] = r
				v.Fixture["agent_expected"].(M)[keys[6].ID] = t["agent_expected"].(M)[keys[3].ID]
				add(fmt.Sprintf("M%02d", n+18), "P-256 in "+position+" cannot become an agent by a contradictory attestation projection.", pair, "key_binding_invalid", v)
			}
			if c.name == "attested-agent-ed25519" {
				v = copyVector(valid)
				v.Fixture["operator_pins"] = []any{keys[3].ID}
				add(fmt.Sprintf("M%02d", n+12), "Ed25519 in "+position+" cannot become an operator device by a contradictory pin.", pair, "key_binding_invalid", v)
			}
		}
	}
}
