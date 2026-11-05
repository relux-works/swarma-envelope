package verifier_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

// All keys in these fixtures are deterministic public TEST ONLY software keys.
func gr2Body() map[string]any {
	k, key := muSeedKey(7)
	_, root := muSeedKey(0)
	return map[string]any{"type": "attestation/1", "issuer": root,
		"subject":   map[string]any{"algorithm": "Ed25519", "key_id": key, "public_bytes": base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))},
		"key_class": "revocation-publisher", "purpose": "grant-revocation", "roles": []any{"author"}, "actions": []any{"revocation.sign"},
		"iat": "2025-06-01T00:00:00Z", "exp": "2026-06-01T00:00:00Z", "binding": map[string]any{"profile": "grant-revocation-2", "domain": root}}
}
func gr2Att(t *testing.T, b map[string]any, signer int) []byte {
	t.Helper()
	k, key := muSeedKey(signer)
	b["issuer"] = key
	return muSign(t, "attestation/1", b, k, key)
}
func gr2Snapshot(t *testing.T, issued string, entries []any) []byte {
	t.Helper()
	k, key := muSeedKey(7)
	return muSign(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": key, "issued_at": issued, "complete": true, "entries": entries}, k, key)
}
func gr2Vector(t *testing.T, att, snap []byte) vector {
	t.Helper()
	v := load(t, "../vectors/swarm-envelope-2/1-positive/PG1.json")
	_, agent := muSeedKey(2)
	grant := muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	v.Input["chain"] = []any{base64.RawURLEncoding.EncodeToString(grant)}
	v.Fixture["request"] = map[string]any{"key": agent, "action": "work.assign", "target": muProduct}
	_, key := muSeedKey(7)
	v.Fixture["grant_revocation_publisher"] = base64.RawURLEncoding.EncodeToString(att)
	// Keep the root's fresh snapshot too: invalid publisher facts must never
	// silently fall back to it. The valid publisher has its own fresh snapshot.
	v.Fixture["revocations"].(map[string]any)[key] = map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": base64.RawURLEncoding.EncodeToString(snap)}
	return v
}
func gr2Good(t *testing.T) vector {
	return gr2Vector(t, gr2Att(t, gr2Body(), 0), gr2Snapshot(t, "2026-01-01T00:00:30Z", []any{}))
}
func gr2Want(t *testing.T, v vector, want string) {
	t.Helper()
	got := derive(t, v)
	if got.Code != want || (want != "accept" && len(got.Plan) != 0) || (want == "accept" && got.Plan["use"] != "until_expiry") {
		t.Fatalf("got %+v, want %s (refusals carry no plan)", got, want)
	}
}

// Claim: an owner-root-appointed Ed25519 profile-2 publisher with an ordinary
// Ed25519-signed fresh snapshot authorizes a depth-zero grant and returns its use.
func TestGrantRevocation2Positive(t *testing.T) { gr2Want(t, gr2Good(t), "accept") }

// Claim: closed profile/algorithm/encoding binding is enforced at G7, with no
// inference or root fallback. The two cross-pairs have otherwise valid keys.
func TestGrantRevocation2Subject(t *testing.T) {
	gr2Want(t, gr2Good(t), "accept")
	for _, name := range []string{"profile1-ed", "profile2-p256", "unknown-profile", "algorithm", "length33", "length31", "padded", "same-length-wrong-bytes", "identity", "small-order", "mixed-order", "off-curve", "noncanonical-point", "malformed-key", "extra-subject", "extra-binding"} {
		t.Run(name, func(t *testing.T) {
			b := gr2Body()
			s := b["subject"].(map[string]any)
			binding := b["binding"].(map[string]any)
			switch name {
			case "profile1-ed":
				binding["profile"] = "grant-revocation-1"
			case "profile2-p256":
				k, id := muP256("publisher")
				s["algorithm"], s["key_id"], s["public_bytes"] = "P-256", id, base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), k.X, k.Y))
			case "unknown-profile":
				binding["profile"] = "grant-revocation-3"
			case "algorithm":
				s["algorithm"] = "ed25519"
			case "length33":
				s["public_bytes"] = base64.RawURLEncoding.EncodeToString(make([]byte, 33))
			case "length31":
				s["public_bytes"] = base64.RawURLEncoding.EncodeToString(make([]byte, 31))
			case "padded":
				s["public_bytes"] = s["public_bytes"].(string) + "="
			case "same-length-wrong-bytes":
				k, _ := muSeedKey(8)
				s["public_bytes"] = base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
			case "identity", "small-order", "mixed-order", "off-curve", "noncanonical-point":
				p := make([]byte, 32)
				if name == "mixed-order" {
					p = append([]byte{0x95}, bytes.Repeat([]byte{0x99}, 31)...)
				}
				if name == "off-curve" {
					p[0] = 2
				}
				if name == "identity" {
					p[0] = 1
				}
				if name == "noncanonical-point" {
					for i := range p {
						p[i] = 255
					}
				}
				enc := base64.RawURLEncoding.EncodeToString(p)
				s["key_id"], s["public_bytes"] = "ed25519:"+enc, enc
			case "malformed-key":
				s["key_id"] = "ed25519:bad"
			case "extra-subject":
				s["extra"] = true
			case "extra-binding":
				binding["extra"] = true
			}
			v := gr2Vector(t, gr2Att(t, b, 0), gr2Snapshot(t, "2026-01-01T00:00:30Z", []any{}))
			if got := gr2Direct(t, v); got != "key_binding_invalid" {
				t.Fatalf("direct binding got %s", got)
			}
			gr2Want(t, v, "revocation_invalid")
		})
	}
}

// Claim: only the pinned owner root appoints a publisher. Every issuer below
// has a valid signature, but lacks appointment authority; malformed scope and
// purpose refuse separately. All cases reach public G7 and return no plan.
func TestGrantRevocation2Appointment(t *testing.T) {
	gr2Want(t, gr2Good(t), "accept")
	for _, role := range []string{"service", "registry", "operator", "commit", "enrollment", "self"} {
		t.Run(role, func(t *testing.T) {
			v := gr2Good(t)
			var issuer string
			switch role {
			case "service":
				issuer = v.Fixture["service_root"].(map[string]any)["key"].(string)
			case "registry":
				issuer = v.Fixture["agent_revocation_root"].(map[string]any)["key"].(string)
			case "operator":
				issuer = v.Fixture["operator_root"].(string)
			case "commit":
				_, issuer = muSeedKey(8)
				v.Fixture["commit_signing_key"] = issuer
			case "enrollment":
				_, issuer = muSeedKey(9)
				v.Fixture["enrollment_publisher"] = issuer
			case "self":
				_, issuer = muSeedKey(7)
			}
			signer := -1
			for i := 0; i < 10; i++ {
				_, id := muSeedKey(i)
				if id == issuer {
					signer = i
					break
				}
			}
			if role == "registry" {
				seed := sha256.Sum256([]byte("waggle public test registry revocation seed"))
				priv := ed25519.NewKeyFromSeed(seed[:])
				id := "ed25519:" + base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
				if id != issuer {
					t.Fatal("registry signer premise")
				}
				b := gr2Body()
				b["issuer"] = issuer
				v.Fixture["grant_revocation_publisher"] = base64.RawURLEncoding.EncodeToString(muSign(t, "attestation/1", b, priv, issuer))
			} else {
				if signer < 0 {
					t.Fatal("missing public test signer for role", role)
				}
				v.Fixture["grant_revocation_publisher"] = base64.RawURLEncoding.EncodeToString(gr2Att(t, gr2Body(), signer))
			}
			gr2Want(t, v, "revocation_invalid")
		})
	}
	for _, name := range []string{"domain", "class", "purpose", "roles", "actions", "agent-attestation", "extra-body"} {
		t.Run(name, func(t *testing.T) {
			b := gr2Body()
			switch name {
			case "domain":
				_, id := muSeedKey(1)
				b["binding"].(map[string]any)["domain"] = id
			case "class":
				b["key_class"] = "agent"
			case "purpose":
				b["purpose"] = "swarma-msg"
			case "roles":
				b["roles"] = []any{"approver"}
			case "actions":
				b["actions"] = []any{"message.sign"}
			case "agent-attestation":
				b["key_class"], b["purpose"], b["actions"] = "agent", "swarma-msg", []any{"message.sign"}
				b["binding"] = map[string]any{"uid": int64(1), "generation": "g", "registration_number": int64(1), "master_epoch": "e", "owner": "o", "path": "p"}
			case "extra-body":
				b["extra"] = true
			}
			v := gr2Vector(t, gr2Att(t, b, 0), gr2Snapshot(t, "2026-01-01T00:00:30Z", []any{}))
			if got := gr2Direct(t, v); got != "key_binding_invalid" {
				t.Fatalf("direct binding got %s", got)
			}
			gr2Want(t, v, "revocation_invalid")
		})
	}
}

// gr2Direct admits a valid Mac agent binding first, then consumes the publisher
// at the direct binding gate. It avoids unrelated legacy-agent or grant-author
// role checks masking a publisher collision.
func gr2Direct(t *testing.T, v vector) string {
	t.Helper()
	k, key := muP256("meta")
	pub := elliptic.MarshalCompressed(elliptic.P256(), k.X, k.Y)
	root := v.Fixture["root"].(string)
	signer := -1
	for i := 0; i < 10; i++ {
		_, id := muSeedKey(i)
		if id == root {
			signer = i
			break
		}
	}
	if signer < 0 {
		t.Fatal("no test root signer")
	}
	att := muMacAttestation(t, key, pub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1)}, signer)
	// Match the issuer to the pinned root as well as the actual signer.
	p, err := record.Parse(att, 65536, 16)
	if err != nil {
		t.Fatal(err)
	}
	body := p.(map[string]any)["body"].(map[string]any)
	body["issuer"] = root
	priv, _ := muSeedKey(signer)
	att = muSign(t, "attestation/1", body, priv, root)
	id := muID(t, att)
	v.Fixture["attestations"].(map[string]any)[id] = base64.RawURLEncoding.EncodeToString(att)
	v.Fixture["active_generations"].(map[string]any)[key] = map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "active": true}
	got, err := verifier.New(context(t, v.Fixture)).VerifyAttestation(key, id, false)
	if err != nil && got != (verifier.Attestation{}) {
		t.Fatal("refusal retained identity", got)
	}
	return code(err)
}

// Claim: all six type-compatible canonical key-role collisions refuse at the
// direct publisher binding gate, after a valid Mac attestation. Ordinary
// distinct roles admit. Four collisions are also reached through Authorize G7;
// grant/service collisions have earlier unrelated public envelope gates.
func TestGrantRevocation2RoleCollisions(t *testing.T) {
	if got := gr2Direct(t, gr2Good(t)); got != "accept" {
		t.Fatal("valid direct control", got)
	}
	for _, name := range []string{"grant", "operator", "service", "registry", "commit", "enrollment"} {
		t.Run(name, func(t *testing.T) {
			v := gr2Good(t)
			_, key := muSeedKey(7)
			switch name {
			case "grant":
				v.Fixture["root"] = key
				b := gr2Body()
				b["binding"].(map[string]any)["domain"] = key
				v.Fixture["grant_revocation_publisher"] = base64.RawURLEncoding.EncodeToString(gr2Att(t, b, 7))
			case "operator":
				v.Fixture["operator_root"] = key
			case "service":
				v.Fixture["service_root"].(map[string]any)["key"] = key
			case "registry":
				v.Fixture["agent_revocation_root"].(map[string]any)["key"] = key
			case "commit":
				v.Fixture["commit_signing_key"] = key
			case "enrollment":
				v.Fixture["enrollment_publisher"] = key
			}
			if got := gr2Direct(t, v); got != "key_binding_invalid" {
				t.Fatalf("direct collision got %s", got)
			}
			if name != "grant" && name != "service" {
				gr2Want(t, v, "revocation_invalid")
			}
		})
	}
}

// Claim: a positive <=366-day window covers min/max(now,W), inclusively at
// start and exclusively at expiry. Boundary controls differ only in the window.
func TestGrantRevocation2Windows(t *testing.T) {
	for _, c := range []struct{ name, start, end, want string }{
		{"366-days", "2025-06-01T00:00:00Z", "2026-06-02T00:00:00Z", "accept"},
		{"367-days", "2025-06-01T00:00:00Z", "2026-06-03T00:00:00Z", "revocation_invalid"},
		{"start-inclusive", "2026-01-01T00:01:00Z", "2026-01-02T00:00:00Z", "accept"},
		{"future-start", "2026-01-01T00:01:01Z", "2026-01-02T00:00:00Z", "revocation_invalid"},
		{"expiry-exclusive", "2025-12-31T00:00:00Z", "2026-01-01T00:01:00Z", "revocation_invalid"},
		{"before-expiry", "2025-12-31T00:00:00Z", "2026-01-01T00:01:01Z", "accept"},
		{"empty", "2026-01-01T00:01:00Z", "2026-01-01T00:01:00Z", "revocation_invalid"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := gr2Body()
			b["iat"], b["exp"] = c.start, c.end
			gr2Want(t, gr2Vector(t, gr2Att(t, b, 0), gr2Snapshot(t, "2026-01-01T00:00:30Z", []any{})), c.want)
		})
	}
}

// Claim: the publisher window covers both ends of min/max(now,W), rather
// than whichever clock the caller supplies first. Each skew has a valid
// neighboring interval and separate too-late-start / exclusive-expiry controls.
func TestGrantRevocation2ClockInterval(t *testing.T) {
	for _, c := range []struct{ name, now, w, low, high, after string }{
		{"now-behind", "2026-01-01T00:00:59Z", "2026-01-01T00:01:00Z", "2026-01-01T00:00:59Z", "2026-01-01T00:01:00Z", "2026-01-01T00:01:01Z"},
		{"watermark-behind", "2026-01-01T00:01:00Z", "2026-01-01T00:00:59Z", "2026-01-01T00:00:59Z", "2026-01-01T00:01:00Z", "2026-01-01T00:01:01Z"},
		{"watermark-ahead", "2026-01-01T00:01:00Z", "2026-01-01T00:01:01Z", "2026-01-01T00:01:00Z", "2026-01-01T00:01:01Z", "2026-01-01T00:01:02Z"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, which := range []string{"valid", "start-after-low", "end-at-high"} {
				t.Run(which, func(t *testing.T) {
					b := gr2Body()
					b["iat"], b["exp"] = c.low, c.after
					want := "accept"
					if which == "start-after-low" {
						b["iat"] = c.high
						want = "revocation_invalid"
					}
					if which == "end-at-high" {
						b["exp"] = c.high
						want = "revocation_invalid"
					}
					v := gr2Vector(t, gr2Att(t, b, 0), gr2Snapshot(t, "2026-01-01T00:00:30Z", []any{}))
					v.Fixture["now"], v.Fixture["watermark"] = c.now, c.w
					// The legacy subject's separate registry snapshot must also precede
					// both clocks; otherwise intake refuses before the publisher gate.
					seed := sha256.Sum256([]byte("waggle public test registry revocation seed"))
					priv := ed25519.NewKeyFromSeed(seed[:])
					registry := v.Fixture["agent_revocation_root"].(map[string]any)["key"].(string)
					v.Fixture["revocations"].(map[string]any)[registry].(map[string]any)["snapshot"] = base64.RawURLEncoding.EncodeToString(muSign(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": registry, "issued_at": "2026-01-01T00:00:30Z", "complete": true, "entries": []any{}}, priv, registry))

					direct := "accept"
					if want != "accept" {
						direct = "key_binding_invalid"
					}
					if got := gr2Direct(t, v); got != direct {
						t.Fatalf("direct got %s want %s", got, direct)
					}
					gr2Want(t, v, want)
				})
			}
		})
	}
}

// Claim: publisher snapshots retain their own freshness, completeness, rollback,
// signature and revocation checks. N10 signs the exact claimed publisher
// preimage with Q, while retaining P's issuer, key, body and correct content ID.
func TestGrantRevocation2Snapshots(t *testing.T) {
	gr2Want(t, gr2Good(t), "accept")
	for _, c := range []struct{ age, want string }{{"2026-01-01T00:00:01Z", "accept"}, {"2026-01-01T00:00:00Z", "accept"}, {"2025-12-31T23:59:59Z", "revocation_unavailable"}, {"2026-01-01T00:01:01Z", "revocation_unavailable"}} {
		t.Run(c.age, func(t *testing.T) {
			gr2Want(t, gr2Vector(t, gr2Att(t, gr2Body(), 0), gr2Snapshot(t, c.age, []any{})), c.want)
		})
	}
	for _, name := range []string{"missing", "wrong-signature", "short-signature", "incomplete", "rollback", "max-age-61", "revoked-grant", "revoked-key", "bad-entry"} {
		t.Run(name, func(t *testing.T) {
			v := gr2Good(t)
			_, key := muSeedKey(7)
			row := v.Fixture["revocations"].(map[string]any)[key].(map[string]any)
			want := "revocation_invalid"
			switch name {
			case "missing":
				delete(v.Fixture["revocations"].(map[string]any), key)
				want = "revocation_unavailable"
			case "wrong-signature", "short-signature", "incomplete":
				raw, _ := b64(row["snapshot"])
				p, err := record.Parse(raw, 65536, 16)
				if err != nil {
					t.Fatal(err)
				}
				e := p.(map[string]any)
				b := e["body"].(map[string]any)
				if name == "incomplete" {
					b["complete"] = false
					want = "revocation_unavailable"
					k, _ := muSeedKey(7)
					raw = muSign(t, "revocation/1", b, k, key)
				} else {
					pre, err := record.SigningPreimage("revocation/1", key, "author", b)
					if err != nil {
						t.Fatal(err)
					}
					q, _ := muSeedKey(8)
					sig := ed25519.Sign(q, pre)
					if name == "short-signature" {
						sig = sig[:63]
					}
					e["signatures"].([]any)[0].(map[string]any)["sig"] = base64.RawURLEncoding.EncodeToString(sig)
					raw, err = record.Canonical(e)
					if err != nil {
						t.Fatal(err)
					}
				}
				row["snapshot"] = base64.RawURLEncoding.EncodeToString(raw)
			case "rollback":
				row["rollback_safe"] = false
				want = "revocation_unavailable"
			case "max-age-61":
				row["max_age"] = int64(61)
			case "revoked-grant", "revoked-key", "bad-entry":
				kind, id := "record", ""
				raw, _ := b64(v.Input["chain"].([]any)[0])
				id = muID(t, raw)
				if name == "revoked-key" {
					kind = "key"
					_, id = muSeedKey(2)
				}
				if name == "bad-entry" {
					kind = "unknown"
				}
				row["snapshot"] = base64.RawURLEncoding.EncodeToString(gr2Snapshot(t, "2026-01-01T00:00:30Z", []any{map[string]any{"kind": kind, "id": id, "from": "2025-12-31T00:00:00Z"}}))
				if name != "bad-entry" {
					want = "revoked"
				}
			}
			gr2Want(t, v, want)
		})
	}
}

// Claim: absent facts choose the root; present nil/invalid facts refuse even
// with a valid root snapshot. No external effect engine is modeled by this test.
func TestGrantRevocation2Presence(t *testing.T) {
	v := gr2Good(t)
	delete(v.Fixture, "grant_revocation_publisher")
	gr2Want(t, v, "accept")
	for _, name := range []string{"nil", "malformed", "missing-root"} {
		t.Run(name, func(t *testing.T) {
			v := gr2Good(t)
			want := "revocation_invalid"
			switch name {
			case "nil":
				v.Fixture["grant_revocation_publisher"] = nil
				want = "revocation_unavailable"
			case "malformed":
				v.Fixture["grant_revocation_publisher"] = "bm90LWpzb24"
			case "missing-root":
				delete(v.Fixture, "root")
				want = "key_binding_unavailable"
			}
			gr2Want(t, v, want)
		})
	}
}

// Claim: a valid Mac binding reaches the publisher gate directly: invalid
// profile is key_binding_invalid there, whereas G7 maps it to revocation_invalid.
func TestGrantRevocation2DirectBinding(t *testing.T) {
	k, key := muP256("meta")
	pub := elliptic.MarshalCompressed(elliptic.P256(), k.X, k.Y)
	att := muMacAttestation(t, key, pub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1)}, 0)
	for _, bad := range []bool{false, true} {
		v := gr2Good(t)
		if bad {
			b := gr2Body()
			b["binding"].(map[string]any)["profile"] = "unknown"
			v.Fixture["grant_revocation_publisher"] = base64.RawURLEncoding.EncodeToString(gr2Att(t, b, 0))
		}
		id := muID(t, att)
		v.Fixture["attestations"].(map[string]any)[id] = base64.RawURLEncoding.EncodeToString(att)
		v.Fixture["active_generations"].(map[string]any)[key] = map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "active": true}
		_, err := verifier.New(context(t, v.Fixture)).VerifyAttestation(key, id, false)
		want := "accept"
		if bad {
			want = "key_binding_invalid"
		}
		if code(err) != want {
			t.Fatalf("bad=%v got %v want %s", bad, err, want)
		}
	}
}

// Claim: a genuine service-root-signed purpose-5 agent attestation is valid
// identity evidence, but cannot appoint a grant publisher when supplied in that
// fact slot. This uses the committed legacy record, not merely a class label.
func TestGrantRevocation2AgentAppointment(t *testing.T) {
	v := gr2Good(t)
	_, agent := muSeedKey(2)
	id := v.Fixture["agent_attestation_ids"].(map[string]any)[agent].(string)
	a, err := verifier.New(context(t, v.Fixture)).VerifyAttestation(agent, id, false)
	if err != nil || a.Key != agent || a.ID != id {
		t.Fatalf("valid purpose-5 identity: %+v %v", a, err)
	}
	v.Fixture["grant_revocation_publisher"] = v.Fixture["attestations"].(map[string]any)[id]
	gr2Want(t, v, "revocation_invalid")
	if got := gr2Direct(t, v); got != "key_binding_invalid" {
		t.Fatalf("agent appointment direct: %s", got)
	}
}

// Claim: publisher scope cannot be promoted to grant or message authorship or
// agent-attestation issuance. Positive controls elsewhere admit ordinary authors.
func TestGrantRevocation2PurposeSeparation(t *testing.T) {
	gr2Want(t, gr2Good(t), "accept")
	k, key := muSeedKey(7)
	_, agent := muSeedKey(2)
	v := gr2Good(t)
	b := muGrantBody(agent, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	b["issuer"] = key
	v.Input["chain"] = []any{base64.RawURLEncoding.EncodeToString(muSign(t, "grant/1", b, k, key))}
	gr2Want(t, v, "signature_profile_invalid")
	m := load(t, "../vectors/swarm-envelope-2/1-positive/PA1.json")
	raw, _ := b64(m.Input["envelope"])
	p, err := record.Parse(raw, 65536, 16)
	if err != nil {
		t.Fatal(err)
	}
	body := p.(map[string]any)["body"].(map[string]any)
	body["author"] = key
	m.Input["envelope"] = base64.RawURLEncoding.EncodeToString(muSign(t, "message/1", body, k, key))
	m.Fixture["grant_revocation_publisher"] = v.Fixture["grant_revocation_publisher"]
	m.Fixture["known_keys"] = append(m.Fixture["known_keys"].([]any), key)
	if got := derive(t, m); got.Code != "signature_profile_invalid" || len(got.Plan) != 0 {
		t.Fatalf("publisher message: %+v", got)
	}
	macPriv, mac := muP256("meta")
	pub := elliptic.MarshalCompressed(elliptic.P256(), macPriv.X, macPriv.Y)
	a := muMacAttestation(t, mac, pub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1)}, 7)
	// muMacAttestation declares grant-root issuer but signs with 7; both issuer
	// and actual signature are then made consistent with the unauthorized publisher.
	parsed, err := record.Parse(a, 65536, 16)
	if err != nil {
		t.Fatal(err)
	}
	ab := parsed.(map[string]any)["body"].(map[string]any)
	ab["issuer"] = key
	a = muSign(t, "attestation/1", ab, k, key)
	v = gr2Good(t)
	id := muID(t, a)
	v.Fixture["attestations"].(map[string]any)[id] = base64.RawURLEncoding.EncodeToString(a)
	_, err = verifier.New(context(t, v.Fixture)).VerifyAttestation(mac, id, false)
	if code(err) != "key_binding_invalid" {
		t.Fatalf("publisher attestation: %v", err)
	}
}

// Claim: committed Go-only signed fixture pairs retain their exact expected
// public verdict and plan. These are not an independent v2 oracle or release gate.
func TestGrantRevocation2Fixtures(t *testing.T) {
	paths, err := filepath.Glob("testdata/grant-revocation2/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 {
		t.Fatalf("fixture inventory: got %d want 5", len(paths))
	}
	runVectors(t, paths)
}
