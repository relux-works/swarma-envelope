package verifier_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/tools/bip340check/oracle"
	"github.com/relux-works/swarma-envelope/verifier"
)

func bipKey() (string, *btcec.PrivateKey) {
	k, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32)) // PUBLIC TEST-ONLY key.
	return "bip340:" + base64.RawURLEncoding.EncodeToString(schnorr.SerializePubKey(k.PubKey())), k
}
func bipSigned(t *testing.T, e map[string]any) []byte {
	t.Helper()
	b := e["body"].(map[string]any)
	s := e["signatures"].([]any)[0].(map[string]any)
	kind := b["type"].(string)
	id, err := record.ContentID(kind, b)
	if err != nil {
		t.Fatal(err)
	}
	e["id"] = id
	pre, err := record.SigningPreimage(kind, s["key"].(string), s["role"].(string), b)
	if err != nil {
		t.Fatal(err)
	}
	_, k := bipKey()
	h := sha256.Sum256(pre)
	sig, err := schnorr.Sign(k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if !oracle.Verify(schnorr.SerializePubKey(k.PubKey()), h[:], sig.Serialize()) {
		t.Fatal("independent math premise")
	}
	s["sig"] = base64.RawURLEncoding.EncodeToString(sig.Serialize())
	raw, err := record.Canonical(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func bipFixture(t *testing.T) (vector, map[string]any) {
	t.Helper()
	v := load(t, "../vectors/swarm-envelope-2/1-positive/PE1.json")
	raw, _ := b64(v.Input["envelope"])
	parsed, err := record.Parse(raw, 65536, 16)
	if err != nil {
		t.Fatal(err)
	}
	e := parsed.(map[string]any)
	b := e["body"].(map[string]any)
	old := b["author"].(string)
	ref := b["author_attestation"].(string)
	key, _ := bipKey()
	atts := v.Fixture["attestations"].(map[string]any)
	raw, _ = b64(atts[ref])
	a, err := record.Parse(raw, 8192, 16)
	if err != nil {
		t.Fatal(err)
	}
	att := a.(map[string]any)
	ab := att["body"].(map[string]any)
	ab["subject"] = map[string]any{"algorithm": "BIP-340", "key_id": key, "public_bytes": key[7:]}
	bipPutAttestation(t, &v, e, att)
	gens := v.Fixture["active_generations"].(map[string]any)
	gens[key] = gens[old]
	delete(gens, old)
	v.Fixture["known_keys"] = []any{key}
	b["author"] = key
	e["signatures"].([]any)[0].(map[string]any)["key"] = key
	v.Input["envelope"] = base64.RawURLEncoding.EncodeToString(bipSigned(t, e))
	return v, e
}
func bipPutAttestation(t *testing.T, v *vector, e, att map[string]any) {
	t.Helper()
	ab := att["body"].(map[string]any)
	id, err := record.ContentID("attestation/1", ab)
	if err != nil {
		t.Fatal(err)
	}
	att["id"] = id
	seed := sha256.Sum256([]byte("waggle public test seed 5"))
	private := ed25519.NewKeyFromSeed(seed[:])
	key := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	if ab["issuer"] != key {
		t.Fatal("root control changed")
	}
	pre, _ := record.SigningPreimage("attestation/1", key, "author", ab)
	att["signatures"] = []any{map[string]any{"key": key, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, pre))}}
	wire, err := record.Canonical(att)
	if err != nil {
		t.Fatal(err)
	}
	v.Fixture["attestations"] = map[string]any{id: base64.RawURLEncoding.EncodeToString(wire)}
	e["body"].(map[string]any)["author_attestation"] = id
}

// A real root-signed BIP-340 author retains exact provenance, generation,
// revocation, delivery/time and identity equality. Every refusal has zero plan
// and no receipt; protected caller-owned fixture state remains unchanged.
func TestBIP340MessageProvenance(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(vector, map[string]any)
	}{
		{"valid", "accept", nil},
		{"missing-attestation", "key_binding_unavailable", func(v vector, e map[string]any) { v.Fixture["attestations"] = map[string]any{} }},
		{"generation", "key_binding_invalid", func(v vector, e map[string]any) {
			key, _ := bipKey()
			v.Fixture["active_generations"].(map[string]any)[key].(map[string]any)["generation"] = "other"
		}},
		{"inactive", "key_binding_invalid", func(v vector, e map[string]any) {
			key, _ := bipKey()
			v.Fixture["active_generations"].(map[string]any)[key].(map[string]any)["active"] = false
		}},
		{"missing-generation", "key_binding_unavailable", func(v vector, e map[string]any) { v.Fixture["active_generations"] = map[string]any{} }},
		{"audience", "audience_mismatch", func(v vector, e map[string]any) { v.Fixture["audience"] = "other" }},
		{"delivery", "message_text_mismatch", func(v vector, e map[string]any) {
			v.Fixture["delivery"].(map[string]any)["text"] = base64.RawURLEncoding.EncodeToString([]byte("other"))
		}},
		{"author-mismatch", "signer_unknown", func(v vector, e map[string]any) {
			e["body"].(map[string]any)["author"] = "ed25519:wue2t1GJeLZTqzYudkzRIhyY11lAzyPXDjsTXgXoIrk"
		}},
		{"unknown-key", "signer_unknown", func(v vector, e map[string]any) { v.Fixture["known_keys"] = []any{} }},
		{"missing-snapshot", "key_binding_unavailable", func(v vector, e map[string]any) { v.Fixture["revocations"] = map[string]any{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := bipFixture(t)
			if tc.change != nil {
				tc.change(v, e)
			}
			raw := bipSigned(t, e)
			c := context(t, v.Fixture)
			before := targetWire(t, v.Fixture)
			r := verifier.New(c).VerifyMessage(raw)
			if r.Code != tc.want {
				t.Fatalf("got %+v want %s", r, tc.want)
			}
			if tc.want != "accept" && (!reflect.DeepEqual(r.Plan, verifier.Plan{}) || r.FreshnessReceipt != nil) {
				t.Fatal("partial result", r)
			}
			if !bytes.Equal(before, targetWire(t, v.Fixture)) {
				t.Fatal("fixture changed")
			}
		})
	}
	for _, fault := range []string{"expired", "wrong-algorithm", "wrong-class", "wrong-purpose", "wrong-subject", "wrong-reference", "bad-signature"} {
		t.Run(fault, func(t *testing.T) {
			v, e := bipFixture(t)
			ref := e["body"].(map[string]any)["author_attestation"].(string)
			raw, _ := b64(v.Fixture["attestations"].(map[string]any)[ref])
			parsed, _ := record.Parse(raw, 8192, 16)
			a := parsed.(map[string]any)
			b := a["body"].(map[string]any)
			want := "key_binding_invalid"
			switch fault {
			case "expired":
				b["exp"] = "2026-01-01T00:01:00Z"
			case "wrong-algorithm":
				b["subject"].(map[string]any)["algorithm"] = "Ed25519"
			case "wrong-class":
				b["key_class"] = "service"
			case "wrong-purpose":
				b["purpose"] = "grant-service"
			case "wrong-subject":
				b["subject"].(map[string]any)["key_id"] = "ed25519:wue2t1GJeLZTqzYudkzRIhyY11lAzyPXDjsTXgXoIrk"
			}
			if fault == "wrong-reference" {
				b["iat"] = "2026-01-01T00:00:01Z"
			}
			bipPutAttestation(t, &v, e, a)
			if fault == "wrong-reference" {
				store := v.Fixture["attestations"].(map[string]any)
				for _, w := range store {
					store[ref] = w
				}
				e["body"].(map[string]any)["author_attestation"] = ref
				want = "author_attestation_mismatch"
			}
			if fault == "bad-signature" {
				s := a["signatures"].([]any)[0].(map[string]any)
				s["sig"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				w, _ := record.Canonical(a)
				v.Fixture["attestations"].(map[string]any)[a["id"].(string)] = base64.RawURLEncoding.EncodeToString(w)
			}
			r := verifier.New(context(t, v.Fixture)).VerifyMessage(bipSigned(t, e))
			if r.Code != want || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
				t.Fatalf("got %+v want %s", r, want)
			}
		})
	}
}

// Low-level mathematical admission does not widen any other signer role. These
// correctly signed witnesses reach the actual envelope profile boundary.
func TestBIP340ClosedSignerRoles(t *testing.T) {
	key, _ := bipKey()
	for _, kind := range []string{"grant/1", "operator-act/1", "message/1"} {
		t.Run(kind, func(t *testing.T) {
			id := "PG1"
			if kind == "operator-act/1" {
				id = "PO1"
			}
			if kind == "message/1" {
				id = "PE1"
			}
			v := load(t, "../vectors/swarm-envelope-2/1-positive/"+id+".json")
			in := v.Input["envelope"]
			if kind == "grant/1" {
				in = v.Input["chain"].([]any)[0]
			}
			raw, _ := b64(in)
			p, _ := record.Parse(raw, 65536, 16)
			e := p.(map[string]any)
			s := e["signatures"].([]any)[0].(map[string]any)
			s["key"] = key
			if kind == "grant/1" {
				e["body"].(map[string]any)["issuer"] = key
			}
			if kind == "message/1" {
				_, be := bipFixture(t)
				author := be["signatures"].([]any)[0]
				e["signatures"] = []any{author, s}
				s["role"] = "approver"
				e["body"] = be["body"]
				v, _ = bipFixture(t)
			}
			raw = bipSigned(t, e)
			if kind == "message/1" { // Sign each attached record independently.
				for _, x := range e["signatures"].([]any) {
					one := map[string]any{"body": e["body"], "signatures": []any{x}}
					bipSigned(t, one)
				}
				raw = targetWire(t, e)
			}
			r := verifier.New(context(t, v.Fixture)).VerifyEnvelope(raw, kind)
			if r.Code != "signature_profile_invalid" || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
				t.Fatal(r)
			}
		})
	}
	for _, pin := range []string{"service_root", "agent_revocation_root", "operator_root", "root", "commit_signing_key", "enrollment_publisher"} {
		t.Run(pin, func(t *testing.T) {
			v, e := bipFixture(t)
			if m, ok := v.Fixture[pin].(map[string]any); ok {
				m["key"] = key
			} else {
				v.Fixture[pin] = key
			}
			r := verifier.New(context(t, v.Fixture)).VerifyMessage(bipSigned(t, e))
			want := "key_binding_invalid"
			if pin == "service_root" || pin == "commit_signing_key" || pin == "enrollment_publisher" {
				want = "signature_profile_invalid"
			}
			if r.Code != want || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
				t.Fatal(r)
			}
		})
	}
}

// Each separately generated new-profile vector is checked through the actual
// public API against its exact ordered verdict and complete expected plan.
func TestBIP340Vectors(t *testing.T) {
	paths, err := filepath.Glob("../vectors/bip340/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatal("missing corpus", err)
	}
	runVectors(t, paths)
}

// Legacy neighboring roles remain accepted without modifying their bytes.
// The scope is these named controls, not a claim of full legacy qualification.
func TestBIP340LegacyNeighbors(t *testing.T) {
	for _, id := range []string{"PE1", "PE2", "PA4", "PG1", "PO1", "P-SVC-chain"} {
		runVectors(t, []string{"../vectors/swarm-envelope-2/1-positive/" + id + ".json"})
	}
}

// BIP-340 is not a device, service or publisher subject, even under a valid
// legacy root signature. Owner-act profile admission remains P-256-only.
func TestBIP340ClosedEvidenceAndOwnerRoles(t *testing.T) {
	key, _ := bipKey()
	t.Run("device", func(t *testing.T) {
		v, e := bipFixture(t)
		ref := e["body"].(map[string]any)["author_attestation"].(string)
		v.Fixture["operator_attestations"] = map[string]any{key: v.Fixture["attestations"].(map[string]any)[ref]}
		a, err := verifier.New(context(t, v.Fixture)).VerifyAttestation(key, "", true)
		if code(err) != "key_binding_invalid" || a != (verifier.Attestation{}) {
			t.Fatal(a, err)
		}
	})
	t.Run("service", func(t *testing.T) {
		v := load(t, "../vectors/swarm-envelope-2/1-positive/P-SVC-chain.json")
		records := v.Fixture["service_attestations"].(map[string]any)
		var raw []byte
		for _, wire := range records {
			raw, _ = b64(wire)
			break
		}
		p, err := record.Parse(raw, 8192, 16)
		if err != nil {
			t.Fatal(err)
		}
		a := p.(map[string]any)
		b := a["body"].(map[string]any)
		b["subject"] = map[string]any{"algorithm": "BIP-340", "key_id": key, "public_bytes": key[7:]}
		f := targetFixture{kind: "attestation/1", e: a}
		v.Fixture["service_attestations"] = map[string]any{key: base64.RawURLEncoding.EncodeToString(f.signed(t))}
		got, err := verifier.New(context(t, v.Fixture)).VerifyServiceAttestation(key)
		if code(err) != "key_binding_invalid" || got != (verifier.Attestation{}) {
			t.Fatal(got, err)
		}
	})
	t.Run("publisher", func(t *testing.T) {
		v := gr2Good(t)
		raw, _ := b64(v.Fixture["grant_revocation_publisher"])
		p, err := record.Parse(raw, 8192, 16)
		if err != nil {
			t.Fatal(err)
		}
		a := p.(map[string]any)
		a["body"].(map[string]any)["subject"] = map[string]any{"algorithm": "BIP-340", "key_id": key, "public_bytes": key[7:]}
		f := targetFixture{kind: "attestation/1", e: a}
		v.Fixture["grant_revocation_publisher"] = base64.RawURLEncoding.EncodeToString(f.signed(t))
		gr2Want(t, v, "revocation_invalid")
	})
	t.Run("owner-act", func(t *testing.T) {
		x := ownerActControl(t, "owner-dm.unbind")
		x.check(t, "accept")
		x.f.e["signatures"].([]any)[0].(map[string]any)["key"] = key
		raw := bipSigned(t, x.f.e)
		r := verifier.New(x.c).VerifyOwnerAct(raw, x.m.Arguments, x.m.Render, x.p)
		assertOwnerActRefusal(t, r, "signature_profile_invalid")
	})
}

// Standalone identity verification admits the same exact root-signed subject
// as VerifyMessage, but still grants no effect or grant authority.
func TestBIP340StandaloneAttestation(t *testing.T) {
	v, e := bipFixture(t)
	key, _ := bipKey()
	id := e["body"].(map[string]any)["author_attestation"].(string)
	a, err := verifier.New(context(t, v.Fixture)).VerifyAttestation(key, id, false)
	if err != nil || a.ID != id || a.Key != key {
		t.Fatal(a, err)
	}
}

// At the public journal/freshness APIs, correctly encoded BIP-340 signatures
// still cannot turn protected registry pins into a newly admitted root role.
// Existing policy refusal owns this case before checkpoint/freshness math.
func TestBIP340PublicRegistryRoles(t *testing.T) {
	key, _ := bipKey()
	for _, id := range []string{"P-JRN-genesis", "P-FR-chain", "P-CU-journal-same", "P-CU-same-head-empty"} {
		t.Run(id, func(t *testing.T) {
			v := load(t, "../vectors/swarm-envelope-2/1-positive/"+id+".json")
			if got := derive(t, v); !reflect.DeepEqual(got, v.Expected) {
				t.Fatal("valid legacy neighbor", got)
			}
			raw, _ := b64(v.Input["checkpoint"])
			p, err := record.Parse(raw, 8192, 16)
			if err != nil {
				t.Fatal(err)
			}
			cp := p.(map[string]any)
			cp["body"].(map[string]any)["registry"] = key
			cp["signatures"].([]any)[0].(map[string]any)["key"] = key
			v.Input["checkpoint"] = base64.RawURLEncoding.EncodeToString(bipSigned(t, cp))
			if v.Mode == "freshness" {
				chain := v.Input["chain"].([]any)
				for i, x := range chain {
					raw, _ := b64(x)
					p, err := record.Parse(raw, 8192, 16)
					if err != nil {
						t.Fatal(err)
					}
					e := p.(map[string]any)
					e["body"].(map[string]any)["registry"] = key
					e["signatures"].([]any)[0].(map[string]any)["key"] = key
					chain[i] = base64.RawURLEncoding.EncodeToString(bipSigned(t, e))
				}
			}
			v.Fixture["agent_revocation_root"].(map[string]any)["key"] = key
			got := derive(t, v)
			want := "journal_invalid"
			if v.Mode == "freshness" {
				want = "freshness_invalid"
			}
			if got.Code != want || len(got.Plan) != 0 {
				t.Fatal(got, "want", want)
			}
		})
	}
}

// E2 owns malformed key encodings even with an unsupported version. Once
// key grammar is valid, E6 signer resolution precedes point mathematics; an
// unknown non-lifting key must not steal the known key's crypto refusal.
func TestBIP340KeyRefusalOrder(t *testing.T) {
	for _, tc := range []struct {
		name, want       string
		malformed, known bool
	}{
		{"malformed-before-version", "envelope_malformed", true, false},
		{"unknown-before-point", "signer_unknown", false, false},
		{"known-invalid-point", "envelope_signature_invalid", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := bipFixture(t)
			raw := make([]byte, 32)
			if tc.malformed {
				raw = append([]byte{2}, raw...)
				e["version"] = "swarm-envelope/3"
			}
			key := "bip340:" + base64.RawURLEncoding.EncodeToString(raw)
			e["body"].(map[string]any)["author"] = key
			e["signatures"].([]any)[0].(map[string]any)["key"] = key
			if tc.known {
				v.Fixture["known_keys"] = []any{key}
			} else {
				v.Fixture["known_keys"] = []any{}
			}
			id, err := record.ContentID("message/1", e["body"].(map[string]any))
			if err != nil {
				t.Fatal(err)
			}
			e["id"] = id
			r := verifier.New(context(t, v.Fixture)).VerifyMessage(targetWire(t, e))
			if r.Code != tc.want || !reflect.DeepEqual(r.Plan, verifier.Plan{}) || r.FreshnessReceipt != nil {
				t.Fatal(r, "want", tc.want)
			}
		})
	}
}
