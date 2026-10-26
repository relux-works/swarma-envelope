package verifier_test

import (
	"reflect"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

func authorIdentity(t *testing.T, v vector) (string, string) {
	t.Helper()
	raw, err := b64(v.Input["envelope"])
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := record.Parse(raw, 65536, 16)
	if err != nil {
		t.Fatal(err)
	}
	b := parsed.(map[string]any)["body"].(map[string]any)
	return b["author"].(string), b["author_attestation"].(string)
}

// A standalone lookup returns exactly the requested key and signed content id.
// Wrong or empty keys and an alias lookup refuse without partial identity;
// the same signed bytes at their exact key/reference remain a valid neighbor.
func TestAttestationExactReference(t *testing.T) {
	for _, which := range []string{"valid", "different-key", "different-reference", "missing-key", "different-agent-key"} {
		t.Run(which, func(t *testing.T) {
			v, _ := messageControl(t)
			if which == "different-agent-key" {
				v = load(t, "../vectors/swarm-envelope-2/0-negative/N02.json")
			}
			key, ref := authorIdentity(t, v)
			wantKey, wantRef := key, ref
			switch which {
			case "different-key":
				key = v.Fixture["service_root"].(map[string]any)["key"].(string)
			case "different-reference":
				records := v.Fixture["attestations"].(map[string]any)
				alias := record.Digest([]byte("reference consistency control"))
				records[alias] = records[ref]
				ref = alias
			case "missing-key":
				key = ""
			case "different-agent-key":
				for k := range v.Fixture["agent_attestation_ids"].(map[string]any) {
					if k != wantKey {
						key = k
						break
					}
				}
				if key == wantKey {
					t.Fatal("different agent setup")
				}
			}
			a, err := verifier.New(context(t, v.Fixture)).VerifyAttestation(key, ref, false)
			if which == "valid" {
				if err != nil || a.Key != wantKey || a.ID != wantRef {
					t.Fatal("valid neighbor", a, err)
				}
			} else if code(err) != "key_binding_invalid" || a != (verifier.Attestation{}) {
				t.Fatalf("expected key_binding_invalid and zero identity; got %+v %v", a, err)
			}
		})
	}
}

// Snapshot verification includes protected issuer purpose and attestation-root
// scope, and never admits the purpose-5 service as a revocation issuer. The
// intact policy/snapshot is a valid not_revoked neighbor for all three refusals.
func TestRevocationRootPolicy(t *testing.T) {
	for _, id := range []string{"PE1", "W-revoker-purpose", "W-revoker-scope", "W-purpose5-snapshot"} {
		t.Run(id, func(t *testing.T) {
			dir := "0-negative/"
			if id == "PE1" {
				dir = "1-positive/"
			}
			v := load(t, "../vectors/swarm-envelope-2/"+dir+id+".json")
			key, ref := authorIdentity(t, v)
			root := v.Fixture["agent_revocation_root"].(map[string]any)["key"].(string)
			if id == "W-purpose5-snapshot" {
				records := v.Fixture["revocations"].(map[string]any)
				service := v.Fixture["service_root"].(map[string]any)["key"].(string)
				records[service] = records[root]
				root = service
			}
			state, err := verifier.New(context(t, v.Fixture)).CheckRevocation(root, []string{ref}, []string{key})
			if id == "PE1" {
				if state != verifier.NotRevoked || err != nil {
					t.Fatal("valid neighbor", state, err)
				}
			} else if state != verifier.Unavailable || code(err) != "key_binding_invalid" {
				t.Fatalf("expected unavailable with key_binding_invalid; got %s %v", state, err)
			}
		})
	}
}

// Exact-reference intake never falls back to current-id lookup. Missing/null
// facts are unavailable, malformed facts are invalid, and each refuses with no
// partial identity; an explicit reference works without a current-id store.
func TestAttestationReferenceAvailability(t *testing.T) {
	for _, which := range []string{"explicit-only", "missing-reference", "bad-reference", "absent-record", "null-store", "bad-store"} {
		t.Run(which, func(t *testing.T) {
			v, _ := messageControl(t)
			key, ref := authorIdentity(t, v)
			c := context(t, v.Fixture)
			want := "key_binding_unavailable"
			switch which {
			case "explicit-only":
				c.AgentAttestationIDs = verifier.Evidence{}
				want = "accept"
			case "missing-reference":
				ref = ""
			case "bad-reference":
				ref = "bad"
				want = "key_binding_invalid"
			case "absent-record":
				ref = record.Digest([]byte("absent reference"))
			case "null-store":
				c.Attestations = evidence(t, nil)
			case "bad-store":
				c.Attestations = evidence(t, []any{})
				want = "key_binding_invalid"
			}
			a, err := verifier.New(c).VerifyAttestation(key, ref, false)
			if code(err) != want || (want != "accept" && a != (verifier.Attestation{})) || (want == "accept" && (a.Key != key || a.ID != ref)) {
				t.Fatal(a, err, "want", want)
			}
		})
	}
}

// Device lookup is by the exact requested key, with an optional exact content
// reference. Neither an alias lookup nor an inconsistent explicit reference
// can return another device's otherwise valid identity.
func TestDeviceAttestationExactReference(t *testing.T) {
	for _, which := range []string{"key-only", "exact-reference", "wrong-reference", "alias-key"} {
		t.Run(which, func(t *testing.T) {
			v := load(t, "../vectors/swarm-envelope-2/1-positive/PO1.json")
			raw, err := b64(v.Input["envelope"])
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := record.Parse(raw, 8192, 16)
			if err != nil {
				t.Fatal(err)
			}
			e := parsed.(map[string]any)
			key := e["signatures"].([]any)[0].(map[string]any)["key"].(string)
			records := v.Fixture["operator_attestations"].(map[string]any)
			att, err := b64(records[key])
			if err != nil {
				t.Fatal(err)
			}
			parsed, err = record.Parse(att, 8192, 16)
			if err != nil {
				t.Fatal(err)
			}
			id := parsed.(map[string]any)["id"].(string)
			ref := ""
			switch which {
			case "exact-reference":
				ref = id
			case "wrong-reference":
				ref = record.Digest([]byte("other device reference"))
			case "alias-key":
				alias := v.Fixture["operator_root"].(string)
				records[alias] = records[key]
				key = alias
			}
			a, err := verifier.New(context(t, v.Fixture)).VerifyAttestation(key, ref, true)
			if which == "key-only" || which == "exact-reference" {
				if err != nil || a.Key != key || a.ID != id {
					t.Fatal("valid neighbor", a, err)
				}
			} else if code(err) != "key_binding_invalid" || a != (verifier.Attestation{}) {
				t.Fatal(a, err)
			}
		})
	}
}

// Snapshot admission needs a protected issuer role and typed policy. Absent
// policy is unavailable; malformed, unpinned or conflicting policy is invalid.
// The unchanged registry policy, plus operator and grant-domain controls, admit.
func TestSnapshotIssuerAvailability(t *testing.T) {
	for _, which := range []string{"registry", "operator", "grant", "unknown", "missing-registry", "null-registry", "wrong-registry", "missing-service", "bad-service-purpose", "bad-scope-type", "missing-scope"} {
		t.Run(which, func(t *testing.T) {
			v, _ := messageControl(t)
			root := v.Fixture["agent_revocation_root"].(map[string]any)["key"].(string)
			want := "accept"
			switch which {
			case "operator":
				root = v.Fixture["operator_root"].(string)
			case "grant":
				root = v.Fixture["root"].(string)
			case "unknown":
				root, _ = authorIdentity(t, load(t, "../vectors/swarm-envelope-2/1-positive/PE2.json"))
				want = "key_binding_invalid"
			case "missing-registry":
				delete(v.Fixture, "agent_revocation_root")
				want = "unavailable"
			case "null-registry":
				v.Fixture["agent_revocation_root"] = nil
				want = "unavailable"
			case "wrong-registry":
				v.Fixture["agent_revocation_root"] = true
				want = "key_binding_invalid"
			case "missing-service":
				delete(v.Fixture, "service_root")
				want = "unavailable"
			case "bad-service-purpose":
				v.Fixture["service_root"].(map[string]any)["purpose"] = float64(5)
				want = "key_binding_invalid"
			case "bad-scope-type":
				v.Fixture["agent_revocation_root"].(map[string]any)["attestation_root"] = true
				want = "key_binding_invalid"
			case "missing-scope":
				delete(v.Fixture["agent_revocation_root"].(map[string]any), "attestation_root")
				want = "unavailable"
			}
			state, err := verifier.New(context(t, v.Fixture)).CheckRevocation(root, nil, nil)
			if want == "accept" {
				if state != verifier.NotRevoked || err != nil {
					t.Fatal(state, err)
				}
			} else if want == "unavailable" {
				if state != verifier.Unavailable || err != nil {
					t.Fatal(state, err)
				}
			} else if state != verifier.Unavailable || code(err) != want {
				t.Fatal(state, err, "want", want)
			}
		})
	}
}

// Every pairwise overlap among the four protected roles refuses before signed
// evidence in both standalone exports. The unmodified context admits each.
func TestStandaloneDistinctRootRoles(t *testing.T) {
	roles := []string{"service_root", "agent_revocation_root", "operator_root", "root"}
	pin := func(f map[string]any, name string) string {
		if m, ok := f[name].(map[string]any); ok {
			return m["key"].(string)
		}
		return f[name].(string)
	}
	for i, a := range roles {
		for _, b := range roles[i+1:] {
			t.Run(a+"/"+b, func(t *testing.T) {
				v, _ := messageControl(t)
				key, ref := authorIdentity(t, v)
				original := verifier.New(context(t, v.Fixture))
				root := pin(v.Fixture, "agent_revocation_root")
				if _, err := original.VerifyAttestation(key, ref, false); err != nil {
					t.Fatal(err)
				}
				if state, err := original.CheckRevocation(root, nil, nil); state != verifier.NotRevoked || err != nil {
					t.Fatal(state, err)
				}
				if m, ok := v.Fixture[b].(map[string]any); ok {
					m["key"] = pin(v.Fixture, a)
				} else {
					v.Fixture[b] = pin(v.Fixture, a)
				}
				lib := verifier.New(context(t, v.Fixture))
				if got, err := lib.VerifyAttestation(key, ref, false); code(err) != "key_binding_invalid" || got != (verifier.Attestation{}) {
					t.Fatal(got, err)
				}
				if state, err := lib.CheckRevocation(root, nil, nil); state != verifier.Unavailable || code(err) != "key_binding_invalid" {
					t.Fatal(state, err)
				}
			})
		}
	}
}

// The lower-level envelope method completes exactly E1–E8 for each supported
// selected type, including the id journal. Grant-chain/O1–O5 authorization is
// deliberately reserved to Authorize/VerifyOperator, not inferred from a plan.
func TestEnvelopePublicBoundary(t *testing.T) {
	for _, tc := range []struct{ id, kind string }{{"PE1", "message/1"}, {"PG1", "grant/1"}, {"PO1", "operator-act/1"}} {
		t.Run(tc.kind, func(t *testing.T) {
			v := load(t, "../vectors/swarm-envelope-2/1-positive/"+tc.id+".json")
			input := v.Input["envelope"]
			if tc.kind == "grant/1" {
				input = v.Input["chain"].([]any)[0]
			}
			raw, err := b64(input)
			if err != nil {
				t.Fatal(err)
			}
			c := context(t, v.Fixture)
			if r := verifier.New(c).VerifyEnvelope(raw, tc.kind); r.Code != "accept" || len(r.Plan.IDs) != 1 {
				t.Fatal("valid neighbor", r)
			}
			c.IDJournalAvailable = evidence(t, false)
			r := verifier.New(c).VerifyEnvelope(raw, tc.kind)
			if r.Code != "id_journal_unavailable" || len(r.Plan.IDs) != 0 || r.Plan.Watermark != "" || r.Plan.ActionID != "" {
				t.Fatal(r)
			}
		})
	}
}

// The N02 pair isolates signer/author equality: both agent identities really
// verify in the SAME context, and the signature over each complete signed
// record is valid. The grant analogue retains its pinned root and valid device
// issuer. Exact verdict/plan checks also protect the accepted neighbors.
func TestSigningKeyBindingVectors(t *testing.T) {
	for _, id := range []string{"N02", "PN02", "N02-grant", "PN02-grant"} {
		t.Run(id, func(t *testing.T) {
			dir := "0-negative/"
			positive := id[0] == 'P'
			if positive {
				dir = "1-positive/"
			}
			v := load(t, "../vectors/swarm-envelope-2/"+dir+id+".json")
			input := v.Input["envelope"]
			kind, field := "message/1", "author"
			if v.Mode == "grant" {
				input = v.Input["chain"].([]any)[0]
				kind, field = "grant/1", "issuer"
			}
			raw, err := b64(input)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := record.Parse(raw, 65536, 16)
			if err != nil {
				t.Fatal(err)
			}
			e := parsed.(map[string]any)
			b := e["body"].(map[string]any)
			s := e["signatures"].([]any)[0].(map[string]any)
			key := s["key"].(string)
			if (key == b[field]) != positive {
				t.Fatal("signer binding setup")
			}
			sig, err := b64(s["sig"])
			if err != nil {
				t.Fatal(err)
			}
			pre, err := record.SigningPreimage(kind, key, s["role"].(string), b)
			if err != nil {
				t.Fatal(err)
			}
			if err = record.VerifySignature(key, sig, pre); err != nil {
				t.Fatal("signature setup", err)
			}
			lib := verifier.New(context(t, v.Fixture))
			if kind == "message/1" {
				for _, k := range []string{key, b["author"].(string)} {
					ref, ok := v.Fixture["agent_attestation_ids"].(map[string]any)[k].(string)
					if !ok {
						t.Fatal("missing attestation for", k)
					}
					if a, err := lib.VerifyAttestation(k, ref, false); err != nil || a.Key != k || a.ID != ref {
						t.Fatal("agent evidence setup", a, err)
					}
				}
			} else {
				if !positive && key != v.Fixture["root"] {
					t.Fatal("authority signer setup")
				}
				if _, err := lib.VerifyAttestation(b["issuer"].(string), "", true); err != nil {
					t.Fatal("device issuer setup", err)
				}
			}
			got := derive(t, v)
			if !reflect.DeepEqual(got, v.Expected) {
				t.Fatal(got, "want", v.Expected)
			}
		})
	}
}
