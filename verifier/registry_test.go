package verifier_test

import (
	"encoding/base64"
	"github.com/relux-works/waggle/record"
	"github.com/relux-works/waggle/verifier"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The named service and capacity contracts have exact code/empty-plan
// refusals and accepted neighbors. This group runs before service admission
// implementation, and later remains a focused regression group.
func TestRegistryService(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		name := filepath.Base(p)
		if strings.HasPrefix(name, "N-SVC-") || strings.HasPrefix(name, "P-SVC-") || strings.HasPrefix(name, "N-ORD-SVC-") || strings.HasPrefix(name, "N-CAP-") || strings.HasPrefix(name, "P-CAP-") || name == "PN02.json" || name == "PO1.json" || name == "P-JRN-genesis.json" {
			paths = append(paths, p)
		}
	}
	runVectors(t, paths)
}

// Journal admission binds real checkpoint signatures, snapshot and witness
// scope, fork/rollback order and every unsigned hash-chain link. Exact plans
// are compared; the referenced records' admission is outside this API.
func TestRegistryJournal(t *testing.T) {
	var paths []string
	for _, p := range namedPaths(t, "../vectors") {
		name := filepath.Base(p)
		if strings.HasPrefix(name, "N-JRN-") || strings.HasPrefix(name, "P-JRN-") || strings.HasPrefix(name, "N-ORD-JRN-") {
			paths = append(paths, p)
		}
	}
	runVectors(t, paths)
}

// The exported identity API completes its advertised subpipeline, without
// converting class attestation into parent authority. All refusals erase the
// returned identity, and the accepted control has exact key/id/owner binding.
func TestServiceAttestationAPI(t *testing.T) {
	for _, id := range []string{"P-SVC-chain", "N-SVC-actions", "N-SVC-agent-profile", "N-SVC-attestation-expired", "N-SVC-key-revoked", "N-SVC-missing-record", "N-SVC-owner-missing", "N-SVC-owner", "N-SVC-purpose", "N-SVC-role-collision", "N-SVC-subject"} {
		t.Run(id, func(t *testing.T) {
			dir := "0-negative"
			if id == "P-SVC-chain" {
				dir = "1-positive"
			}
			v := load(t, "../vectors/swarm-envelope-2/"+dir+"/"+id+".json")
			rows := v.Fixture["service_attestations"].(map[string]any)
			var key string
			for k := range rows {
				key = k
			}
			a, err := verifier.New(context(t, v.Fixture)).VerifyServiceAttestation(key)
			if code(err) != v.Expected.Code {
				t.Fatalf("code %v want %s", err, v.Expected.Code)
			}
			if err != nil {
				if !reflect.DeepEqual(a, verifier.Attestation{}) {
					t.Fatal("refusal leaked identity", a)
				}
				return
			}
			raw, err := b64(rows[key])
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := record.Parse(raw, 8192, 16)
			if err != nil {
				t.Fatal(err)
			}
			if a.Key != key || a.Owner != "owner-a" || a.ID != parsed.(map[string]any)["id"] {
				t.Fatal("identity binding", a)
			}
		})
	}
}

// Count, wire-byte and depth limits refuse before malformed protected policy.
// This calls the exported API directly; transport base64 is outside its scope.
func TestJournalBounds(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-JRN-genesis.json")
	cp, err := base64.RawURLEncoding.DecodeString(v.Input["checkpoint"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var entries [][]byte
	for _, x := range v.Input["entries"].([]any) {
		b, e := base64.RawURLEncoding.DecodeString(x.(string))
		if e != nil {
			t.Fatal(e)
		}
		entries = append(entries, b)
	}
	good := verifier.New(context(t, v.Fixture))
	if r := good.VerifyJournal(entries, cp, nil); r.Code != "accept" {
		t.Fatal("positive control", r)
	}
	bad := verifier.New(verifier.Context{})
	for _, tc := range []struct {
		name    string
		entries [][]byte
		cp      []byte
	}{
		{"65-entries", make([][]byte, 65), cp},
		{"entry-bytes", [][]byte{make([]byte, 8193)}, cp},
		{"checkpoint-bytes", entries, append(cp, make([]byte, 8193-len(cp))...)},
		{"depth", [][]byte{[]byte(strings.Repeat("[", 17) + strings.Repeat("]", 17))}, cp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bad.VerifyJournal(tc.entries, tc.cp, nil)
			if r.Code != "journal_malformed" || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
				t.Fatal(r)
			}
		})
	}
}

// A configured commit signer has no message/grant/act record profile even
// when the otherwise accepted fixture uses that exact signing key. This
// tests the public intake methods with nearby unchanged accepted controls.
func TestCommitSignerProfiles(t *testing.T) {
	for _, id := range []string{"PN02", "PG1", "PO1"} {
		t.Run(id, func(t *testing.T) {
			v := load(t, "../vectors/swarm-envelope-2/1-positive/"+id+".json")
			if got := derive(t, v); !reflect.DeepEqual(got, v.Expected) {
				t.Fatal("positive control", got)
			}
			field := "envelope"
			var encoded any
			if v.Mode == "grant" {
				encoded = v.Input["chain"].([]any)[0]
			} else {
				encoded = v.Input[field]
			}
			raw, err := b64(encoded)
			if err != nil {
				t.Fatal(err)
			}
			e, err := record.Parse(raw, 65536, 16)
			if err != nil {
				t.Fatal(err)
			}
			key := e.(map[string]any)["signatures"].([]any)[0].(map[string]any)["key"]
			v.Fixture["commit_signing_key"] = key
			got := derive(t, v)
			if got.Code != "signature_profile_invalid" || len(got.Plan) != 0 {
				t.Fatal("commit signer admitted", got)
			}
		})
	}
}
