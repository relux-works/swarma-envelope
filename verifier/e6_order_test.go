package verifier_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

func e6Signature(t *testing.T, e map[string]any) {
	t.Helper()
	b := e["body"].(map[string]any)
	s := e["signatures"].([]any)[0].(map[string]any)
	key := s["key"].(string)
	alg, pub, err := record.KeyBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := record.SigningPreimage("grant/1", key, s["role"].(string), b)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := b64(s["sig"])
	if err != nil {
		t.Fatal(err)
	}
	if alg == "ed25519" {
		if !ed25519.Verify(pub, pre, sig) {
			t.Fatal("invalid signature premise")
		}
	} else {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pub)
		h := sha256.Sum256(pre)
		if x == nil || !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatal("invalid signature premise")
		}
	}
}

// E6 issuer/profile admission precedes strict subject-point crypto through
// both grant APIs. Subject-only operands still refuse; two unchanged accepted
// neighbors and the single-failure issuer/profile controls ground the order.
// Stdlib signature math independently verifies every constructed premise.
func TestE6GrantSubjectOrder(t *testing.T) {
	for _, id := range []string{
		"N-E6-issuer-before-subject-ed25519", "N-E6-issuer-before-subject-p256", "N-E6-profile-before-subject",
		"N-E6-subject-only-ed25519", "N-E6-subject-only-p256", "PN02-grant", "PG1", "N02-grant", "W-purpose5-grant",
	} {
		t.Run(id, func(t *testing.T) {
			dir := "0-negative/"
			if id == "PN02-grant" || id == "PG1" {
				dir = "1-positive/"
			}
			v := load(t, "../vectors/swarm-envelope-2/"+dir+id+".json")
			raw, err := b64(v.Input["chain"].([]any)[0])
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := record.Parse(raw, 65536, 16)
			if err != nil {
				t.Fatal(err)
			}
			e := parsed.(map[string]any)
			e6Signature(t, e)
			if strings.HasPrefix(id, "N-E6-") && code(record.ValidateKey(e["body"].(map[string]any)["subject"].(string))) != "envelope_signature_invalid" {
				t.Fatal("invalid subject premise")
			}
			got := derive(t, v)
			if !reflect.DeepEqual(got, v.Expected) {
				t.Error("Authorize", got, "want", v.Expected)
			}
			r := verifier.New(context(t, v.Fixture)).VerifyEnvelope(raw, "grant/1")
			wantPlan := verifier.Plan{}
			if v.Expected.Code == "accept" {
				wantPlan = verifier.Plan{IDs: []string{e["id"].(string)}, Watermark: v.Expected.Plan["watermark"].(string)}
			}
			if r.Code != v.Expected.Code || !reflect.DeepEqual(r.Plan, wantPlan) {
				t.Error("VerifyEnvelope", r, "want", v.Expected.Code, wantPlan)
			}
		})
	}
}

// A four-link accepted chain reaches each leaf/intermediate/root position in
// order. The same issuer/invalid-subject compound at ANY link must refuse at
// G2/E6, before later parent-edge failures caused by the changed content id.
func TestE6EveryGrantPosition(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32)) // Synthetic test-only signer.
	key := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	for position := 0; position < 4; position++ {
		v := load(t, "../vectors/swarm-envelope-2/1-positive/PG4.json")
		if got := derive(t, v); !reflect.DeepEqual(got, v.Expected) {
			t.Fatal("valid neighbor", got)
		}
		chain := v.Input["chain"].([]any)
		raw, err := b64(chain[position])
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := record.Parse(raw, 65536, 16)
		if err != nil {
			t.Fatal(err)
		}
		e := parsed.(map[string]any)
		b := e["body"].(map[string]any)
		if b["issuer"] == key {
			t.Fatal("issuer mismatch premise")
		}
		b["subject"] = "ed25519:" + base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
		id, err := record.ContentID("grant/1", b)
		if err != nil {
			t.Fatal(err)
		}
		e["id"] = id
		s := e["signatures"].([]any)[0].(map[string]any)
		s["key"] = key
		pre, err := record.SigningPreimage("grant/1", key, "author", b)
		if err != nil {
			t.Fatal(err)
		}
		s["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, pre))
		e6Signature(t, e)
		raw, err = record.Canonical(e)
		if err != nil {
			t.Fatal(err)
		}
		chain[position] = base64.RawURLEncoding.EncodeToString(raw)
		got := derive(t, v)
		if got.Code != "signer_unknown" || len(got.Plan) != 0 {
			t.Fatalf("position%d: %+v", position, got)
		}
		r := verifier.New(context(t, v.Fixture)).VerifyEnvelope(raw, "grant/1")
		if r.Code != "signer_unknown" || !reflect.DeepEqual(r.Plan, verifier.Plan{}) {
			t.Fatalf("position%d: %+v", position, r)
		}
	}
}
