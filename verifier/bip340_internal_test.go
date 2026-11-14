package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-envelope/record"
)

// Correct BIP-340 math never admits signed evidence or either currency version.
// These exercise the shared root/profile checks directly with valid signatures;
// public journal/freshness callers retain their existing earlier policy gates.
func TestBIP340CurrencyAndRootRoles(t *testing.T) {
	private, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32)) // PUBLIC TEST-ONLY.
	key := "bip340:" + base64.RawURLEncoding.EncodeToString(schnorr.SerializePubKey(private.PubKey()))
	for _, kind := range []string{"attestation/1", "revocation/1", "checkpoint/1", "freshness/1", "checkpoint/2", "freshness/2"} {
		t.Run(kind, func(t *testing.T) {
			b := map[string]any{"type": kind, "issuer": key, "registry": key, "owner": "owner-a"}
			id, err := record.ContentID(kind, b)
			if err != nil {
				t.Fatal(err)
			}
			pre, err := record.SigningPreimage(kind, key, "author", b)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(pre)
			sig, err := schnorr.Sign(private, h[:])
			if err != nil {
				t.Fatal(err)
			}
			if err := record.VerifySignature(key, sig.Serialize(), pre); err != nil {
				t.Fatal("math premise", err)
			}
			e := map[string]any{"version": "swarm-envelope/2", "body": b, "id": id, "signatures": []any{map[string]any{"role": "author", "key": key, "sig": base64.RawURLEncoding.EncodeToString(sig.Serialize())}}}
			raw, err := record.Canonical(e)
			if err != nil {
				t.Fatal(err)
			}
			want := "key_binding_invalid"
			r := decide(func() Plan {
				switch kind {
				case "checkpoint/1":
					checkpointSignature(e, key, "owner-a")
				case "freshness/1":
					freshnessSignature(e, key, "owner-a")
				case "checkpoint/2", "freshness/2":
					currencySignature(e, kind, key, "owner-a", "currency_signature_invalid")
				default:
					signed(facts{}, raw, kind, key)
				}
				return Plan{IDs: []string{id}}
			})
			switch kind {
			case "checkpoint/1":
				want = "checkpoint_invalid"
			case "freshness/1":
				want = "freshness_signature_invalid"
			case "checkpoint/2", "freshness/2":
				want = "currency_signature_invalid"
			}
			if r.Code != want || !reflect.DeepEqual(r.Plan, Plan{}) {
				t.Fatal(r, "want", want)
			}
		})
	}
}
