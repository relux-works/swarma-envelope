package cryptocheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"math/big"
	"os"
	"testing"
)

// This exercises the production fixed32 verifier beneath the SHA256 envelope
// adapter on original official operands. Unsupported arbitrary messages retain
// official TRUE and an explicit false capability observation; not a pass of
// those vectors. Scalar overflow and R parity/infinity are official negatives.
func TestBIP340OfficialFixed32AndCapability(t *testing.T) {
	raw, e := os.ReadFile("../../tools/bip340check/testdata/official/test-vectors.csv")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != "34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d" {
		t.Fatal("official hash mismatch")
	}
	rows, e := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows[1:] {
		t.Run(row[0], func(t *testing.T) {
			decode := func(s string) []byte {
				b, e := hex.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			msg := decode(row[4])
			got := verifyBIP340(decode(row[2]), decode(row[5]), msg) == ""
			want := row[6] == "TRUE"
			if len(msg) != 32 {
				// Observe the pinned dependency itself as well as our fixed32
				// adapter; an adapter-only refusal is not a capability probe.
				pub, pe := schnorr.ParsePubKey(decode(row[2]))
				sig, se := schnorr.ParseSignature(decode(row[5]))
				if pe != nil || se != nil {
					t.Fatal("capability probe setup", pe, se)
				}
				dependencyObserved := sig.Verify(msg, pub)
				if !want || got || dependencyObserved {
					t.Fatal("capability bound changed", want, got)
				}
				t.Logf("official_expected=true supported_by_fixed32_dependency=false observed_verify=false message_bytes=%d", len(msg))
				return
			}
			if got != want {
				t.Fatalf("official verdict mismatch: expected=%t observed=%t", want, got)
			}
		})
	}
}

// Scope caching of Ed25519 points must not share an algorithm identity with an
// identically sized BIP-340 x coordinate or bypass signature equations.
func TestBIP340DispatchAndScope(t *testing.T) {
	s := new(Scope)
	for _, alg := range []string{"unknown", "BIP340"} {
		if ValidateKey(alg, make([]byte, 32), s) != "envelope_signature_invalid" || VerifySignature(alg, make([]byte, 32), make([]byte, 64), nil, s) != "envelope_signature_invalid" {
			t.Fatal("unknown algorithm accepted")
		}
	}
	if ValidateKey("bip340", make([]byte, 32), s) != "envelope_signature_invalid" {
		t.Fatal("nonlifting key")
	}
}

// This parser-boundary witness checks ORIGINAL scalars independently of the
// later equation. It makes no claim that s=n yields a valid signature/forgery.
// Zero and n-1 are valid scalar encodings, not necessarily valid signatures.
func TestBIP340OriginalScalarBounds(t *testing.T) {
	p, n := btcec.S256().Params().P, btcec.S256().Params().N
	for _, tc := range []struct {
		name string
		r, s *big.Int
		want bool
	}{
		{"zero", big.NewInt(0), big.NewInt(0), true},
		{"upper-neighbor", new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(n, big.NewInt(1)), true},
		{"s=n", big.NewInt(1), n, false},
		{"s=n+1", big.NewInt(1), new(big.Int).Add(n, big.NewInt(1)), false},
		{"r=p", p, big.NewInt(1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, 64)
			tc.r.FillBytes(raw[:32])
			tc.s.FillBytes(raw[32:])
			if got := bip340ScalarBounds(raw); got != tc.want {
				t.Fatalf("original scalar-bound mismatch: got=%t want=%t", got, tc.want)
			}
		})
	}
	if bip340ScalarBounds(make([]byte, 63)) || bip340ScalarBounds(make([]byte, 65)) {
		t.Fatal("wrong scalar length")
	}
}
