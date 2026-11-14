package record_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-envelope/record"
)

// Synthetic public test-only scalar; this is never a deployment key.
func bipControl(t *testing.T) (string, []byte, []byte) {
	t.Helper()
	k, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	key := "bip340:" + base64.RawURLEncoding.EncodeToString(schnorr.SerializePubKey(k.PubKey()))
	pre := []byte("swarma-msg/2\n{}")
	h := sha256.Sum256(pre)
	sig, e := schnorr.Sign(k, h[:])
	if e != nil {
		t.Fatal(e)
	}
	return key, sig.Serialize(), pre
}

// Exact x-only encoding and curve membership are independent of full-point
// parity. Wrong lengths, aliases, field overflow and non-lifting x refuse.
func TestBIP340KeyAdmission(t *testing.T) {
	key, _, _ := bipControl(t)
	raw, _ := base64.RawURLEncoding.DecodeString(key[7:])
	if e := record.ValidateKey(key); e != nil {
		t.Fatal("valid control", e)
	}
	p := btcec.S256().Params().P.FillBytes(make([]byte, 32))
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"short", raw[:31], "envelope_malformed"}, {"compressed", append([]byte{2}, raw...), "envelope_malformed"},
		{"uncompressed", make([]byte, 65), "envelope_malformed"}, {"empty", nil, "envelope_malformed"},
		{"field-prime", p, "envelope_signature_invalid"}, {"nonlifting-zero", make([]byte, 32), "envelope_signature_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := refusalCode(record.ValidateKey("bip340:" + base64.RawURLEncoding.EncodeToString(tc.raw))); got != tc.want {
				t.Fatalf("%s want %s", got, tc.want)
			}
		})
	}
	for _, alias := range []string{key + "=", key[:len(key)-1] + "!", "BIP340:" + key[7:]} {
		if got := refusalCode(record.ValidateKey(alias)); got != "envelope_malformed" {
			t.Fatalf("alias: %s", got)
		}
	}
	for i := byte(1); i < 20; i++ {
		k, _ := btcec.PrivKeyFromBytes([]byte{i})
		full := k.PubKey().SerializeCompressed()
		if full[0] == 3 {
			oddSource := "bip340:" + base64.RawURLEncoding.EncodeToString(full[1:])
			if e := record.ValidateKey(oddSource); e != nil {
				t.Fatal("x from odd source", e)
			}
			return
		}
	}
	t.Fatal("odd-source control absent")
}

// Verification binds SHA256 of the complete original preimage; raw, double
// hash, outer-tag, role/body/key changes and cross-algorithm signatures refuse.
// This low-level API grants no role authority and has no effects.
func TestBIP340SignatureContract(t *testing.T) {
	key, sig, pre := bipControl(t)
	if e := record.VerifySignature(key, sig, pre); e != nil {
		t.Fatal("valid", e)
	}
	for _, changed := range [][]byte{append(bytes.Clone(pre), ' '), []byte("swarma-waggle grant/1\n{}"), nil} {
		if got := refusalCode(record.VerifySignature(key, sig, changed)); got != "envelope_signature_invalid" {
			t.Fatal(got)
		}
	}
	k, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	h := sha256.Sum256(pre)
	hh := sha256.Sum256(h[:])
	outer := sha256.Sum256(append([]byte("BIP0340/outer"), pre...))
	for _, wrong := range [][]byte{hh[:], outer[:]} {
		s, e := schnorr.Sign(k, wrong)
		if e != nil {
			t.Fatal(e)
		}
		if got := refusalCode(record.VerifySignature(key, s.Serialize(), pre)); got != "envelope_signature_invalid" {
			t.Fatal("wrong outer hash", got)
		}
	}
	seed := sha256.Sum256([]byte("public test-only Ed25519 confusion control"))
	ed := ed25519.NewKeyFromSeed(seed[:])
	edkey := "ed25519:" + base64.RawURLEncoding.EncodeToString(ed.Public().(ed25519.PublicKey))
	if got := refusalCode(record.VerifySignature(key, ed25519.Sign(ed, pre), pre)); got != "envelope_signature_invalid" {
		t.Fatal("ed under bip", got)
	}
	if got := refusalCode(record.VerifySignature(edkey, sig, pre)); got != "envelope_signature_invalid" {
		t.Fatal("bip under ed", got)
	}
	n := btcec.S256().Params().N
	p := btcec.S256().Params().P
	for _, tc := range []struct {
		name   string
		offset int
		value  *big.Int
	}{
		{"r=p", 0, p}, {"r=p+1", 0, new(big.Int).Add(p, big.NewInt(1))}, {"s=n", 32, n}, {"s=n+1", 32, new(big.Int).Add(n, big.NewInt(1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := bytes.Clone(sig)
			tc.value.FillBytes(s[tc.offset : tc.offset+32])
			if got := refusalCode(record.VerifySignature(key, s, pre)); got != "envelope_signature_invalid" {
				t.Fatal(got)
			}
		})
	}
	for _, s := range [][]byte{nil, sig[:63], append(bytes.Clone(sig), 0), make([]byte, 64)} {
		if got := refusalCode(record.VerifySignature(key, s, pre)); got != "envelope_signature_invalid" {
			t.Fatal("length/zero", got)
		}
	}
	// A valid s above n/2 MUST accept; low-S is exclusively the P-256 contract.
	for i := 0; i < 100; i++ {
		m := append(bytes.Clone(pre), byte(i))
		h := sha256.Sum256(m)
		s, e := schnorr.Sign(k, h[:])
		if e != nil {
			t.Fatal(e)
		}
		raw := s.Serialize()
		if new(big.Int).SetBytes(raw[32:]).Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
			if e := record.VerifySignature(key, raw, m); e != nil {
				t.Fatal("high-s", e)
			}
			return
		}
	}
	t.Fatal("high-s control absent")
}

// Protected provider identity narrows all three existing paths for BIP-340;
// unavailable policy and foreign key/author/attestation never admit a signature.
func TestBIP340SignerIdentity(t *testing.T) {
	key, _, _ := bipControl(t)
	id := record.Digest([]byte("public test-only attestation"))
	body := map[string]any{"type": "message/1", "author": key, "author_attestation": id}
	pre, e := record.SigningPreimage("message/1", key, "author", body)
	if e != nil {
		t.Fatal(e)
	}
	policy := record.IdentityPolicy{MultiAgent: true, CallerKey: key, CallerAttestationID: id}
	if _, e := record.AdmitSigner(pre, policy); e != nil {
		t.Fatal("valid", e)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*record.IdentityPolicy)
	}{
		{"missing-key", "signer_identity_unavailable", func(p *record.IdentityPolicy) { p.CallerKey = "" }},
		{"wrong-attestation", "signer_identity_mismatch", func(p *record.IdentityPolicy) { p.CallerAttestationID = record.Digest(nil) }},
		{"invalid-policy", "signer_identity_unavailable", func(p *record.IdentityPolicy) { p.Invalid = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := policy
			tc.change(&p)
			a, e := record.AdmitSigner(pre, p)
			if refusalCode(e) != tc.want || a != (record.SignerAdmission{}) {
				t.Fatal(a, e)
			}
		})
	}
	for _, field := range []string{"author", "author_attestation"} {
		b := map[string]any{"type": "message/1", "author": key, "author_attestation": id}
		b[field] = "foreign"
		p, _ := record.SigningPreimage("message/1", key, "author", b)
		a, e := record.AdmitSigner(p, policy)
		if refusalCode(e) != "signer_identity_mismatch" || a != (record.SignerAdmission{}) {
			t.Fatal(field, a, e)
		}
	}
}

// Every existing signed-record dimension remains in the original SHA256
// preimage. Independently changing key, role, version, body or domain must not
// verify under a formerly valid signature, even at the math-only boundary.
func TestBIP340SignedRecordBinding(t *testing.T) {
	key, _, _ := bipControl(t)
	k, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	b := map[string]any{"type": "message/1", "author": key, "text": "test-only"}
	pre, e := record.SigningPreimage("message/1", key, "author", b)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(pre)
	s, e := schnorr.Sign(k, h[:])
	if e != nil {
		t.Fatal(e)
	}
	if e := record.VerifySignature(key, s.Serialize(), pre); e != nil {
		t.Fatal("valid", e)
	}
	for _, field := range []string{"key", "role", "version", "body"} {
		t.Run(field, func(t *testing.T) {
			parsed, e := record.Parse(pre[len("swarma-msg/2\n"):], 24576, 12)
			if e != nil {
				t.Fatal(e)
			}
			p := parsed.(map[string]any)
			switch field {
			case "key":
				p[field] = "foreign"
			case "role":
				p[field] = "approver"
			case "version":
				p[field] = "swarm-envelope/3"
			case "body":
				p[field].(map[string]any)["text"] = "changed"
			}
			raw, e := record.Canonical(p)
			if e != nil {
				t.Fatal(e)
			}
			raw = append([]byte("swarma-msg/2\n"), raw...)
			if got := refusalCode(record.VerifySignature(key, s.Serialize(), raw)); got != "envelope_signature_invalid" {
				t.Fatal(got)
			}
		})
	}
	other, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{4}, 32))
	otherKey := "bip340:" + base64.RawURLEncoding.EncodeToString(schnorr.SerializePubKey(other.PubKey()))
	if got := refusalCode(record.VerifySignature(otherKey, s.Serialize(), pre)); got != "envelope_signature_invalid" {
		t.Fatal("other key", got)
	}
}
