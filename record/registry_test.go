package record_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"github.com/relux-works/waggle/record"
	"testing"
)

// Both new tags are exact, distinct closed-registry members and content-id
// domains. Codec math does not admit a signed journal profile; the message
// signer refuses either domain before inspecting any canonical payload.
func TestRegistryDomains(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, 32)) // Synthetic public test material.
	key := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	body := map[string]any{"type": "opaque"}
	seen := map[string]bool{}
	for _, kind := range []string{"journal-entry/1", "checkpoint/1"} {
		tag := record.Tag(kind)
		if tag == "" || seen[tag] || !record.Registered(tag) || record.Registered(tag+" ") {
			t.Fatal("exact tag membership", tag)
		}
		seen[tag] = true
		id, err := record.ContentID(kind, body)
		if err != nil || id == "" {
			t.Fatal(id, err)
		}
		pre, err := record.SigningPreimage(kind, key, "author", body)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(private, pre)
		if err := record.CheckDomain(pre, tag, key, sig); err != nil {
			t.Fatal("math control", err)
		}
		if _, err := record.AdmitSigner(pre, record.IdentityPolicy{}); err == nil || err.Error() != "signer_domain_refused" {
			t.Fatal("signer domain", err)
		}
		other := "checkpoint/1"
		if kind == other {
			other = "journal-entry/1"
		}
		otherID, err := record.ContentID(other, body)
		if err != nil || id == otherID {
			t.Fatal("id domain separation", err)
		}
		if err := record.CheckDomain(pre, record.Tag(other), key, sig); err == nil || err.Error() != "domain_mismatch" {
			t.Fatal("signature domain separation", err)
		}
	}
}
