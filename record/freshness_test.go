package record_test

import (
	"testing"

	"github.com/relux-works/waggle/record"
)

// Freshness has an exact new closed-registry literal; mathematical domain
// registration does not admit it to the message signer.
func TestFreshnessDomain(t *testing.T) {
	tag := record.Tag("freshness/1")
	if tag != "swarma-registry freshness/1" || !record.Registered(tag) || record.Registered(tag+" ") {
		t.Fatal("exact freshness tag", tag)
	}
	if _, err := record.AdmitSigner([]byte(tag+"\n{}"), record.IdentityPolicy{}); err == nil || err.Error() != "signer_domain_refused" {
		t.Fatal("signer refusal", err)
	}
}
