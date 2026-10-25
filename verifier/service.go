package verifier

import (
	"bytes"

	"github.com/relux-works/waggle/record"
)

// Protocol-key roles come from protected configuration, never a claimed class.
func excludedSigner(k string, kind string, f facts) bool {
	if equal(k, f["commit_signing_key"]) || equal(k, f["enrollment_publisher"]) {
		return true
	}
	_, service := obj(f["service_attestations"])[k]
	return service && kind != "grant/1"
}
func serviceAttestation(k string, f facts) map[string]any {
	distinct(f)
	policy := evidenceExact(f["service_authority"], "key purpose owner")
	need(policy["purpose"] == "grant-service" && equal(policy["key"], grantRoot(f)), "key_binding_invalid")
	owner := text(policy["owner"], "key_binding_invalid")
	records := evidence(f["service_attestations"], "")
	e := signed(records[k], "attestation/1", policy["key"])
	b := evidenceExact(e["body"], "type issuer subject key_class purpose roles actions iat exp binding")
	subject := evidenceExact(b["subject"], "algorithm key_id public_bytes")
	mapped(func() bool {
		alg, pub := key(k)
		need(alg == "ed25519" && record.ValidateKey(k) == nil && subject["algorithm"] == "Ed25519" && subject["key_id"] == k && isString(subject["public_bytes"]), "key_binding_invalid")
		raw := must(record.DecodeBase64(str(subject["public_bytes"]), 32))
		need(bytes.Equal(pub, raw), "key_binding_invalid")
		return true
	}, "*", "key_binding_invalid")
	binding := evidenceExact(b["binding"], "owner")
	text(binding["owner"], "key_binding_invalid")
	need(equal(owner, binding["owner"]), "key_binding_invalid")
	need(b["key_class"] == "service" && b["purpose"] == "grant-service" && equal(b["roles"], []any{"author"}) && equal(b["actions"], []any{"grant.sign"}), "key_binding_invalid")
	start := mapped(func() int64 { return stamp(b["iat"]) }, "*", "key_binding_invalid")
	end := mapped(func() int64 { return stamp(b["exp"]) }, "*", "key_binding_invalid")
	low, high := times(f)
	receiptGate(f, low, high)
	need(start < end && end-start <= 86400 && start <= low && high < end, "key_binding_invalid")
	snapshot(f, policy["key"], []string{str(e["id"])}, []string{k})
	return e
}

// VerifyServiceAttestation admits the exact service identity and current
// grant-owner revocation, without conferring delegation or effect authority.
// Authorize must still verify the complete parent chain for any service link.
func (v Verifier) VerifyServiceAttestation(key string) (a Attestation, err error) {
	r := decide(func() Plan {
		e := serviceAttestation(key, v.consumerFacts())
		a = Attestation{ID: str(e["id"]), Key: key, Owner: str(obj(obj(e["body"])["binding"])["owner"])}
		return Plan{}
	})
	if r.Code != "accept" {
		return Attestation{}, &record.Error{Code: r.Code}
	}
	return a, nil
}
