package verifier

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
)

// AssembleOwnerActNativeP256 converts a supplied native DER P-256 signature to
// raw64 low-S, then delegates verification and envelope construction to
// AssembleOwnerAct using the original private plan and exact returned key.
// Refusals return nil and *OwnerActAssemblyError (assembly_invalid).
// Inputs must remain stable during this synchronous call. This explicit provider
// path authenticates no native origin, custody, confirmation, presence, current
// enrollment, rights or release authority. Repeated pure conversion authorizes
// no native key use. Raw assembly and consumer wire input remain raw64 low-S.
func AssembleOwnerActNativeP256(p *OwnerActSigningPlan, returnedKey string, nativeDER []byte) (*VerifiedOwnerActEnvelope, error) {
	raw, ok := ownerActNativeP256(nativeDER)
	if !ok {
		return nil, &OwnerActAssemblyError{Code: "assembly_invalid"}
	}
	return AssembleOwnerAct(p, returnedKey, raw[:])
}

// Private representation conversion releases no unverified raw signature API.
func ownerActNativeP256(der []byte) ([64]byte, bool) {
	var raw [64]byte
	// Two one-byte positive INTEGERs need eight bytes. Check the native ceiling
	// before decoding, copying or any input-dependent allocation.
	if len(der) < 8 || len(der) > 72 {
		return raw, false
	}
	var pair struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &pair)
	if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil {
		return raw, false
	}
	// Unmarshal into a struct permits extra SEQUENCE members, which are not in
	// rest. Exact standard-library re-encoding also excludes those members.
	canonical, err := asn1.Marshal(pair)
	if err != nil || !bytes.Equal(canonical, der) {
		return raw, false
	}
	n := elliptic.P256().Params().N
	if pair.R.Sign() <= 0 || pair.S.Sign() <= 0 || pair.R.Cmp(n) >= 0 || pair.S.Cmp(n) >= 0 {
		return raw, false
	}
	otherS := new(big.Int).Sub(n, pair.S)
	if otherS.Cmp(pair.S) < 0 {
		pair.S = otherS
	}
	pair.R.FillBytes(raw[:32])
	pair.S.FillBytes(raw[32:])
	return raw, true
}
