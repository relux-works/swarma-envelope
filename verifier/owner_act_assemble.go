package verifier

import (
	"bytes"
	"encoding/base64"

	"github.com/relux-works/swarma-envelope/record"
)

// OwnerActAssemblyError is a fixed local failure, never a consumer/wire verdict
// or native diagnostic. Its only code is assembly_invalid; output is nil.
type OwnerActAssemblyError struct{ Code string }

func (e *OwnerActAssemblyError) Error() string { return e.Code }

// VerifiedOwnerActEnvelope retains ordinary correctly formed signed intent,
// not consumer authority, native confirmation or an effect permit. Only
// AssembleOwnerAct constructs it. A zero value is invalid; value copies share
// immutable private state. It has no native attempt or once-consumption state.
type VerifiedOwnerActEnvelope struct{ state *ownerActAssembled }
type ownerActAssembled struct{ wire []byte }

// Bytes returns a fresh caller-owned copy of the complete canonical envelope.
// Nil/zero results return nil, false. Changing a copy changes no retained result.
func (e *VerifiedOwnerActEnvelope) Bytes() ([]byte, bool) {
	if e == nil || e.state == nil {
		return nil, false
	}
	return bytes.Clone(e.state.wire), true
}

// AssembleOwnerAct purely verifies an already supplied raw64 low-S P256
// signature and assembles the ordinary one-approver swarm-envelope/2 envelope.
// The returned key must exactly match the original privately prepared plan.
// Inputs must stay stable during this synchronous call. No DER conversion,
// signing, native key use, presence, current facts or consumer gates are supplied.
// Repeated verification is permitted; it does not authorize another native use.
// Native one-use/cancellation/destruction/publication remain separate work.
func AssembleOwnerAct(p *OwnerActSigningPlan, returnedKey string, rawSignature []byte) (result *VerifiedOwnerActEnvelope, err error) {
	defer func() {
		if x := recover(); x != nil {
			if _, ok := x.(refusal); !ok {
				panic(x)
			}
			result = nil
			err = &OwnerActAssemblyError{Code: "assembly_invalid"}
		}
	}()
	// Refuse the raw byte bound before any copy, decode or allocation of input.
	need(len(rawSignature) == 64 && p != nil && p.state != nil, "assembly_invalid")
	d := p.state.data // Original private authority, never a detached Snapshot.
	need(returnedKey == d.Key, "assembly_invalid")
	need(len(d.Body) <= 8192 && len(d.SigningPreimage) <= 12288, "assembly_invalid")
	b, ok := must(record.Parse(d.Body, 8192, 16)).(map[string]any)
	need(ok && bytes.Equal(must(record.Canonical(b)), d.Body), "assembly_invalid")
	id := must(record.ContentID("operator-act/1", b))
	pre := must(record.SigningPreimage("operator-act/1", d.Key, "approver", b))
	need(id == d.ContentID && bytes.Equal(pre, d.SigningPreimage), "assembly_invalid")
	alg, _ := key(d.Key)
	need(alg == "p256", "assembly_invalid")
	need(record.VerifySignature(d.Key, rawSignature, d.SigningPreimage) == nil, "assembly_invalid")

	wire := must(record.Canonical(map[string]any{
		"body": b, "id": id, "version": "swarm-envelope/2",
		"signatures": []any{map[string]any{
			"key": d.Key, "role": "approver", "sig": base64.RawURLEncoding.EncodeToString(rawSignature),
		}},
	}))
	need(len(wire) <= 8192 && len(wire) == d.PredictedEnvelopeBytes, "assembly_invalid")
	// Re-parse the final emitted bytes and use shared pure shape/crypto helpers.
	// envelope()/VerifyOwnerAct need independent consumer facts; none are forged.
	e, ok := must(record.Parse(wire, 8192, 16)).(map[string]any)
	need(ok, "assembly_invalid")
	schema(e, "operator-act/1")
	finalBody := obj(e["body"])
	need(e["version"] == "swarm-envelope/2" && finalBody["type"] == "operator-act/1" && bytes.Equal(must(record.Canonical(finalBody)), d.Body), "assembly_invalid")
	need(e["id"] == id && e["id"] == must(record.ContentID("operator-act/1", finalBody)), "assembly_invalid")
	sigs := array(e["signatures"])
	need(len(sigs) == 1, "assembly_invalid")
	s := obj(sigs[0])
	need(s["key"] == d.Key && s["role"] == "approver", "assembly_invalid")
	finalPre := must(record.SigningPreimage("operator-act/1", str(s["key"]), str(s["role"]), finalBody))
	sig := must(record.DecodeBase64(str(s["sig"]), 64))
	need(bytes.Equal(finalPre, d.SigningPreimage) && bytes.Equal(sig, rawSignature), "assembly_invalid")
	need(record.VerifySignature(str(s["key"]), sig, finalPre) == nil, "assembly_invalid")
	return &VerifiedOwnerActEnvelope{state: &ownerActAssembled{wire: wire}}, nil
}
