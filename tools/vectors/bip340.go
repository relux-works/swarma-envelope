package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// All keys and signing operations in this file are PUBLIC TEST-ONLY operands.
// This opt-in corpus never rewrites or relabels any legacy vector/checker.
func bip340Vectors(out string, check bool) {
	private, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	agent := Key{ID: "bip340:" + b64(schnorr.SerializePubKey(private.PubKey())), K1: private}
	baseMessage := func() Vector {
		v := base("envelope", 0)
		pruneAgentEvidence(&v)
		materializeEvidence(&v)
		indexAttestations(&v)
		e := decode(v.Input["envelope"].(string))
		b := e["body"].(M)
		old := b["author"].(string)
		ref := b["author_attestation"].(string)
		a := decode(v.Fixture["attestations"].(M)[ref].(string))["body"].(M)
		a["subject"] = M{"algorithm": "BIP-340", "key_id": agent.ID, "public_bytes": agent.ID[7:]}
		att := decode(evidenceWire(a, keys[5]))
		b["author"], b["author_attestation"] = agent.ID, att["id"]
		v.Fixture["attestations"] = M{att["id"].(string): wire(att)}
		v.Fixture["agent_attestation_ids"] = M{agent.ID: att["id"]}
		gens := v.Fixture["active_generations"].(M)
		gens[agent.ID] = gens[old]
		delete(gens, old)
		v.Fixture["known_keys"] = []any{agent.ID}
		v.Input["envelope"] = wire(envelope(b, agent, "author"))
		return v
	}
	var vectors []Vector
	emit := func(v Vector, id, claim, pair, code string) {
		v.ID, v.Claim, v.Positive = id, claim, pair
		v.Expected = M{"code": code, "plan": M{}}
		if code == "accept" {
			if v.Mode == "domain" {
				v.Expected["plan"] = M{"tag": v.Fixture["expected_tag"], "key": v.Input["key"]}
			} else {
				v.Expected["plan"] = M{"ids": []any{decode(v.Input["envelope"].(string))["id"]}, "watermark": v.Fixture["now"]}
			}
		}
		vectors = append(vectors, v)
	}
	emit(baseMessage(), "P-BIP-author", "A purpose-5 root-signed BIP-340 author retains full agent provenance; no grant authority is implied.", "", "accept")
	high := baseMessage()
	for i := 0; i < 256; i++ {
		b := body(high)
		b["nonce"] = b64(bytes.Repeat([]byte{byte(i)}, 16))
		high.Input["envelope"] = wire(envelope(b, agent, "author"))
		s := unb64(decode(high.Input["envelope"].(string))["signatures"].([]any)[0].(M)["sig"].(string))
		if new(big.Int).SetBytes(s[32:]).Cmp(new(big.Int).Rsh(new(big.Int).Set(btcec.S256().Params().N), 1)) > 0 {
			break
		}
		if i == 255 {
			panic("missing high-s control")
		}
	}
	emit(high, "P-BIP-high-s", "A valid BIP-340 s above n/2 is accepted; P-256 low-S is not imported.", "", "accept")
	editMessage := func(v *Vector, fn func(M)) {
		b := body(*v)
		fn(b)
		v.Input["envelope"] = wire(envelope(b, agent, "author"))
	}
	editAtt := func(v *Vector, fn func(M)) {
		e := decode(v.Input["envelope"].(string))
		b := e["body"].(M)
		old := b["author_attestation"].(string)
		a := decode(v.Fixture["attestations"].(M)[old].(string))["body"].(M)
		fn(a)
		att := decode(evidenceWire(a, keys[5]))
		v.Fixture["attestations"] = M{att["id"].(string): wire(att)}
		b["author_attestation"] = att["id"]
		v.Input["envelope"] = wire(envelope(b, agent, "author"))
	}
	rows := []struct {
		name, claim, code string
		edit              func(*Vector)
	}{
		{"attestation-signature", "An unsigned/forged provenance record never substitutes for the root signature.", "key_binding_invalid", func(v *Vector) {
			ref := body(*v)["author_attestation"].(string)
			a := decode(v.Fixture["attestations"].(M)[ref].(string))
			a["signatures"].([]any)[0].(M)["sig"] = b64(make([]byte, 64))
			v.Fixture["attestations"].(M)[ref] = wire(a)
		}},
		{"snapshot-signature", "A current-looking snapshot still requires the independently pinned issuer signature.", "key_binding_invalid", func(v *Vector) {
			row := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			a := decode(row["snapshot"].(string))
			a["signatures"].([]any)[0].(M)["sig"] = b64(make([]byte, 64))
			row["snapshot"] = wire(a)
		}},
		{"missing-attestation", "Unavailable provenance never becomes a successful author.", "key_binding_unavailable", func(v *Vector) { v.Fixture["attestations"] = M{} }},
		{"generation", "Protected current generation must equal the root-signed binding.", "key_binding_invalid", func(v *Vector) { v.Fixture["active_generations"].(M)[agent.ID].(M)["generation"] = "other" }},
		{"inactive", "A non-current generation refuses despite valid math.", "key_binding_invalid", func(v *Vector) { v.Fixture["active_generations"].(M)[agent.ID].(M)["active"] = false }},
		{"missing-generation", "Current-generation absence fails closed.", "key_binding_unavailable", func(v *Vector) { v.Fixture["active_generations"] = M{} }},
		{"audience", "Protected audience is exact.", "audience_mismatch", func(v *Vector) { v.Fixture["audience"] = "other" }},
		{"body-binding", "Delivered bytes must match the signed digest.", "message_text_mismatch", func(v *Vector) { v.Fixture["delivery"].(M)["text"] = b64([]byte("other")) }},
		{"author-key", "Signing key and body author must match.", "signer_unknown", func(v *Vector) { editMessage(v, func(b M) { b["author"] = keys[0].ID }) }},
		{"unknown-key", "Admitted author keys come from protected context.", "signer_unknown", func(v *Vector) { v.Fixture["known_keys"] = []any{} }},
		{"missing-snapshot", "A valid attestation cannot replace current signed revocation evidence.", "key_binding_unavailable", func(v *Vector) { v.Fixture["revocations"] = M{} }},
		{"revoked-key", "Current key revocation is enforced after valid author math.", "revoked", func(v *Vector) {
			r := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			b := decode(r["snapshot"].(string))["body"].(M)
			b["entries"] = []any{M{"kind": "key", "id": agent.ID, "from": v.Fixture["now"]}}
			r["snapshot"] = evidenceWire(b, keys[7])
		}},
		{"revoked-attestation", "The exact provenance record is revocable.", "revoked", func(v *Vector) {
			r := v.Fixture["revocations"].(M)[keys[7].ID].(M)
			b := decode(r["snapshot"].(string))["body"].(M)
			b["entries"] = []any{M{"kind": "record", "id": body(*v)["author_attestation"], "from": v.Fixture["now"]}}
			r["snapshot"] = evidenceWire(b, keys[7])
		}},
		{"expired-attestation", "Attestation expiry remains exclusive.", "key_binding_invalid", func(v *Vector) { editAtt(v, func(b M) { b["exp"] = "2026-01-01T00:01:00Z" }) }},
		{"subject-algorithm", "Algorithm spelling and key prefix must agree.", "key_binding_invalid", func(v *Vector) { editAtt(v, func(b M) { b["subject"].(M)["algorithm"] = "Ed25519" }) }},
		{"subject-key", "An attestation for another key cannot identify this author.", "key_binding_invalid", func(v *Vector) { editAtt(v, func(b M) { b["subject"].(M)["key_id"] = keys[0].ID }) }},
		{"subject-class", "BIP-340 does not become a service subject.", "key_binding_invalid", func(v *Vector) { editAtt(v, func(b M) { b["key_class"] = "service" }) }},
		{"subject-purpose", "BIP-340 agent provenance is message-only.", "key_binding_invalid", func(v *Vector) { editAtt(v, func(b M) { b["purpose"] = "grant-service" }) }},
		{"wrong-reference", "Lookup location cannot substitute for exact attestation content id.", "author_attestation_mismatch", func(v *Vector) {
			ref := body(*v)["author_attestation"].(string)
			editAtt(v, func(b M) { b["iat"] = "2026-01-01T00:00:01Z" })
			store := v.Fixture["attestations"].(M)
			for _, w := range store {
				store[ref] = w
			}
			editMessage(v, func(b M) { b["author_attestation"] = ref })
		}},
		{"version", "An unsupported envelope version has no profile fallback.", "envelope_version_unsupported", func(v *Vector) { edit(v, func(e M) { e["version"] = "swarm-envelope/3" }) }},
		{"type", "Protected type selection precedes signature math.", "envelope_type_mismatch", func(v *Vector) { edit(v, func(e M) { e["body"].(M)["type"] = "grant/1" }) }},
		{"approver", "A BIP-340 author cannot count as an approver.", "signature_profile_invalid", func(v *Vector) {
			edit(v, func(e M) {
				b := e["body"].(M)
				e["signatures"] = append(e["signatures"].([]any), M{"key": agent.ID, "role": "approver", "sig": b64(sign(agent, sigPre(b, "approver", agent.ID, "message/1")))})
			})
		}},
		{"delegate", "The reserved delegate role gains no BIP-340 profile.", "signature_profile_invalid", func(v *Vector) {
			edit(v, func(e M) {
				b := e["body"].(M)
				e["signatures"] = append(e["signatures"].([]any), M{"key": agent.ID, "role": "delegate", "sig": b64(sign(agent, sigPre(b, "delegate", agent.ID, "message/1")))})
			})
		}},
		{"bad-signature", "Changed signature bytes refuse without candidate effects.", "envelope_signature_invalid", func(v *Vector) {
			edit(v, func(e M) {
				s := e["signatures"].([]any)[0].(M)
				raw := unb64(s["sig"].(string))
				raw[3] ^= 1
				s["sig"] = b64(raw)
			})
		}},
	}
	for _, row := range rows {
		v := baseMessage()
		row.edit(&v)
		emit(v, "N-BIP-"+row.name, row.claim, "P-BIP-author", row.code)
	}
	pre := append([]byte("swarma-msg/2\n"), canonical(M{"text": "1234567890"})...)
	// Pick a canonical original preimage of exactly32bytes for the raw-vs-hash witness.
	pre = append([]byte("swarma-msg/2\n"), canonical(M{"text": strings.Repeat("x", 32-len("swarma-msg/2\n")-len(canonical(M{"text": ""})))})...)
	domainBase := func() Vector {
		return Vector{Mode: "domain", Input: M{"key": agent.ID, "sig": b64(sign(agent, pre)), "preimage": b64(pre)}, Fixture: M{"expected_tag": "swarma-msg/2"}}
	}
	emit(domainBase(), "P-BIP-domain", "The mathematical API verifies SHA256 of the unchanged exact registered preimage without granting a role.", "", "accept")
	crypto := []struct {
		name, code string
		edit       func(*Vector)
	}{
		{"key33", "envelope_malformed", func(v *Vector) {
			v.Input["key"] = "bip340:" + b64(append([]byte{2}, schnorr.SerializePubKey(private.PubKey())...))
		}},
		{"key65", "envelope_malformed", func(v *Vector) { v.Input["key"] = "bip340:" + b64(private.PubKey().SerializeUncompressed()) }},
		{"key31", "envelope_malformed", func(v *Vector) { v.Input["key"] = "bip340:" + b64(schnorr.SerializePubKey(private.PubKey())[:31]) }},
		{"key-pad", "envelope_malformed", func(v *Vector) { v.Input["key"] = agent.ID + "=" }},
		{"key-alias", "envelope_malformed", func(v *Vector) {
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			i := strings.IndexByte(alphabet, agent.ID[len(agent.ID)-1])
			v.Input["key"] = agent.ID[:len(agent.ID)-1] + string(alphabet[i+1])
		}},
		{"x-prime", "envelope_signature_invalid", func(v *Vector) { v.Input["key"] = "bip340:" + b64(btcec.S256().Params().P.FillBytes(make([]byte, 32))) }},
		{"x-nonlift", "envelope_signature_invalid", func(v *Vector) { v.Input["key"] = "bip340:" + b64(make([]byte, 32)) }},
		{"r-prime", "envelope_signature_invalid", func(v *Vector) {
			s := unb64(v.Input["sig"].(string))
			btcec.S256().Params().P.FillBytes(s[:32])
			v.Input["sig"] = b64(s)
		}},
		{"s-order", "envelope_signature_invalid", func(v *Vector) {
			s := unb64(v.Input["sig"].(string))
			btcec.S256().Params().N.FillBytes(s[32:])
			v.Input["sig"] = b64(s)
		}},
		{"s-order-plus-one", "envelope_signature_invalid", func(v *Vector) {
			s := unb64(v.Input["sig"].(string))
			new(big.Int).Add(btcec.S256().Params().N, big.NewInt(1)).FillBytes(s[32:])
			v.Input["sig"] = b64(s)
		}},
		{"s-order-minus-one", "envelope_signature_invalid", func(v *Vector) {
			s := unb64(v.Input["sig"].(string))
			new(big.Int).Sub(btcec.S256().Params().N, big.NewInt(1)).FillBytes(s[32:])
			v.Input["sig"] = b64(s)
		}},
		{"signature63", "envelope_signature_invalid", func(v *Vector) { v.Input["sig"] = b64(unb64(v.Input["sig"].(string))[:63]) }},
		{"raw-preimage", "envelope_signature_invalid", func(v *Vector) {
			if len(pre) != 32 {
				panic("raw32 control")
			}
			s, e := schnorr.Sign(private, pre)
			must(e)
			v.Input["sig"] = b64(s.Serialize())
		}},
		{"double-hash", "envelope_signature_invalid", func(v *Vector) {
			h := sha256.Sum256(pre)
			hh := sha256.Sum256(h[:])
			s, e := schnorr.Sign(private, hh[:])
			must(e)
			v.Input["sig"] = b64(s.Serialize())
		}},
		{"outer-tag", "envelope_signature_invalid", func(v *Vector) {
			h := sha256.Sum256(append([]byte("BIP0340/outer"), pre...))
			s, e := schnorr.Sign(private, h[:])
			must(e)
			v.Input["sig"] = b64(s.Serialize())
		}},
		{"changed-bytes", "envelope_signature_invalid", func(v *Vector) { v.Input["preimage"] = b64(bytes.Replace(pre, []byte("xxx"), []byte("yyy"), 1)) }},
		{"domain-swap", "domain_mismatch", func(v *Vector) { v.Fixture["expected_tag"] = "swarma-waggle grant/1" }},
		{"ed-under-bip", "envelope_signature_invalid", func(v *Vector) { v.Input["sig"] = b64(ed25519.Sign(keys[0].Ed, pre)) }},
		{"bip-under-ed", "envelope_signature_invalid", func(v *Vector) { v.Input["key"] = keys[0].ID }},
	}
	for _, row := range crypto {
		v := domainBase()
		row.edit(&v)
		emit(v, "N-BIP-crypto-"+row.name, "The original key, signature and exact SHA256/preimage/domain contract refuses "+row.name+".", "P-BIP-domain", row.code)
	}
	managed := map[string]bool{}
	failures := 0
	for _, v := range vectors {
		path := filepath.Join(out, "bip340", v.ID+".json")
		managed[path] = true
		data, e := json.MarshalIndent(v, "", "  ")
		must(e)
		data = append(data, '\n')
		if check {
			old, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(old, data) {
				fmt.Fprintln(os.Stderr, "byte mismatch:", path)
				failures++
			}
		} else {
			must(os.MkdirAll(filepath.Dir(path), 0755))
			must(os.WriteFile(path, data, 0644))
		}
	}
	if check {
		paths, e := filepath.Glob(filepath.Join(out, "bip340", "*.json"))
		must(e)
		for _, p := range paths {
			if !managed[p] {
				fmt.Fprintln(os.Stderr, "unexpected vector:", p)
				failures++
			}
		}
	}
	if failures > 0 {
		os.Exit(1)
	}
	fmt.Printf("%d BIP-340 vectors; legacy corpus unchanged; check=%v\n", len(vectors), check)
}
