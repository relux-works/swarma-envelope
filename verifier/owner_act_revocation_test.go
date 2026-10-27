package verifier_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
)

// This changes only bounded synthetic fixtures, rebuilding every affected
// journal hash and genuine root signature before the real shared F mint.
// It does not fabricate receipt internals or assert native source qualification.
func ownerActRevokedVector(t *testing.T) vector {
	t.Helper()
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-CU-receipt-operator.json")
	decode := func(wire any) map[string]any {
		t.Helper()
		raw, err := b64(wire)
		if err != nil {
			t.Fatal(err)
		}
		p, err := record.Parse(raw, 8192, 16)
		if err != nil {
			t.Fatal(err)
		}
		return p.(map[string]any)
	}
	encode := func(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }
	registrySeed := sha256.Sum256([]byte("waggle public test registry revocation seed"))
	registryPrivate := ed25519.NewKeyFromSeed(registrySeed[:])
	signRegistry := func(e map[string]any) []byte {
		raw, id := currencySigned(t, e["body"].(map[string]any), registryPrivate)
		e["id"] = id
		return raw
	}
	consume := decode(v.Input["consume"].(map[string]any)["input"].(map[string]any)["envelope"])
	device := consume["signatures"].([]any)[0].(map[string]any)["key"]
	root := v.Fixture["operator_root"].(string)
	row := v.Fixture["revocations"].(map[string]any)[root].(map[string]any)
	snap := decode(row["snapshot"])
	oldID := snap["id"].(string)
	snap["body"].(map[string]any)["entries"] = []any{map[string]any{"kind": "key", "id": device, "from": "2026-01-01T00:00:00Z"}}
	signed := targetFixture{kind: "revocation/1", e: snap}.signed(t)
	newID := snap["id"].(string)
	row["snapshot"] = encode(signed)
	seen := v.Fixture["seen"].(map[string]any)
	delete(seen, oldID)
	seen[newID] = encode(signed)
	index := v.Fixture["snapshot_journal"].(map[string]any)
	entries := index["entries"].([]any)
	var previous any
	for i, wire := range entries {
		e := decode(wire)
		b := e["body"].(map[string]any)
		b["prev"] = previous
		if b["record"] == oldID {
			b["record"] = newID
		}
		id, err := record.ContentID("journal-entry/1", b)
		if err != nil {
			t.Fatal(err)
		}
		e["id"] = id
		previous = id
		entries[i] = encode(targetWire(t, e))
	}
	fixSet := func(set any) {
		for _, value := range set.([]any) {
			s := value.(map[string]any)
			if s["snapshot_id"] == oldID {
				s["snapshot_id"] = newID
			}
		}
	}
	mint := v.Input["mint"].(map[string]any)["input"].(map[string]any)
	cp := decode(mint["checkpoint"])
	cb := cp["body"].(map[string]any)
	cb["head"] = previous
	fixSet(cb["snapshots"])
	mint["checkpoint"] = encode(signRegistry(cp))
	chain := mint["chain"].([]any)
	for i, wire := range chain {
		tip := decode(wire)
		b := tip["body"].(map[string]any)
		b["checkpoint_id"] = cp["id"]
		fixSet(b["snapshots"])
		chain[i] = encode(signRegistry(tip))
	}
	w := v.Fixture["journal_witness"].(map[string]any)
	w["checkpoint_id"], w["registry_head"] = cp["id"], previous
	a := v.Fixture["freshness_anchor"].(map[string]any)
	a["checkpoint_id"] = cp["id"]
	fixSet(a["snapshots"])
	return v
}

// Current exact rights cannot repair genuine signed device revocation; a
// separate withdrawn policy still wins at its earlier O2 authority slot.
func TestOwnerActsHuntRevocationIndependent(t *testing.T) {
	ownerActControl(t, "owner-dm.unbind").check(t, "accept")
	x := ownerActFrom(t, "owner-dm.unbind", "owner-a", ownerActRevokedVector(t))
	x.check(t, "revoked")
	x.authority["admitted"] = false
	x.snapshots(t)
	x.check(t, "key_binding_invalid")
}
