package verifier_test

import (
	"fmt"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
)

// Published additional entries are permitted, while unavailable/malformed pin
// values or a missing selected definition cannot produce exact current rights.
// Catalog naming/provisioning itself is an external qualified premise.
func TestReviewOwnerActProfileCatalogPinnedEntries(t *testing.T) {
	for _, tc := range []struct {
		name string
		pin  any
		want string
	}{
		{"valid", record.Digest([]byte("separate synthetic published profile pin")), "accept"},
		{"null", nil, "key_binding_unavailable"},
		{"empty", "", "key_binding_unavailable"},
		{"wrong-type", int64(1), "key_binding_unavailable"},
		{"non-content-id", "source", "key_binding_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := ownerActControl(t, "owner-dm.unbind")
			x.profiles["profiles"].(map[string]any)["other/1"] = tc.pin
			x.snapshots(t)
			x.check(t, tc.want)
		})
	}
	x := ownerActControl(t, "owner-dm.unbind")
	delete(x.profiles["profiles"].(map[string]any), "owner-acts/1")
	x.snapshots(t)
	x.check(t, "key_binding_unavailable")
}

// Identity and policy revision are independent of generation and binding
// revision. Matching new signed/protected binding values can be valid while a
// stale exact authority query still refuses; changing all facts is not a cache.
func TestReviewOwnerActGenerationScope(t *testing.T) {
	x := ownerActControl(t, "owner-dm.unbind")
	x.check(t, "accept")
	x.binding["generation"], x.binding["revision"] = int64(2), int64(7)
	x.in.Arguments.IdentityGeneration, x.in.Arguments.BindingRevision = 2, 7
	x.remap(t)
	x.snapshots(t)
	x.check(t, "key_binding_unavailable")
	x.authority["generation"] = int64(2)
	x.snapshots(t)
	x.check(t, "accept")
	x.authority["admitted"] = false
	x.snapshots(t)
	x.check(t, "key_binding_invalid")
}

// A genuine three-step protected history is usable; checking only its current
// endpoint cannot conceal a conflicting interior predecessor. These are
// in-process premises, not a qualified durable-history source.
func TestReviewOwnerActLineageLinks(t *testing.T) {
	x := ownerActControl(t, "owner-dm.unbind")
	for revision := int64(2); revision <= 3; revision++ {
		previous := x.authority["policy_id"]
		id := record.Digest([]byte(fmt.Sprintf("synthetic protected successor %d", revision)))
		for _, value := range []map[string]any{x.authority, x.head, x.floor} {
			value["revision"], value["policy_id"], value["previous"] = revision, id, previous
		}
		x.lineage["policies"] = append(x.lineage["policies"].([]any), map[string]any{"revision": revision, "policy_id": id, "previous": previous})
	}
	x.in.Arguments.AuthorityRevision = 3
	x.remap(t)
	x.snapshots(t)
	x.check(t, "accept")
	x.lineage["policies"].([]any)[1].(map[string]any)["previous"] = record.Digest([]byte("foreign predecessor"))
	x.snapshots(t)
	x.check(t, "key_binding_unavailable")
}
