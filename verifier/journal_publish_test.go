package verifier_test

import (
	"reflect"
	"testing"

	"github.com/relux-works/waggle/record"
)

// The shared fixture is exactly anchor + agent attestation reference + reissue,
// with the exact witnessed prior checkpoint and unchanged cumulative entries.
// Journal acceptance proves publication continuity, not referenced authority.
func TestRegistryJournalPublicationTransaction(t *testing.T) {
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-JRN-publish-reissue.json")
	parse := func(value any) map[string]any {
		t.Helper()
		raw, err := b64(value)
		if err != nil {
			t.Fatal(err)
		}
		e, err := record.Parse(raw, 8192, 16)
		if err != nil {
			t.Fatal(err)
		}
		return e.(map[string]any)
	}
	rows := v.Input["entries"].([]any)
	if len(rows) != 3 {
		t.Fatal("entry count", len(rows))
	}
	a, n, r := parse(rows[0]), parse(rows[1]), parse(rows[2])
	ab, nb, rb := a["body"].(map[string]any), n["body"].(map[string]any), r["body"].(map[string]any)
	cp := parse(v.Input["checkpoint"])
	cb := cp["body"].(map[string]any)
	w := v.Fixture["journal_witness"].(map[string]any)
	prior := parse(v.Fixture["seen"].(map[string]any)[w["checkpoint_id"].(string)])
	pb := prior["body"].(map[string]any)
	if len(w) != 6 || v.Fixture["id_journal_available"] != true || prior["id"] != w["checkpoint_id"] || pb["seq"] != w["registry_seq"] || pb["head"] != w["registry_head"] || a["id"] != w["registry_head"] {
		t.Fatal("prior projection", w, prior)
	}
	if ab["seq"] != int64(1) || nb["seq"] != int64(2) || rb["seq"] != int64(3) || nb["prev"] != a["id"] || rb["prev"] != n["id"] || cb["seq"] != int64(3) || cb["head"] != r["id"] {
		t.Fatal("transaction chain")
	}
	if nb["op"] != "add" || nb["record_type"] != "attestation/1" || rb["op"] != "add" || rb["record_type"] != "revocation/1" {
		t.Fatal("transaction kinds")
	}
	att := parse(v.Fixture["attestations"].(map[string]any)[nb["record"].(string)])
	if att["id"] != nb["record"] || att["body"].(map[string]any)["key_class"] != "agent" {
		t.Fatal("real agent reference", att)
	}
	root := w["registry_id"].(string)
	snap := parse(v.Fixture["revocations"].(map[string]any)[root].(map[string]any)["snapshot"])
	old := load(t, "../vectors/swarm-envelope-2/1-positive/P-JRN-genesis.json")
	oldSnap := parse(old.Fixture["revocations"].(map[string]any)[root].(map[string]any)["snapshot"])
	sb, ob := snap["body"].(map[string]any), oldSnap["body"].(map[string]any)
	if pb["snapshot"] != oldSnap["id"] || cb["snapshot"] != snap["id"] || rb["record"] != snap["id"] || sb["issued_at"].(string) <= ob["issued_at"].(string) || !reflect.DeepEqual(sb["entries"], ob["entries"]) {
		t.Fatal("unchanged cumulative reissue")
	}
	if got := derive(t, v); !reflect.DeepEqual(got, v.Expected) {
		t.Fatal(got, v.Expected)
	}
}
