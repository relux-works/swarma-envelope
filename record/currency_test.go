package record_test

import (
	"github.com/relux-works/swarma-envelope/record"
	"testing"
)

// Golden byte domains and canonical preimages are codec claims; these minimal
// bodies do not claim full checkpoint/freshness schema admission.
func TestCurrencyGoldenDomains(t *testing.T) {
	for _, tc := range []struct{ kind, id string }{
		{"checkpoint/1", "sha256:5ac99ea6bffb4fc45c78e6c2a1cc551ac174e42dcaacc6fcd322ca1d780c2297"},
		{"checkpoint/2", "sha256:cc21d3c0255055fc9bdcc0be7dc7ee51fbf74b787573d779268e1e5b97a0492f"},
		{"freshness/1", "sha256:d2329ee9d45cfb5625374dc231fbffab0b79171d54157f236b44449cb4d28c9e"},
		{"freshness/2", "sha256:1a254411694be1c3326e7eade604da8a21b87960283733a4f6a21ea27c4bebf8"},
	} {
		b := map[string]any{"type": tc.kind}
		id, e := record.ContentID(tc.kind, b)
		if e != nil || id != tc.id {
			t.Fatal(tc.kind, id, e)
		}
		tag := "swarma-registry " + tc.kind
		if record.Tag(tc.kind) != tag || !record.Registered(tag) || record.Registered(tag+" ") {
			t.Fatal(tag)
		}
		got, e := record.SigningPreimage(tc.kind, "fixture-key", "author", b)
		want := tag + "\n" + `{"body":{"type":"` + tc.kind + `"},"key":"fixture-key","role":"author","version":"swarm-envelope/2"}`
		if e != nil || string(got) != want {
			t.Fatal(string(got), want, e)
		}
	}
}
