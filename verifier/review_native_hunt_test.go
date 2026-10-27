package verifier_test

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// A genuine 69-byte signature makes every extra-member/sign-padding comparison
// fit inside 72 bytes. These negative cases exercise parsing, not the size cap.
func TestReviewNativeHuntCanonicalNeighbours(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	f.owner("native-third254")
	p, d := prepareAccept(t, f)
	raw := assembleSign(t, f.preimage, false)
	der := reviewNativeDER(t, raw, false)
	if len(der) != 69 {
		t.Fatalf("signed witness changed length: %d", len(der))
	}
	want := reviewNativeExpected(f, raw)
	prior, e := verifier.AssembleOwnerActNativeP256(p, d.Key, der)
	if e != nil || prior == nil {
		t.Fatal("genuine positive", e)
	}
	stored, ok := prior.Bytes()
	if !ok || !bytes.Equal(stored, want) {
		t.Fatal("wire oracle")
	}
	bad := map[string][]byte{}
	for name, tail := range map[string][]byte{"third-integer": {2, 1, 1}, "inner-null": {5, 0}, "inner-opaque": {0}} {
		b := append(bytes.Clone(der), tail...)
		b[1] += byte(len(tail))
		bad[name] = b
	}
	redundant := append(bytes.Clone(der[:4]), append([]byte{0}, der[4:]...)...)
	redundant[1]++
	redundant[3]++
	bad["redundant-r-sign"] = redundant
	bad["overlong-outer-length"] = append([]byte{der[0], 0x81, der[1]}, der[2:]...)
	constructed := bytes.Clone(der)
	constructed[2] = 0x22
	bad["constructed-integer"] = constructed
	bad["outer-null"] = append(bytes.Clone(der), 5, 0)
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			if len(b) > 72 {
				t.Fatal("comparison accidentally above cap")
			}
			before := bytes.Clone(b)
			out, err := verifier.AssembleOwnerActNativeP256(p, d.Key, b)
			var local *verifier.OwnerActAssemblyError
			if out != nil || !errors.As(err, &local) || local.Code != "assembly_invalid" || err.Error() != "assembly_invalid" {
				t.Fatal("canonical neighbour not exact refusal")
			}
			after, _ := p.Snapshot()
			old, _ := prior.Bytes()
			if !bytes.Equal(before, b) || !reflect.DeepEqual(after, d) || !bytes.Equal(old, want) {
				t.Fatal("refusal mutation")
			}
			next, err := verifier.AssembleOwnerActNativeP256(p, d.Key, der)
			if err != nil || next == nil {
				t.Fatal("post-refusal positive", err)
			}
		})
	}
}

// Same backing array and returned copies stay caller-owned. The native high-S
// pair yields the literal low-S wire; the raw API must still refuse its high-S.
func TestReviewNativeHuntSharedBacking(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	p, d := prepareAccept(t, f)
	low := assembleSign(t, f.preimage, false)
	der := reviewNativeDER(t, low, true)
	backing := append([]byte{0xaa}, der...)
	backing = append(backing, 0xbb)
	supplied := backing[1 : len(backing)-1]
	out, err := verifier.AssembleOwnerActNativeP256(p, d.Key, supplied)
	if err != nil || out == nil {
		t.Fatal("positive", err)
	}
	if backing[0] != 0xaa || backing[len(backing)-1] != 0xbb || !bytes.Equal(supplied, der) {
		t.Fatal("borrowed input changed")
	}
	view, _ := out.Bytes()
	clear(view)
	clear(backing)
	stored, _ := out.Bytes()
	if !bytes.Equal(stored, reviewNativeExpected(f, low)) {
		t.Fatal("result retained caller alias")
	}
	high := bytes.Clone(low)
	new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(low[32:])).FillBytes(high[32:])
	r, e := verifier.AssembleOwnerAct(p, d.Key, high)
	var local *verifier.OwnerActAssemblyError
	if r != nil || !errors.As(e, &local) || local.Code != "assembly_invalid" {
		t.Fatal("raw API normalization introduced")
	}
	after, _ := p.Snapshot()
	if !reflect.DeepEqual(after, d) {
		t.Fatal("plan changed")
	}
}
