package verifier_test

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Separate hunt after the persisted three-family formal sweep. The actual
// tighter schemas attain body2043/A2048/request4171 and envelope2348/result2396.
// The outer 16464/8240 transport ceilings are not eligible profile witnesses.
func TestOwnerActFrameHuntReachableBounds(t *testing.T) {
	f := prepareFixtureFor(t, "mirror-enable")
	f.owner(strings.Repeat("\x00", 255))
	for _, b := range []*[]byte{&f.body, &f.render} {
		*b = bytes.Replace(*b, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("a", 63)+`"`), 1)
	}
	f.argument("source_room", "room", strings.Repeat(`"`, 255))
	f.argument("source_recipient", "service", strings.Repeat(`"`, 255))
	f.argument("owner_recipient", "owner", strings.Repeat(`"`, 255))
	f.argument("bound_room", "bound", strings.Repeat("b", 136))
	c, s := frameIDs()
	raw := frameRequest(f.body, f.args, c, s)
	frameAccept(t, raw, f.body, f.args, c, s)
	r, wire := frameSigned(t, f)
	out := frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
	if len(f.body) != 2043 || len(f.args) != 2048 || len(raw) != 4171 || len(wire) != 2348 || len(out) != 2396 {
		t.Fatal("real joint profile maxima differ")
	}
	t.Logf("real joint byte bounds body=%d A=%d request=%d envelope=%d result=%d", len(f.body), len(f.args), len(raw), len(wire), len(out))
	f.argument("bound_room", strings.Repeat("b", 136), strings.Repeat("b", 137))
	if len(f.args) != 2049 {
		t.Fatal("A size neighbor not exact")
	}
	frameReject(t, frameRequest(f.body, f.args, c, s))
}

// Subslice guards and each opaque field position are preserved byte for byte,
// with no special all-zero/nonUTF8 rejection or caller-buffer retention. These
// variants establish syntax, not randomness or a protected enrollment lookup.
func TestOwnerActFrameHuntOpaqueAndSubslice(t *testing.T) {
	f := prepareFixtureFor(t, "bind")
	c, s := frameIDs()
	for field := 0; field < 2; field++ {
		for pos := 0; pos < 32; pos++ {
			for _, value := range []byte{0, 0x80, 0xff} {
				t.Run(fmt.Sprintf("%d/%d/%d", field, pos, value), func(t *testing.T) {
					cc, ss := c, s
					if field == 0 {
						cc[pos] = value
					} else {
						ss[pos] = value
					}
					raw := frameRequest(f.body, f.args, cc, ss)
					backing := append([]byte{0xaa, 0xbb}, raw...)
					backing = append(backing, 0xcc)
					r := frameAccept(t, backing[2:len(backing)-1], f.body, f.args, cc, ss)
					if backing[0] != 0xaa || backing[1] != 0xbb || backing[len(backing)-1] != 0xcc {
						t.Fatal("guard changed")
					}
					clear(backing)
					if !bytes.Equal(r.Body, f.body) || !bytes.Equal(r.Arguments, f.args) || r.Correlation != cc || r.EnrollmentSelector != ss {
						t.Fatal("subslice retained input alias")
					}
				})
			}
		}
	}
}

// Both confirmed assertions and all operations remain mere proposed data. The
// exact encoded signed intent still lacks independent consumer facts; repeated
// encoding/parse supplies no confirmation, presence, currentness or effect.
func TestOwnerActFrameHuntNoConsumerAuthority(t *testing.T) {
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		for _, confirmed := range []string{"false", "true"} {
			t.Run(op+"/"+confirmed, func(t *testing.T) {
				f := prepareFixtureFor(t, op)
				for _, b := range []*[]byte{&f.body, &f.render} {
					*b = bytes.Replace(*b, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
				}
				f.rehash()
				c, s := frameIDs()
				frameAccept(t, frameRequest(f.body, f.args, c, s), f.body, f.args, c, s)
				r, wire := frameSigned(t, f)
				for i := 0; i < 2; i++ {
					out := frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
					v := verifier.New(verifier.Context{})
					for _, got := range []verifier.Result{v.VerifyEnvelope(out[48:], "operator-act/1"), v.VerifyOperator(out[48:]), v.VerifyOwnerAct(out[48:], f.args, f.render, verifier.OwnerActContext{})} {
						if got.Code != "signer_unavailable" || !reflect.DeepEqual(got.Plan, verifier.Plan{}) {
							t.Fatal("framing invented consumer authority", got.Code)
						}
					}
				}
			})
		}
	}
}

// Header/size refusals must precede input-dependent parse/copy allocation. On
// the selected Go toolchain the fixed empty error itself allocates no storage.
// This bounded allocation witness distinguishes early limits from the deeper
// parsers refusing the same otherwise malformed oversized input later.
func TestOwnerActFrameHuntEarlyBounds(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	c, s := frameIDs()
	cases := map[string][]byte{
		"body8193":      frameRequest(bytes.Repeat([]byte{'x'}, 8193), f.args, c, s),
		"arguments2049": frameRequest(f.body, bytes.Repeat([]byte{'x'}, 2049), c, s),
		"protocol-over": make([]byte, 16465),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(5, func() {
				r, err := verifier.ParseOwnerActRequestFrame(raw)
				if err == nil || r.Body != nil || r.Arguments != nil || r.Correlation != ([32]byte{}) || r.EnrollmentSelector != ([32]byte{}) {
					panic("early-bound refusal invariant")
				}
			})
			if allocs != 0 {
				t.Fatalf("oversized input allocated before refusal: %g allocations", allocs)
			}
			frameReject(t, raw)
		})
	}
}
