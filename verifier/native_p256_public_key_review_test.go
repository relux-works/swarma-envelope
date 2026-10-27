package verifier_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/relux-works/swarma-envelope/verifier"
	"testing"
)

var reviewNativePublicVectors = []struct{ name, native, key string }{
	{"multiple1", "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", "p256:A2sX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"},
	{"minus-G", "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a", "p256:AmsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"},
	{"multiple2", "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1", "p256:A3zyexiNA09-ilI4AwS1GsPAiWnid_IbNaYLSPxHZpl4"},
	{"leading-Y-zero", "04986ae2506f1ff104d04230861d8f4b498f4bc4c6d009b30f7544dc129b82d28d003cccc0a6460e0ae328a4d97d3c7b61d86fc6289c189f2525110c441bb07e97", "p256:A5hq4lBvH_EE0EIwhh2PS0mPS8TG0AmzD3VE3BKbgtKN"},
	{"last-20", "04ba6821cba9bab3ba57a98127482a5de00c108a6ac3241ebb508c58a24d9edba28841c5de60c4af3b87375ec78cbd21e7e70a85292d77eb4f8f218b036784e120", "p256:ArpoIcupurO6V6mBJ0gqXeAMEIpqwyQeu1CMWKJNntui"},
	{"last-0d", "04fc8b9e62fd84b49a3e70b728e31a34fa21b5fa95141f580fc96a49751f461042d5b4287a2a5816f78bfc86cb0b63b6086da77b7c5a014ab0f51db6524f3d820d", "p256:A_yLnmL9hLSaPnC3KOMaNPohtfqVFB9YD8lqSXUfRhBC"},
	{"leading-X-zero", "04005543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00abb4c85a3d8ea29efaafa24406912dd84d5b14dc32bf656ef6c6bd58a5d943f92", "p256:AgBVQ4lK89AO19dAq9vXXJawaHe3h9tfcO6ni5Co18AK"},
	{"last-0a", "045cce8e5c56f245100cb0514fb4c9f165e57c5b4e99ea27070a3befb07c3771559e21ef4c70f7d4de9d8cce92a060656324087155cb2b2e03e45774b02897b60a", "p256:AlzOjlxW8kUQDLBRT7TJ8WXlfFtOmeonBwo777B8N3FV"},
	{"independent-3G", "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032", "p256:Al7L5NGmMwpEyPfvlR1L8WXmxrch762phftBZhvG5_1s"},
}

func reviewNativeBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func reviewNativeAccept(t *testing.T, i int) []byte {
	t.Helper()
	v := reviewNativePublicVectors[i]
	b := reviewNativeBytes(t, v.native)
	old := bytes.Clone(b)
	k, e := verifier.NativeP256KeyID(b)
	if e != nil || k != v.key {
		t.Fatalf("literal identity %s: got %q/%v want %q", v.name, k, e, v.key)
	}
	if !bytes.Equal(old, b) {
		t.Fatal("caller bytes changed")
	}
	return b
}
func reviewNativeRefuse(t *testing.T, b []byte) {
	t.Helper()
	old := bytes.Clone(b)
	k, e := verifier.NativeP256KeyID(b)
	var typed *verifier.NativeP256PublicKeyError
	if k != "" || !errors.As(e, &typed) || e.Error() != "native_public_key_invalid" {
		t.Fatalf("expected empty fixed typed refusal; got %q / %v", k, e)
	}
	if !bytes.Equal(old, b) {
		t.Fatal("refusal changed bytes")
	}
	reviewNativeAccept(t, 8)
}

// Independently checked integer-field literals pin full IDs and both Y parities.
// These public mathematical fixtures do not prove native origin or key custody.
func TestReviewNativePublicNormalization(t *testing.T) {
	for i, v := range reviewNativePublicVectors {
		t.Run(v.name, func(t *testing.T) {
			b := reviewNativeAccept(t, i)
			reviewNativeRefuse(t, append([]byte(" "), b...))
			reviewNativeRefuse(t, []byte(v.native))
			reviewNativeRefuse(t, []byte(v.key))
		})
	}
	if reviewNativePublicVectors[0].key == reviewNativePublicVectors[1].key {
		t.Fatal("bad parity fixtures")
	}
	for _, loc := range []struct{ i, pos int }{{3, 33}, {6, 1}} {
		b := reviewNativeAccept(t, loc.i)
		if b[loc.pos] != 0 {
			t.Fatal("missing leading-zero fixture")
		}
		reviewNativeRefuse(t, append(bytes.Clone(b[:loc.pos]), b[loc.pos+1:]...))
	}
}

// CR, LF, NUL and space inside valid binary coordinates are data; external
// line endings are not alternative representations. No text/Unicode premise.
func TestReviewNativePublicLineEndings(t *testing.T) {
	var all []byte
	for i, v := range reviewNativePublicVectors {
		t.Run(v.name, func(t *testing.T) {
			b := reviewNativeAccept(t, i)
			all = append(all, b...)
			for _, e := range [][]byte{{10}, {13}, {13, 10}, {10, 13}} {
				reviewNativeRefuse(t, append(bytes.Clone(b), e...))
				reviewNativeRefuse(t, append(bytes.Clone(e), b...))
			}
		})
	}
	for _, c := range []byte{0, 10, 13, 32} {
		if !bytes.Contains(all, []byte{c}) {
			t.Fatal("missing binary control")
		}
	}
}

// A valid 65-byte prefix cannot authorize any suffix or second frame.
func TestReviewNativePublicTrailing(t *testing.T) {
	for i, v := range reviewNativePublicVectors {
		t.Run(v.name, func(t *testing.T) {
			b := reviewNativeAccept(t, i)
			for _, s := range [][]byte{{0}, {255}, {32}, {9}, b, []byte("trailer")} {
				reviewNativeRefuse(t, append(bytes.Clone(b), s...))
			}
		})
	}
}
