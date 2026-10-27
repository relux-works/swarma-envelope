package verifier_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

// Independent literal public mathematical goldens, not production/native keys.
// G is the SP800-186 P-256 basepoint, as pinned in Go1.26.10 elliptic/nistec.go;
// -G uses p-Y and has the same X with the other parity. Other rows are the named
// public scalar multiples, derived once by the bounded Go fixture tool (<=8192,
// stopped at753). Expected native/SEC1/key bytes are hardcoded; tests do not
// search, marshal/unmarshal to build expectations, or invoke the new helper as
// their oracle. These software fixtures prove no SE/provider/enrollment origin.
var publicKeyGoldens = []struct {
	name                    string
	scalar                  int
	native, compressed, key string
}{
	{"multiple1", 1, "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "p256:A2sX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"},
	{"minus-G", -1, "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a", "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "p256:AmsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"},
	{"multiple2", 2, "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1", "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978", "p256:A3zyexiNA09-ilI4AwS1GsPAiWnid_IbNaYLSPxHZpl4"},
	{"leading-Y-zero", 43, "04986ae2506f1ff104d04230861d8f4b498f4bc4c6d009b30f7544dc129b82d28d003cccc0a6460e0ae328a4d97d3c7b61d86fc6289c189f2525110c441bb07e97", "03986ae2506f1ff104d04230861d8f4b498f4bc4c6d009b30f7544dc129b82d28d", "p256:A5hq4lBvH_EE0EIwhh2PS0mPS8TG0AmzD3VE3BKbgtKN"},
	{"last-20", 50, "04ba6821cba9bab3ba57a98127482a5de00c108a6ac3241ebb508c58a24d9edba28841c5de60c4af3b87375ec78cbd21e7e70a85292d77eb4f8f218b036784e120", "02ba6821cba9bab3ba57a98127482a5de00c108a6ac3241ebb508c58a24d9edba2", "p256:ArpoIcupurO6V6mBJ0gqXeAMEIpqwyQeu1CMWKJNntui"},
	{"last-0d", 89, "04fc8b9e62fd84b49a3e70b728e31a34fa21b5fa95141f580fc96a49751f461042d5b4287a2a5816f78bfc86cb0b63b6086da77b7c5a014ab0f51db6524f3d820d", "03fc8b9e62fd84b49a3e70b728e31a34fa21b5fa95141f580fc96a49751f461042", "p256:A_yLnmL9hLSaPnC3KOMaNPohtfqVFB9YD8lqSXUfRhBC"},
	{"leading-X-zero", 379, "04005543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00abb4c85a3d8ea29efaafa24406912dd84d5b14dc32bf656ef6c6bd58a5d943f92", "02005543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00a", "p256:AgBVQ4lK89AO19dAq9vXXJawaHe3h9tfcO6ni5Co18AK"},
	{"last-0a", 753, "045cce8e5c56f245100cb0514fb4c9f165e57c5b4e99ea27070a3befb07c3771559e21ef4c70f7d4de9d8cce92a060656324087155cb2b2e03e45774b02897b60a", "025cce8e5c56f245100cb0514fb4c9f165e57c5b4e99ea27070a3befb07c377155", "p256:AlzOjlxW8kUQDLBRT7TJ8WXlfFtOmeonBwo777B8N3FV"},
}

func publicHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func publicAccept(t *testing.T, i int) string {
	t.Helper()
	g := publicKeyGoldens[i]
	b := publicHex(t, g.native)
	before := bytes.Clone(b)
	got, err := verifier.NativeP256KeyID(b)
	if err != nil || got != g.key {
		t.Fatalf("%s exact key: got %q/%v want %q", g.name, got, err, g.key)
	}
	alg, comp, e := record.KeyBytes(got)
	if e != nil || alg != "p256" || !bytes.Equal(comp, publicHex(t, g.compressed)) || record.ValidateKey(got) != nil {
		t.Fatal("literal compressed coordinate/parity or canonical key validation differs")
	}
	if len(b) != 65 || len(comp) != 33 || len(got) != 49 || !bytes.Equal(before, b) {
		t.Fatal("exact lengths or input immutability")
	}
	return got
}
func publicReject(t *testing.T, b []byte) {
	t.Helper()
	before := bytes.Clone(b)
	got, err := verifier.NativeP256KeyID(b)
	var local *verifier.NativeP256PublicKeyError
	if got != "" || !errors.As(err, &local) || err.Error() != "native_public_key_invalid" {
		t.Fatalf("want empty/fixed typed refusal, got %q/%v", got, err)
	}
	if !bytes.Equal(before, b) {
		t.Fatal("refusal mutated input")
	}
	// A nearby legitimate next call must remain good after each rejected shape.
	publicAccept(t, 0)
}

// Formal identity/normalisation: G/-G share X but name DISTINCT keys; every
// literal point retains all coordinate bytes, including leading zeroes. Text,
// whitespace and variable-width wrappers are not alternate accepted spellings.
func TestNativeP256PublicKeyIdentityNormalization(t *testing.T) {
	seen := map[string]bool{}
	for i, g := range publicKeyGoldens {
		t.Run(g.name, func(t *testing.T) {
			key := publicAccept(t, i)
			if seen[key] {
				t.Fatal("distinct point identity collapsed")
			}
			seen[key] = true
		})
	}
	a, b := publicHex(t, publicKeyGoldens[0].native), publicHex(t, publicKeyGoldens[1].native)
	if !bytes.Equal(a[1:33], b[1:33]) || bytes.Equal(a[33:], b[33:]) || publicKeyGoldens[0].compressed[0:2] == publicKeyGoldens[1].compressed[0:2] {
		t.Fatal("same-X opposite-parity witness not applied")
	}
	for _, b := range [][]byte{append([]byte(" "), a...), append([]byte{0}, a...), []byte(publicKeyGoldens[0].key), []byte(publicKeyGoldens[0].native), []byte("04 " + publicKeyGoldens[0].native[2:])} {
		publicReject(t, b)
	}
	// Dropping either legitimate coordinate's leading zero is a64-byte encoding,
	// not permission to import variable-width values or reject the valid65-byte row.
	for _, i := range []int{3, 6} {
		g := publicKeyGoldens[i]
		v := publicHex(t, g.native)
		j := 1
		if g.name == "leading-Y-zero" {
			j = 33
		}
		if v[j] != 0 {
			t.Fatal("leading zero fixture missing")
		}
		publicAccept(t, i)
		publicReject(t, append(bytes.Clone(v[:j]), v[j+1:]...))
	}
}

// Formal identity/line endings: terminal CR/LF/space and embedded control bytes
// belong to valid POINTS. Rewriting/trimming them must never change the result;
// prepended/appended EOL is forbidden framing, not text to normalize or strip.
func TestNativeP256PublicKeyIdentityLineEndings(t *testing.T) {
	for i, g := range publicKeyGoldens {
		t.Run(g.name, func(t *testing.T) {
			v := publicHex(t, g.native)
			publicAccept(t, i)
			for _, eol := range [][]byte{{13}, {10}, {13, 10}, {10, 13}} {
				publicReject(t, append(bytes.Clone(v), eol...))
				publicReject(t, append(bytes.Clone(eol), v...))
			}
		})
	}
	for _, i := range []int{4, 5, 7} {
		v := publicHex(t, publicKeyGoldens[i].native)
		if v[64] != 32 && v[64] != 13 && v[64] != 10 {
			t.Fatal("valid terminal binary control fixture missing")
		}
		publicAccept(t, i)
	}
	// Together these valid fixtures contain zero, CR, LF and space as binary data.
	var v []byte
	for _, g := range publicKeyGoldens {
		v = append(v, publicHex(t, g.native)...)
	}
	for _, c := range []byte{0, 13, 10, 32} {
		if !bytes.Contains(v, []byte{c}) {
			t.Fatalf("binary fixture lacks %02x", c)
		}
	}
}

// Formal identity/trailing bytes: exact length admits no NUL/space/line/point
// suffix or valid prefix. Every rejection keeps input and next valid call intact.
func TestNativeP256PublicKeyIdentityTrailingBytes(t *testing.T) {
	for i, g := range publicKeyGoldens {
		t.Run(g.name, func(t *testing.T) {
			v := publicHex(t, g.native)
			publicAccept(t, i)
			for _, tail := range [][]byte{{0}, {32}, {9}, {13}, {10}, {13, 10}, {255}, v, []byte("suffix")} {
				publicReject(t, append(bytes.Clone(v), tail...))
			}
		})
	}
}

// Literal positives pin full IDs/coordinates/parity for multiple valid points;
// successful conversion of a different point is not reject-all acceptance.
func TestNativeP256PublicKeyLiteralGoldens(t *testing.T) {
	for i, g := range publicKeyGoldens {
		t.Run(fmt.Sprintf("%s-%d", g.name, g.scalar), func(t *testing.T) { publicAccept(t, i) })
	}
}
