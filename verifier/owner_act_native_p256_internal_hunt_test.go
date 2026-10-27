package verifier

import (
	"bytes"
	"testing"
)

// Separate post-formal hunt: literal DER integer content bytes that resemble
// text line endings/UTF8 separators remain binary numeric data, with no trim or
// text decoding. These are representation fixtures, not signature equations.
func TestNativeP256HuntBinaryScalars(t *testing.T) {
	for _, scalar := range [][]byte{{10}, {13}, {13, 10}, {0, 0xc2, 0x85}, {0, 0xe2, 0x80, 0xa8}, {0, 0xe2, 0x80, 0xa9}} {
		der := append([]byte{0x30, byte(5 + len(scalar)), 2, byte(len(scalar))}, scalar...)
		der = append(der, 2, 1, 1)
		raw, ok := ownerActNativeP256(der)
		if !ok {
			t.Fatal("binary scalar representation refused")
		}
		want := make([]byte, 64)
		positive := bytes.TrimPrefix(scalar, []byte{0})
		copy(want[32-len(positive):32], positive)
		want[63] = 1
		if !bytes.Equal(raw[:], want) {
			t.Fatal("binary scalar bytes reinterpreted as text")
		}
	}
}
