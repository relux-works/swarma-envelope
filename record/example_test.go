package record_test

import (
	"fmt"
	"github.com/relux-works/waggle/record"
)

// Codec-only provider admission signs no bytes and grants no receiver authority.
func ExampleAdmitSigner() {
	a, e := record.AdmitSigner([]byte("swarma-msg/2\n{}"), record.IdentityPolicy{})
	fmt.Println(a.Tag, e)
	// Output: swarma-msg/2 <nil>
}

// Canonical output uses registrar CCJ-1, including scalar-sorted names.
func ExampleCanonical() {
	b, e := record.Canonical(map[string]any{"b": int64(2), "a": int64(1)})
	fmt.Println(string(b), e)
	// Output: {"a":1,"b":2} <nil>
}
