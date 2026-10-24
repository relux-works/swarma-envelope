package verifier_test

import (
	"github.com/relux-works/waggle/internal/apicheck"
	"testing"
)

// Exported names, fields and methods must match the reviewed inventory.
// This check does not prove behavior or approve an API change.
func TestAPISurface(t *testing.T) { apicheck.Check(t) }
