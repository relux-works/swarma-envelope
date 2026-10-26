package verifier_test

import (
	"fmt"
	"github.com/relux-works/swarma-envelope/verifier"
)

// Missing protected facts cannot authorize an act or populate a plan.
func ExampleVerifier_VerifyOperator() {
	r := verifier.New(verifier.Context{}).VerifyOperator([]byte(`{}`))
	fmt.Println(r.Code, len(r.Plan.IDs), r.Plan.ActionID)
	// Output: envelope_malformed 0
}

// Only stable coarse refusal classes cross the native operator-record boundary.
func ExampleOperatorRecordCode() {
	fmt.Println(verifier.OperatorRecordCode("key_binding_unavailable"))
	fmt.Println(verifier.OperatorRecordCode("act_replay"))
	// Output:
	// operator_record_unavailable
	// operator_record_invalid
}
