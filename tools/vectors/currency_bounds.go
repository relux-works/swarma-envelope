package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Transport whitespace preserves signed content while exercising the inclusive
// byte limit independently of schema, signature and profile checks.
func currencyPadded(raw string, size int) string {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) > size {
		panic("invalid byte-bound fixture")
	}
	return b64(append(b, []byte(strings.Repeat(" ", size-len(b)))...))
}

// Each over-limit record competes with a supported opposite-profile candidate.
// The accepted control proves that exactly 8192 bytes still admit that position.
func currencyBoundVectors() {
	for _, pin := range []int{0, 1, 2} {
		fresh := currencyBase2()
		journal := reviewSource("P-CU-journal-upgrade")
		opposite := reviewSource("P-CU-version1")
		if pin != 2 {
			fresh = reviewSource(fmt.Sprintf("P-CU-version%d", pin))
			journal = reviewSource(fmt.Sprintf("P-CU-r1-journal-v%d", pin))
			opposite = currencyBase2()
		}
		for _, position := range []string{"publication", "fresh-checkpoint", "entry", "primary", "conflict"} {
			v := copyVector(journal)
			if position == "publication" || position == "fresh-checkpoint" {
				v = copyVector(fresh)
			}
			if position == "conflict" {
				v.Input["conflict"] = v.Input["checkpoint"]
			}
			pad := func(v *Vector, size int) {
				switch position {
				case "publication":
					xs := v.Input["chain"].([]any)
					xs[0] = currencyPadded(xs[0].(string), size)
				case "entry":
					xs := v.Input["entries"].([]any)
					xs[0] = currencyPadded(xs[0].(string), size)
				case "conflict":
					v.Input["conflict"] = currencyPadded(v.Input["conflict"].(string), size)
				default:
					v.Input["checkpoint"] = currencyPadded(v.Input["checkpoint"].(string), size)
				}
			}
			pad(&v, 8192)
			pair := fmt.Sprintf("P-CU-r2-%s-v%d", position, pin)
			add(pair, "Exactly 8192 received bytes at this position preserve acceptance and the signed content identity.", "", "accept", v)
			v = copyVector(v)
			pad(&v, 8193)
			switch position {
			case "publication", "entry", "conflict":
				v.Input["checkpoint"] = opposite.Input["checkpoint"]
			case "fresh-checkpoint":
				v.Input["chain"] = opposite.Input["chain"]
			case "primary":
				v.Input["conflict"] = opposite.Input["checkpoint"]
			}
			code := "journal_malformed"
			if v.Mode == "freshness" {
				code = "freshness_malformed"
			}
			add(fmt.Sprintf("N-CU-r2-%s-v%d", position, pin), "An 8193-byte input refuses at the byte bound before any opposite-profile candidate can determine the refusal.", pair, code, v)
		}
	}
}
