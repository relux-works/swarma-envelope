package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Original official expected verdicts, not implementation agreement, ground
// oracle correctness; valid arbitrary-length vectors are never reclassified.
func TestOfficialOracle(t *testing.T) {
	var out bytes.Buffer
	if e := checkOfficial("testdata/official/test-vectors.csv", "", &out); e != nil {
		t.Fatal(out.String(), e)
	}
	t.Log(out.String())
}

// Both isolated verdict plants must be APPLIED and fail with the intended
// independently sourced expected/observed mismatch, never a setup failure.
func TestOfficialBidirectionalControls(t *testing.T) {
	for _, tc := range []struct{ plant, index, expected, observed string }{{"valid-refused", "0", "true", "false"}, {"invalid-accepted", "5", "false", "true"}} {
		t.Run(tc.plant, func(t *testing.T) {
			var out bytes.Buffer
			e := checkOfficial("testdata/official/test-vectors.csv", tc.plant, &out)
			want := "official verdict mismatch: index=" + tc.index + " expected=" + tc.expected + " observed=" + tc.observed
			if e == nil || !strings.Contains(out.String(), "control applied: "+tc.plant) || !strings.Contains(out.String(), want) {
				t.Fatal(out.String(), e)
			}
			t.Log(out.String())
		})
	}
}

// Hash pinning fails on changed official bytes before any vector is accepted.
func TestOfficialHashPin(t *testing.T) {
	p := t.TempDir() + "/changed.csv"
	if e := os.WriteFile(p, []byte("changed"), 0644); e != nil {
		t.Fatal(e)
	}
	e := checkOfficial(p, "", &bytes.Buffer{})
	if e == nil || e.Error() != "official CSV hash mismatch" {
		t.Fatal(e)
	}
}

// The independently implemented protocol checker covers every new committed
// operand's hash/domain/attestation semantics and full expected candidate plan.
func TestIndependentBIP340Corpus(t *testing.T) {
	var out bytes.Buffer
	if e := checkVectors("../../vectors/bip340", &out); e != nil {
		t.Fatal(out.String(), e)
	}
	t.Log(out.String())
}
