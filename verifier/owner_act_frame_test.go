package verifier_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Literal headers pin byte offsets/endianness separately from the fixture
// builder. Every operation and all five explicitly numbered statuses have full
// independent expected bytes. Signatures are software test equations only.
func TestOwnerActFrameLiteralGoldens(t *testing.T) {
	c, s := frameIDs()
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		f := prepareFixtureFor(t, op)
		raw := frameRequest(f.body, f.args, c, s)
		frameAccept(t, raw, f.body, f.args, c, s)
		r, wire := frameSigned(t, f)
		out := frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
		if op == "bind" {
			// Original literal files: body454 (0x1c6), A267 (0x10b), wire759
			// (0x2f7). No expected length is read back from the product frame.
			h, err := hex.DecodeString("5345414354303031" +
				"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
				"fffefdfcfbfaf900f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
				"000001c60000010b")
			if err != nil || len(h) != 80 || !bytes.Equal(raw[:80], h) || len(raw) != 801 || !bytes.Equal(raw[80:534], f.body) || !bytes.Equal(raw[534:], f.args) {
				t.Fatal("literal request header/offsets differ")
			}
			h = append([]byte("SEOUT001"), c[:]...)
			h = append(h, 0, 0, 0, 0, 0, 0, 2, 0xf7)
			if len(out) != 807 || !bytes.Equal(out[:48], h) || !bytes.Equal(out[48:], wire) {
				t.Fatal("literal success header/offsets differ")
			}
		}
	}
	for _, tc := range []struct {
		status verifier.OwnerActResultStatus
		number byte
	}{
		{verifier.OwnerActResultRejected, 1}, {verifier.OwnerActResultCanceled, 2}, {verifier.OwnerActResultBusy, 3}, {verifier.OwnerActResultUnavailable, 4},
	} {
		if uint32(tc.status) != uint32(tc.number) {
			t.Fatal("status numbering differs")
		}
		out := frameResultAccept(t, c, tc.status, nil, nil)
		want := append([]byte("SEOUT001"), c[:]...)
		want = append(want, 0, 0, 0, tc.number, 0, 0, 0, 0)
		if len(out) != 48 || !bytes.Equal(out, want) {
			t.Fatal("literal nonzero status/payload differs")
		}
	}
	if uint32(verifier.OwnerActResultSuccess) != 0 {
		t.Fatal("success status differs")
	}
}

// Every header prefix, every changed magic byte and declared length edge is
// rejected without a partial result or mutation; valid next-call controls are
// in frameReject. UINT32_MAX cases are arithmetic attacks, not valid shapes.
func TestOwnerActFrameHeaderBounds(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	c, s := frameIDs()
	good := frameRequest(f.body, f.args, c, s)
	frameReject(t, nil)
	for n := 0; n < 80; n++ {
		t.Run(fmt.Sprintf("header-prefix-%d", n), func(t *testing.T) { frameReject(t, good[:n]) })
	}
	for i := 0; i < 8; i++ {
		b := bytes.Clone(good)
		b[i] ^= 1
		frameReject(t, b)
	}
	for _, magic := range []string{"SEACT000", "SEACT002", "seact001", "SEOUT001"} {
		b := bytes.Clone(good)
		copy(b[:8], magic)
		frameReject(t, b)
	}
	frameReject(t, good[:80])
	for _, lengths := range [][2]uint32{
		{0, uint32(len(f.args))}, {uint32(len(f.body)), 0},
		{8193, 1}, {1, 8193}, {1, 2049}, {0xffffffff, 1}, {1, 0xffffffff}, {0xffffffff, 0xffffffff},
		{0x80000000, 0x80000000}, {0xfffffff0, 0x20},
		{uint32(len(f.body) - 1), uint32(len(f.args))}, {uint32(len(f.body) + 1), uint32(len(f.args))},
		{uint32(len(f.body)), uint32(len(f.args) - 1)}, {uint32(len(f.body)), uint32(len(f.args) + 1)},
		{uint32(len(f.args)), uint32(len(f.body))},
	} {
		b := bytes.Clone(good)
		copy(b[72:76], frameU32(lengths[0]))
		copy(b[76:80], frameU32(lengths[1]))
		frameReject(t, b)
	}
	b := bytes.Clone(good)
	copy(b[72:76], []byte{byte(len(f.body)), byte(len(f.body) >> 8), 0, 0})
	copy(b[76:80], []byte{byte(len(f.args)), byte(len(f.args) >> 8), 0, 0})
	frameReject(t, b)
	for _, n := range []int{80, 81, 82, 16464, 16465} {
		b := make([]byte, n)
		copy(b, good)
		frameReject(t, b)
	}
	for _, lengths := range [][2]uint32{{1, 1}, {8192, 1}, {1, 2048}, {8192, 8192}, {8193, 1}, {1, 8193}} {
		// Real allocated payloads reach outer caps; their invalid grammar never
		// serves as a valid profile boundary control.
		b := frameRequest(bytes.Repeat([]byte{'x'}, int(lengths[0])), bytes.Repeat([]byte{'x'}, int(lengths[1])), c, s)
		frameReject(t, b)
	}
}

// The frame delegates all text semantics to unchanged owneracts parsers. These
// exact local refusals are syntax/schema evidence, not key/digest/rights checks.
func TestOwnerActFrameStrictParsers(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	c, s := frameIDs()
	for _, which := range []string{"body", "arguments"} {
		raw := f.body
		if which == "arguments" {
			raw = f.args
		}
		variants := map[string][]byte{
			"empty": {}, "null": []byte("null"), "array": []byte("[]"), "object": []byte("{}"),
			"BOM": append([]byte{0xef, 0xbb, 0xbf}, raw...), "UTF16": {0xff, 0xfe, '{', 0, '}', 0},
			"leading-space": append([]byte(" "), raw...), "leading-CRLF": append([]byte("\r\n"), raw...),
			"truncated": bytes.Clone(raw[:len(raw)-1]), "trailing-lf": append(bytes.Clone(raw), '\n'),
			"second-value": append(bytes.Clone(raw), []byte("{}")...),
			"unknown":      append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"zzz":false}`)...),
			"depth":        []byte(strings.Repeat(`{"x":`, 17) + "0" + strings.Repeat("}", 17)),
			"array65":      []byte("[" + strings.TrimSuffix(strings.Repeat("0,", 65), ",") + "]"),
		}
		needle := []byte(`"owner":"owner"`)
		field := "owner"
		if which == "arguments" {
			needle = []byte(`"source_room":"room"`)
			field = "source_room"
		}
		for name, token := range map[string]string{"invalid-UTF8": "\"\xff\"", "raw-NUL": "\"a\x00b\"", "wrong-type": "true", "nested": "{}", "null-field": "null", "array-field": "[]", "string8193": prepareJSON(strings.Repeat("x", 8193))} {
			variants[name] = bytes.Replace(raw, needle, []byte(prepareJSON(field)+":"+token), 1)
		}
		variants["duplicate"] = append([]byte(`{"`+field+`":"foreign",`), raw[1:]...)
		variants["escaped-duplicate"] = append([]byte(`{"\u00`+fmt.Sprintf("%02x", field[0])+field[1:]+`":"foreign",`), raw[1:]...)
		variants["escaped-key"] = bytes.Replace(raw, []byte(prepareJSON(field)), []byte(`"\u00`+fmt.Sprintf("%02x", field[0])+field[1:]+`"`), 1)
		variants["missing"] = bytes.Replace(raw, append(bytes.Clone(needle), ','), nil, 1)
		if bytes.Equal(variants["missing"], raw) {
			t.Fatal("missing-field fixture unapplied")
		}
		if which == "body" {
			for _, op := range []string{"owner-dm.UNBIND", "revoke", "launch.approve", "host.change", "owner-dm.unbind "} {
				variants[op] = bytes.Replace(raw, []byte("owner-dm.unbind"), []byte(op), 1)
			}
			variants["target-kind"] = bytes.Replace(raw, []byte(`"kind":"owner-dm"`), []byte(`"kind":"account"`), 1)
		} else {
			variants["unsupported-profile"] = bytes.Replace(raw, []byte("owner-acts/1"), []byte("owner-acts/2"), 1)
			variants["extra-key"] = append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"key":"caller"}`)...)
		}
		for name, b := range variants {
			t.Run(which+"/"+name, func(t *testing.T) {
				body, args := f.body, f.args
				if which == "body" {
					body = b
				} else {
					args = b
				}
				frameReject(t, frameRequest(body, args, c, s))
			})
		}
	}
}

// Grammar-only body/A mismatch is allowed; authentic independent test enrollment
// still makes the REAL PrepareOwnerAct reject its association, with nil plan.
// The protected selection fixture is not derived from the parsed request.
func TestOwnerActFramePreparationStillRequired(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	c, s := frameIDs()
	selection := f.context(t)
	p, err := verifier.PrepareOwnerAct(f.body, f.args, selection)
	if err != nil || p == nil {
		t.Fatal("nearby independent preparation positive", err)
	}
	args := bytes.Replace(f.args, []byte(`"bound_room":"bound"`), []byte(`"bound_room":"other"`), 1)
	r := frameAccept(t, frameRequest(f.body, args, c, s), f.body, args, c, s)
	p, err = verifier.PrepareOwnerAct(r.Body, r.Arguments, selection)
	var local *verifier.OwnerActPreparationError
	if p != nil || !errors.As(err, &local) || local.Code != "preparation_mismatch" {
		t.Fatal("grammar-only admission bypassed association", err)
	}
	// An otherwise valid foreign owner is also syntax, not protected selection.
	body := bytes.Replace(f.body, []byte(`"owner":"owner"`), []byte(`"owner":"foreign"`), 1)
	r = frameAccept(t, frameRequest(body, f.args, c, s), body, f.args, c, s)
	p, err = verifier.PrepareOwnerAct(r.Body, r.Arguments, selection)
	if p != nil || !errors.As(err, &local) || local.Code != "preparation_mismatch" {
		t.Fatal("request supplied its own owner authority", err)
	}
}

// All opaque bytes, including all-zero IDs, remain data. Synchronous input and
// every returned buffer/cross-call value are independent; plain value copies of
// request structs intentionally share slices, not an immutable-plan promise.
func TestOwnerActFrameOwnership(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	c, s := frameIDs()
	wantB, wantA := bytes.Clone(f.body), bytes.Clone(f.args)
	raw := frameRequest(f.body, f.args, c, s)
	one := frameAccept(t, raw, wantB, wantA, c, s)
	two := frameAccept(t, raw, wantB, wantA, c, s)
	clear(one.Body)
	clear(one.Arguments)
	one.Correlation = [32]byte{}
	one.EnrollmentSelector = [32]byte{}
	frameAccept(t, raw, wantB, wantA, c, s)
	clear(raw)
	if !bytes.Equal(two.Body, wantB) || !bytes.Equal(two.Arguments, wantA) || two.Correlation != c || two.EnrollmentSelector != s {
		t.Fatal("caller/cross-call alias retained")
	}
	for _, ids := range [][2][32]byte{{{}, {}}, {c, s}, {s, c}} {
		frameAccept(t, frameRequest(wantB, wantA, ids[0], ids[1]), wantB, wantA, ids[0], ids[1])
	}
	r, wire := frameSigned(t, f)
	copyResult := *r
	view, _ := r.Bytes()
	clear(view)
	out := frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
	second := frameResultAccept(t, c, verifier.OwnerActResultSuccess, &copyResult, wire)
	clear(out)
	if !bytes.Equal(second, frameExpectedResult(c, 0, wire)) {
		t.Fatal("result buffers alias")
	}
	stored, _ := r.Bytes()
	if !bytes.Equal(stored, wire) {
		t.Fatal("result encoding mutated verified bytes")
	}
	frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
	frameResultAccept(t, [32]byte{}, verifier.OwnerActResultSuccess, r, wire)
}

// No ordinary zero/JSON forged result or inconsistent status can release a
// success/payload. Each rejection leaves genuine immutable bytes unchanged and
// a nearby valid pure encoding usable. Unknown bit patterns are not inferred.
func TestOwnerActFrameResultRefusals(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	r, wire := frameSigned(t, f)
	c, _ := frameIDs()
	var forged verifier.VerifiedOwnerActEnvelope
	if err := json.Unmarshal([]byte(`{"state":{"wire":"unverified"}}`), &forged); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		status verifier.OwnerActResultStatus
		result *verifier.VerifiedOwnerActEnvelope
	}{
		{0, nil}, {0, new(verifier.VerifiedOwnerActEnvelope)}, {0, &forged},
	}
	for _, status := range []verifier.OwnerActResultStatus{1, 2, 3, 4, 5, 255, 0x80000000, 0xffffffff} {
		for _, result := range []*verifier.VerifiedOwnerActEnvelope{r, {}, &forged} {
			cases = append(cases, struct {
				status verifier.OwnerActResultStatus
				result *verifier.VerifiedOwnerActEnvelope
			}{status, result})
		}
		if status > 4 {
			cases = append(cases, struct {
				status verifier.OwnerActResultStatus
				result *verifier.VerifiedOwnerActEnvelope
			}{status, nil})
		}
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			out, err := verifier.EncodeOwnerActResultFrame(c, tc.status, tc.result)
			var local *verifier.OwnerActFrameError
			if out != nil || !errors.As(err, &local) || err.Error() != "frame_invalid" {
				t.Fatalf("want fixed error/nil whole output, got %v %x", err, out)
			}
			stored, _ := r.Bytes()
			if !bytes.Equal(stored, wire) {
				t.Fatal("refusal changed retained result")
			}
			frameResultAccept(t, c, verifier.OwnerActResultSuccess, r, wire)
		})
	}
}
