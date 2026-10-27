package owneracts_test

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/owneracts"
	"github.com/relux-works/swarma-envelope/record"
)

// This oracle spells the closed schemas and framing separately from Map. The
// shared CCJ serializer is normative, not an independent codec implementation;
// the literal goldens separately constrain its ordinary ASCII output bytes.
func reviewMappingOracle(t *testing.T, in owneracts.MappingInput, class string) owneracts.Mapping {
	t.Helper()
	canonical := func(v any) []byte {
		b, err := record.Canonical(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a := in.Arguments
	a0 := map[string]any{
		"profile": "owner-acts/1", "source_room": a.SourceRoom,
		"source_recipient": a.SourceRecipient, "owner_recipient": a.OwnerRecipient,
		"authority_revision": a.AuthorityRevision, "identity_generation": a.IdentityGeneration,
		"binding_revision": a.BindingRevision,
	}
	switch in.Operation {
	case "owner-dm.bind":
		a0["mirror"] = false
	case "owner-dm.unbind":
		a0["bound_room"] = a.BoundRoom
	case "owner-dm.mirror-enable":
		a0["bound_room"], a0["mirror"] = a.BoundRoom, true
		a0["audience_revision"], a0["audience_digest"] = a.AudienceRevision, a.AudienceDigest
	default:
		t.Fatal("unsupported oracle operation")
	}
	target := map[string]any{"id": in.Identity, "kind": "owner-dm"}
	d := map[string]any{
		"profile": "owner-acts/1", "class": class, "operation": in.Operation,
		"target": target, "owner": in.Owner, "epoch": in.Epoch, "aud": in.Audience,
		"action_id": in.ActionID, "nonce": in.Nonce, "iat": in.IssuedAt, "exp": in.ExpiresAt,
		"confirmed": in.Confirmed, "key": in.Key, "arguments": a0,
	}
	render := append([]byte("owner-acts/1\n"), canonical(d)...)
	a0["text_sha256"] = mappingSHA(render)
	arguments := canonical(a0)
	digest := "sha256:" + mappingSHA(arguments)
	body := canonical(map[string]any{
		"type": "operator-act/1", "aud": in.Audience, "nonce": in.Nonce,
		"iat": in.IssuedAt, "exp": in.ExpiresAt, "operation": in.Operation,
		"target": target, "owner": in.Owner, "epoch": in.Epoch,
		"action_id": in.ActionID, "arguments_digest": digest, "confirmed": in.Confirmed,
	})
	preimage := []byte(mappingDomain + `{"body":` + string(body) + `,"key":"` + in.Key + `","role":"approver","version":"swarm-envelope/2"}`)
	return owneracts.Mapping{Render: render, Arguments: arguments, ArgumentsDigest: digest,
		Body: body, ContentID: "sha256:" + mappingSHA(append([]byte(mappingDomain), body...)), SigningPreimage: preimage}
}

func reviewMappingEqual(t *testing.T, in owneracts.MappingInput, class string) owneracts.Mapping {
	t.Helper()
	want := reviewMappingOracle(t, in, class)
	got := mapped(t, in)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("closed byte mapping differs from schema oracle")
	}
	return got
}

// All three operations preserve owner EOL/Unicode/trailing bytes and every
// opaque argument position. Invalid typed neighbors refuse, never normalize.
// This is not validation of externally delivered text or observed audiences.
func TestReviewMappingIdentityOracle(t *testing.T) {
	for _, c := range []struct{ op, class string }{
		{"owner-dm.bind", "widening"}, {"owner-dm.unbind", "narrowing"}, {"owner-dm.mirror-enable", "widening"},
	} {
		t.Run(c.op, func(t *testing.T) {
			seen := map[string]bool{}
			for _, owner := range []string{"owner", " owner", "owner ", "owner\r", "owner\n", "owner\r\n", "owner\u0085", "owner\u2028", "owner\u2029", "é", "e\u0301", "\ufeffowner", "owner\x00", "owner\x7f", "owner\u200b", "\ufffd"} {
				in := mappingInput(c.op)
				in.Owner = owner
				got := reviewMappingEqual(t, in, c.class)
				if seen[got.ContentID] {
					t.Fatal("distinct owners collapsed")
				}
				seen[got.ContentID] = true
			}
			for field := 0; field < 4; field++ {
				if field == 3 && c.op == "owner-dm.bind" {
					continue
				}
				set := func(in *owneracts.MappingInput, v string) {
					ptrs := []*string{&in.Arguments.SourceRoom, &in.Arguments.SourceRecipient, &in.Arguments.OwnerRecipient, &in.Arguments.BoundRoom}
					*ptrs[field] = v
				}
				for _, value := range []string{"A", "a", "!~", `a"\/:>{}`, strings.Repeat("\\", 255)} {
					in := mappingInput(c.op)
					set(&in, value)
					reviewMappingEqual(t, in, c.class)
				}
				for _, suffix := range []string{" ", "\r", "\n", "\r\n", "\u0085", "\u2028", "\u2029", "\x00", "\x7f", "é"} {
					in := mappingInput(c.op)
					set(&in, "a"+suffix)
					mappingReject(t, in, "mapping_invalid")
				}
			}
		})
	}
}

// Calendar and byte limits are checked at Map, including century leap rules,
// original second precision and valid public-key neighbors. No live time or
// enrollment/uniqueness is inferred from these representation controls.
func TestReviewMappingEndpointNeighbors(t *testing.T) {
	for _, c := range []struct {
		start, end string
		valid      bool
	}{
		{"2000-02-29T23:59:00Z", "2000-03-01T00:01:00Z", true},
		{"2100-02-28T23:59:00Z", "2100-03-01T00:01:00Z", true},
		{"2100-02-29T23:59:00Z", "2100-03-01T00:01:00Z", false},
		{"2000-02-29T23:59:00Z", "2000-03-01T00:01:01Z", false},
		{"1970-01-01T00:00:00Z", "1970-01-01T00:02:00Z", true},
		{"9999-12-31T23:59:58Z", "9999-12-31T23:59:59Z", true},
		{"2026-01-02T24:00:00Z", "2026-01-03T00:00:01Z", false},
		{"2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z", false},
	} {
		in := mappingInput("owner-dm.unbind")
		in.IssuedAt, in.ExpiresAt = c.start, c.end
		if c.valid {
			reviewMappingEqual(t, in, "narrowing")
		} else {
			mappingReject(t, in, "mapping_invalid")
		}
	}
	for _, owner := range []string{strings.Repeat("😀", 63) + "abc", strings.Repeat("\x00", 255)} {
		in := mappingInput("owner-dm.bind")
		in.Owner = owner
		reviewMappingEqual(t, in, "widening")
		in.Owner += "x"
		mappingReject(t, in, "mapping_invalid")
	}
	for _, key := range []string{mappingKey, mappingOtherKey} {
		for _, confirmed := range []bool{false, true} {
			in := mappingInput("owner-dm.mirror-enable")
			in.Key, in.Confirmed, in.ActionID = key, confirmed, "AAAAAAAAAAAAAAAAAAAAAA"
			in.Nonce = in.ActionID
			in.Arguments.AudienceDigest = "sha256:" + strings.Repeat("a", 64)
			reviewMappingEqual(t, in, "widening")
		}
	}
}

// Complete-A admission dominates the 4096 Render bound for these closed
// metadata grammars. Witness lengths are measured by the independent schema
// oracle even when Map correctly refuses; no imaginary 4096 valid control.
func TestReviewMappingRenderBound(t *testing.T) {
	for _, c := range []struct {
		op, class string
		delta     int
	}{
		{"owner-dm.bind", "widening", 384}, {"owner-dm.unbind", "narrowing", 387}, {"owner-dm.mirror-enable", "widening", 393},
	} {
		in := mappingInput(c.op)
		for _, confirmed := range []bool{false, true} {
			in.Confirmed = confirmed
			base := reviewMappingOracle(t, in, c.class)
			want := c.delta
			if confirmed {
				want--
			}
			if len(base.Render)-len(base.Arguments) != want {
				t.Fatal("metadata delta changed")
			}
			in.Owner, in.Identity = strings.Repeat("\x00", 255), strings.Repeat("a", 63)
			maximal := reviewMappingOracle(t, in, c.class)
			if len(maximal.Render)-len(maximal.Arguments) != want+1525+55 {
				t.Fatal("metadata expansion changed")
			}
			reviewMappingEqual(t, in, c.class)
			in.Owner, in.Identity = "owner", "identity"
		}
	}
	for _, c := range []struct{ a, render int }{{2048, 4015}, {2129, 4096}, {2130, 4097}} {
		in := mappingAtArgumentSize(t, c.a)
		in.Owner, in.Identity = strings.Repeat("\x00", 255), strings.Repeat("a", 63)
		want := reviewMappingOracle(t, in, "narrowing")
		if len(want.Arguments) != c.a || len(want.Render) != c.render {
			t.Fatalf("witness got A=%d Render=%d", len(want.Arguments), len(want.Render))
		}
		if c.a <= 2048 {
			reviewMappingEqual(t, in, "narrowing")
		} else {
			mappingReject(t, in, "mapping_too_large")
		}
		t.Logf("complete A=%d Render=%d", c.a, c.render)
	}
}

// Mutating entire returned buffers, appending, failing a later call and then
// remapping cannot change other outputs or prior calls. Struct-copy aliasing
// remains ordinary Go behavior and is not an immutable-plan guarantee.
func TestReviewMappingIndependentBuffers(t *testing.T) {
	in := mappingInput("owner-dm.mirror-enable")
	for i := 0; i < 4; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got := mapped(t, in)
			original := cloneMapping(got)
			bufs := []*[]byte{&got.Render, &got.Arguments, &got.Body, &got.SigningPreimage}
			for j := range *bufs[i] {
				(*bufs[i])[j] = 0
			}
			*bufs[i] = append(*bufs[i], bytes.Repeat([]byte{255}, 64)...)
			wantBufs := [][]byte{original.Render, original.Arguments, original.Body, original.SigningPreimage}
			for j := range bufs {
				if j != i && !bytes.Equal(*bufs[j], wantBufs[j]) {
					t.Fatal("buffer alias")
				}
			}
			bad := in
			bad.Arguments.AudienceRevision = 0
			mappingReject(t, bad, "mapping_invalid")
			if !reflect.DeepEqual(mapped(t, in), original) {
				t.Fatal("later invocation retained mutable output")
			}
			if got.ContentID != original.ContentID || got.ArgumentsDigest != original.ArgumentsDigest {
				t.Fatal("digest alias")
			}
		})
	}
}
