package verifier_test

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// All eight pin combinations test equality of THREE independent snapshots,
// beside coherent changed-pin and changed-key positives. No native enrollment or
// installed-package provenance is asserted by these ordinary synthetic facts.
func TestReviewPrepareSelectionMatrix(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("pin-%d", mask), func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			if mask&1 != 0 {
				f.enrollment["profile_pin"] = prepareRootID
			}
			if mask&2 != 0 {
				f.installed["pin"] = prepareRootID
			}
			if mask&4 != 0 {
				f.profiles["profiles"].(map[string]any)["owner-acts/1"] = prepareRootID
			}
			if mask == 0 || mask == 7 {
				reviewPrepareOK(t, f)
			} else {
				reviewPrepareNo(t, f, f.context(t), "preparation_selection_invalid")
			}
		})
	}
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		t.Run("coherent-key-"+op, func(t *testing.T) {
			f := prepareFixtureFor(t, op)
			f.enrollment["device"] = prepareOtherKey
			f.render = bytes.ReplaceAll(f.render, []byte(prepareKey), []byte(prepareOtherKey))
			f.rehash()
			reviewPrepareOK(t, f)
		})
	}
	for _, field := range strings.Fields("device owner installation aud epoch issuer root_catalog_id profile_catalog_id profile profile_pin") {
		for _, bad := range []any{nil, true, int64(7), []any{}, map[string]any{}} {
			f := prepareFixtureFor(t, "unbind")
			f.enrollment[field] = bad
			reviewPrepareNo(t, f, f.context(t), "preparation_selection_invalid")
		}
	}
	// Unsupported UTF8 cannot enter an Evidence snapshot at its public boundary.
	for _, value := range []any{"\xff", map[string]any{"\xff": preparePin}, map[string]any{"installation": "\xed\xa0\x80"}} {
		e, err := verifier.Present(value)
		if err == nil || e.IsAvailable() {
			t.Fatal("review: invalid UTF8 snapshot admitted")
		}
	}
	reviewPrepareOK(t, prepareFixtureFor(t, "unbind"))
}

func reviewPrepareRoles(t *testing.T, keys []string) prepareFixture {
	t.Helper()
	f := prepareFixtureFor(t, "unbind")
	f.enrollment["issuer"] = keys[2]
	f.roots["roles"] = map[string]any{
		"service_root":          map[string]any{"key": keys[0], "purpose": int64(5)},
		"agent_revocation_root": map[string]any{"key": keys[1], "purpose": "registry-revocation", "attestation_root": keys[0]},
		"operator_root":         keys[2], "root": keys[3], "commit_signing_key": keys[4], "enrollment_publisher": keys[5],
		"service_authority": map[string]any{"key": keys[3], "purpose": "grant-service", "owner": "owner"}, "service_attestations": nil,
	}
	return f
}

// Pairwise collisions preserve all redundant role references, so a rejection
// exercises role separation rather than a stale service/issuer reference. The
// nearby complete six-distinct-role control remains valid, with optional nulls
// distinguished from omitted/unavailable sources by the existing tests.
func TestReviewPrepareRoleSeparation(t *testing.T) {
	keys := []string{"ed25519:b2CdQco2XmEi01K78Tg0l7-24Eu5_wHLHlSvQE3mj1M", "ed25519:2dJ3Im2a_cYnF0y9xP2zc5XitBT0maSzUxgZgNKq9f4", prepareIssuer, "ed25519:wue2t1GJeLZTqzYudkzRIhyY11lAzyPXDjsTXgXoIrk", prepareOtherKey, "ed25519:IUj_CVABHAaYiUFvd6OplZ6sq6L0khQW_GIOF-PhTJo"}
	reviewPrepareOK(t, reviewPrepareRoles(t, keys))
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			t.Run(fmt.Sprintf("roles-%d-%d", i, j), func(t *testing.T) {
				changed := append([]string(nil), keys...)
				changed[j] = changed[i]
				f := reviewPrepareRoles(t, changed)
				reviewPrepareNo(t, f, f.context(t), "preparation_selection_invalid")
			})
		}
	}
	for i := range keys {
		t.Run(fmt.Sprintf("device-role-%d", i), func(t *testing.T) {
			changed := append([]string(nil), keys...)
			changed[i] = prepareKey
			f := reviewPrepareRoles(t, changed)
			reviewPrepareNo(t, f, f.context(t), "preparation_selection_invalid")
		})
	}
}

// Each valid A0 member changes alone while the received body digest is updated
// and old text hash is retained. Full mapping must still refuse the association;
// otherwise the parser/digest pair alone would conceal changed reviewed values.
func TestReviewPrepareCompleteAssociation(t *testing.T) {
	for _, pair := range [][2]string{
		{`"authority_revision":7`, `"authority_revision":8`}, {`"identity_generation":11`, `"identity_generation":12`}, {`"binding_revision":12`, `"binding_revision":13`},
		{`"audience_revision":13`, `"audience_revision":14`}, {`"source_room":"room"`, `"source_room":"Room"`}, {`"source_recipient":"service"`, `"source_recipient":"Service"`},
		{`"owner_recipient":"owner"`, `"owner_recipient":"Owner"`}, {`"bound_room":"bound"`, `"bound_room":"Bound"`},
		{`"audience_digest":"sha256:` + strings.Repeat("0", 64) + `"`, `"audience_digest":"sha256:` + strings.Repeat("1", 64) + `"`},
	} {
		t.Run(pair[0], func(t *testing.T) {
			f := prepareFixtureFor(t, "mirror-enable")
			old := bytes.Clone(f.args)
			f.args = bytes.Replace(f.args, []byte(pair[0]), []byte(pair[1]), 1)
			if bytes.Equal(f.args, old) {
				t.Fatal("review: mutation not applied")
			}
			f.body = bytes.Replace(f.body, []byte(reviewPrepareHash(old)), []byte(reviewPrepareHash(f.args)), 1)
			reviewPrepareNo(t, f, f.context(t), "preparation_mismatch")
		})
	}
	// Original booleans are frozen, not interpreted as authentication evidence.
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		f := prepareFixtureFor(t, op)
		f.body = bytes.Replace(f.body, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1)
		f.render = bytes.Replace(f.render, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1)
		f.rehash()
		reviewPrepareOK(t, f)
	}
}

// Snapshot copies are tested one buffer at a time with detached fixed expected
// fixtures. Each other snapshot and copied plan must retain ALL raw and review
// values after overwrite and later valid/invalid preparations.
func TestReviewPrepareDetachedViews(t *testing.T) {
	f := prepareFixtureFor(t, "mirror-enable")
	p, before := reviewPrepareOK(t, f)
	cp := *p
	for _, field := range []string{"Body", "Arguments", "Render", "Review", "SigningPreimage"} {
		t.Run(field, func(t *testing.T) {
			view, _ := p.Snapshot()
			v := reflect.ValueOf(&view).Elem().FieldByName(field)
			clear(v.Bytes())
			v.SetBytes([]byte("replacement"))
			fresh, ok := p.Snapshot()
			if !ok {
				t.Fatal("review: plan lost")
			}
			reviewPrepareData(t, f, fresh)
			copyView, ok := cp.Snapshot()
			if !ok {
				t.Fatal("review: copy lost")
			}
			reviewPrepareData(t, f, copyView)
			if !reflect.DeepEqual(before, fresh) {
				t.Fatal("review: detached view changed retained fields")
			}
		})
	}
	for _, field := range []string{"Enrollment", "InstalledProfile", "RootCatalog", "ProfileCatalog"} {
		view, _ := p.Snapshot()
		reflect.ValueOf(&view.Selection).Elem().FieldByName(field).Set(reflect.ValueOf(verifier.Evidence{}))
		reviewPrepareNo(t, f, view.Selection, "preparation_selection_invalid")
		fresh, _ := p.Snapshot()
		reviewPrepareData(t, f, fresh)
	}
	bad := prepareFixtureFor(t, "unbind")
	bad.body = append(bad.body, 0)
	reviewPrepareNo(t, bad, bad.context(t), "preparation_invalid")
	reviewPrepareOK(t, prepareFixtureFor(t, "bind"))
	fresh, _ := p.Snapshot()
	reviewPrepareData(t, f, fresh)
}

// Full review decoding covers all C0, DEL, ordinary punctuation, space and
// selected Unicode scalar boundaries; literal escape-like values remain data.
// The joint maximum uses different field bytes from producer witnesses and
// admits false/true neighbors; declared unreachable caps are not fake positives.
func TestReviewPrepareProjectionAndBounds(t *testing.T) {
	values := []string{`\u{000020}`, `\u{01F600}`, "\u00ad\u034f\u061c\u2066\u2069\ufe0f", "\U00010000\U0010ffff"}
	for i := 0; i <= 127; i++ {
		values = append(values, string(rune(i)))
	}
	for _, s := range values {
		f := prepareFixtureFor(t, "bind")
		f.owner(s)
		f.enrollment["installation"] = s
		reviewPrepareOK(t, f)
	}
	f := prepareFixtureFor(t, "mirror-enable")
	f.owner(strings.Repeat("\x01", 255))
	f.enrollment["installation"] = strings.Repeat(" ", 255)
	f.body = bytes.Replace(f.body, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("z", 63)+`"`), 1)
	f.render = bytes.Replace(f.render, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("z", 63)+`"`), 1)
	f.rehash()
	f.argument("source_room", "room", strings.Repeat("\\", 255))
	f.argument("source_recipient", "service", strings.Repeat("\\", 255))
	f.argument("owner_recipient", "owner", strings.Repeat("\\", 255))
	f.argument("bound_room", "bound", strings.Repeat("q", 136))
	_, d := reviewPrepareOK(t, f)
	if len(d.Body) != 2043 || len(d.Arguments) != 2048 || len(d.Render) != 4021 || len(d.SigningPreimage) != 2186 || d.PredictedEnvelopeBytes != 2348 || len(d.Review) >= 28000 {
		t.Fatal("review: independent joint maximum differs")
	}
	t.Logf("joint maxima body=%d A=%d Render=%d preimage=%d envelope=%d review=%d", len(d.Body), len(d.Arguments), len(d.Render), len(d.SigningPreimage), d.PredictedEnvelopeBytes, len(d.Review))
	f.body = bytes.Replace(f.body, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1)
	f.render = bytes.Replace(f.render, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1)
	f.rehash()
	_, d = reviewPrepareOK(t, f)
	if len(d.Body) != 2042 || len(d.Render) != 4020 || len(d.SigningPreimage) != 2185 || d.PredictedEnvelopeBytes != 2347 {
		t.Fatal("review: valid true maximum neighbor differs")
	}
	f.argument("bound_room", strings.Repeat("q", 136), strings.Repeat("q", 137))
	reviewPrepareNo(t, f, f.context(t), "preparation_too_large")
}
