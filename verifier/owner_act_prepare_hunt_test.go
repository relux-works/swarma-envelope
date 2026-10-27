package verifier_test

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Independent selected facts are never filled from raw bytes or a received pin.
// Each counterexample retains an otherwise valid positive neighboring fixture.
func TestPrepareHuntSelection(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		value       any
		code        string
	}{
		{"missing-owner", "owner", nil, "preparation_selection_invalid"},
		{"owner-mismatch", "owner", "other", "preparation_mismatch"},
		{"aud-mismatch", "aud", "owner-acts:ffffffffffffffffffffffffffffffff", "preparation_mismatch"},
		{"epoch-mismatch", "epoch", "epoch:00000000000000000000000000000000", "preparation_mismatch"},
		{"key-substitution", "device", prepareOtherKey, "preparation_mismatch"},
		{"bad-key", "device", "p256:bad", "preparation_selection_invalid"},
		{"issuer-substitution", "issuer", prepareOtherKey, "preparation_selection_invalid"},
		{"root-id", "root_catalog_id", prepareProfileID, "preparation_selection_invalid"},
		{"profile-catalog-id", "profile_catalog_id", prepareRootID, "preparation_selection_invalid"},
		{"pin-substitution", "profile_pin", prepareRootID, "preparation_selection_invalid"},
		{"unsupported-profile", "profile", "owner-acts/2", "preparation_selection_invalid"},
		{"profile-alias", "profile", "Owner-acts/1", "preparation_selection_invalid"},
		{"empty-label", "installation", "", "preparation_selection_invalid"},
		{"over-label", "installation", strings.Repeat("x", 256), "preparation_selection_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			f.enrollment[tc.field] = tc.value
			prepareReject(t, f, tc.code)
		})
	}
	for _, extra := range []string{"class", "presence_current", "current", "policy", "callback", "operation"} {
		t.Run("extra-"+extra, func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			f.enrollment[extra] = "widening"
			prepareReject(t, f, "preparation_selection_invalid")
		})
	}
	for _, field := range []string{"Enrollment", "InstalledProfile", "RootCatalog", "ProfileCatalog"} {
		for _, value := range []any{nil, []any{}, map[string]any{}, "digest-only"} {
			t.Run(fmt.Sprintf("%s/%T", field, value), func(t *testing.T) {
				f := prepareFixtureFor(t, "unbind")
				c := f.context(t)
				reflect.ValueOf(&c).Elem().FieldByName(field).Set(reflect.ValueOf(evidence(t, value)))
				prepareRejectContext(t, f, c, "preparation_selection_invalid")
			})
		}
		t.Run("unavailable-"+field, func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			c := f.context(t)
			reflect.ValueOf(&c).Elem().FieldByName(field).Set(reflect.ValueOf(verifier.Evidence{}))
			prepareRejectContext(t, f, c, "preparation_selection_invalid")
		})
	}
	for _, change := range []func(*prepareFixture){
		func(f *prepareFixture) { f.installed["pin"] = prepareRootID },
		func(f *prepareFixture) { f.installed["profile"] = "owner-acts/2" },
		func(f *prepareFixture) { f.installed["extra"] = true },
		func(f *prepareFixture) {
			f.enrollment["profile_pin"] = prepareRootID
			f.profiles["profiles"].(map[string]any)["owner-acts/1"] = prepareRootID
		},
	} {
		f := prepareFixtureFor(t, "unbind")
		change(&f)
		prepareReject(t, f, "preparation_selection_invalid")
	}
	// Exact independent installed/enrollment/catalog pin transition is usable;
	// these explicit fixture premises do not prove installed build provenance.
	f := prepareFixtureFor(t, "unbind")
	f.enrollment["profile_pin"] = prepareRootID
	f.installed["pin"] = prepareRootID
	f.profiles["profiles"].(map[string]any)["owner-acts/1"] = prepareRootID
	_, d := prepareAccept(t, f)
	if d.ProfilePin != prepareRootID {
		t.Fatal("selected pin not frozen")
	}
	prepareAccept(t, prepareFixtureFor(t, "unbind"))
}

// Every named catalog role must be present; null means an explicitly absent
// optional role, not unavailable catalog. Whole selected catalogs are retained.
// Role separation and other entries cannot be bypassed by a matching catalog ID.
func TestPrepareHuntCatalogs(t *testing.T) {
	for _, n := range strings.Fields("service_root agent_revocation_root operator_root root commit_signing_key enrollment_publisher service_authority service_attestations") {
		t.Run("missing-"+n, func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			delete(f.roots["roles"].(map[string]any), n)
			prepareReject(t, f, "preparation_selection_invalid")
		})
		t.Run("malformed-"+n, func(t *testing.T) {
			f := prepareFixtureFor(t, "unbind")
			f.roots["roles"].(map[string]any)[n] = []any{}
			prepareReject(t, f, "preparation_selection_invalid")
		})
	}
	for _, change := range []func(*prepareFixture){
		func(f *prepareFixture) { f.roots["roles"].(map[string]any)["extra"] = nil },
		func(f *prepareFixture) { f.roots["id"] = prepareProfileID },
		func(f *prepareFixture) { f.profiles["id"] = prepareRootID },
		func(f *prepareFixture) { delete(f.profiles["profiles"].(map[string]any), "owner-acts/1") },
		func(f *prepareFixture) { f.profiles["profiles"].(map[string]any)["other/1"] = nil },
		func(f *prepareFixture) { f.profiles["profiles"].(map[string]any)[""] = preparePin },
		func(f *prepareFixture) {
			f.profiles["profiles"].(map[string]any)[strings.Repeat("x", 256)] = preparePin
		},
		func(f *prepareFixture) { f.roots["roles"].(map[string]any)["root"] = prepareIssuer },
		func(f *prepareFixture) { f.roots["roles"].(map[string]any)["commit_signing_key"] = prepareKey },
		func(f *prepareFixture) { f.roots["roles"].(map[string]any)["enrollment_publisher"] = prepareKey },
		func(f *prepareFixture) {
			f.enrollment["device"] = prepareOtherKey
			f.roots["roles"].(map[string]any)["root"] = prepareOtherKey
		},
	} {
		f := prepareFixtureFor(t, "unbind")
		change(&f)
		prepareReject(t, f, "preparation_selection_invalid")
	}
	f := prepareFixtureFor(t, "unbind")
	roles := f.roots["roles"].(map[string]any)
	service := "ed25519:b2CdQco2XmEi01K78Tg0l7-24Eu5_wHLHlSvQE3mj1M"
	revoker := "ed25519:2dJ3Im2a_cYnF0y9xP2zc5XitBT0maSzUxgZgNKq9f4"
	grant := "ed25519:wue2t1GJeLZTqzYudkzRIhyY11lAzyPXDjsTXgXoIrk"
	roles["service_root"] = map[string]any{"key": service, "purpose": int64(5)}
	roles["agent_revocation_root"] = map[string]any{"key": revoker, "purpose": "registry-revocation", "attestation_root": service}
	roles["root"] = grant
	roles["service_authority"] = map[string]any{"key": grant, "purpose": "grant-service", "owner": "owner"}
	// An explicitly available empty service catalog makes no service-key claim.
	roles["service_attestations"] = map[string]any{}
	f.profiles["profiles"].(map[string]any)["other/1"] = prepareRootID
	prepareAccept(t, f)
	// The public service fixture contains real synthetic signed evidence. Its
	// bytes are retained unchanged/opaque; this leaf makes no signature claim.
	v := load(t, "../vectors/swarm-envelope-2/1-positive/P-CU-receipt-service.json")
	serviceRecords := map[string]any{}
	for k, encoded := range v.Fixture["service_attestations"].(map[string]any) {
		raw, err := b64(encoded)
		if err != nil {
			t.Fatal(err)
		}
		serviceRecords[k] = raw
	}
	roles["service_attestations"] = serviceRecords
	c := f.context(t)
	p, err := verifier.PrepareOwnerAct(f.body, f.args, c)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := p.Snapshot()
	before.Body = bytes.Clone(before.Body)
	before.Arguments = bytes.Clone(before.Arguments)
	before.Render = bytes.Clone(before.Render)
	before.Review = bytes.Clone(before.Review)
	before.SigningPreimage = bytes.Clone(before.SigningPreimage)
	for k, raw := range serviceRecords {
		clear(raw.([]byte))
		retained, err := verifier.PrepareOwnerAct(f.body, f.args, c)
		if err != nil {
			t.Fatal("caller catalog byte alias", err)
		}
		after, _ := retained.Snapshot()
		if !reflect.DeepEqual(before, after) {
			t.Fatal("retained full catalog changed")
		}
		serviceRecords[k] = nil
		prepareReject(t, f, "preparation_selection_invalid")
		serviceRecords[k] = bytes.Repeat([]byte("x"), 8193)
		prepareReject(t, f, "preparation_selection_invalid")
		delete(serviceRecords, k)
	}
	roles["commit_signing_key"] = prepareOtherKey
	prepareAccept(t, f)
	roles["enrollment_publisher"] = prepareOtherKey
	prepareReject(t, f, "preparation_selection_invalid")
	roles["commit_signing_key"], roles["enrollment_publisher"] = nil, nil

	roles["agent_revocation_root"].(map[string]any)["purpose"] = "other"
	prepareReject(t, f, "preparation_selection_invalid")
	roles["agent_revocation_root"].(map[string]any)["purpose"] = "registry-revocation"
	roles["service_root"].(map[string]any)["purpose"] = int64(4)
	prepareReject(t, f, "preparation_selection_invalid")
	roles["service_root"].(map[string]any)["purpose"] = int64(5)
	roles["service_authority"].(map[string]any)["key"] = service
	prepareReject(t, f, "preparation_selection_invalid")
}

// A complete but false text hash/digest, hidden member or body mutation cannot
// be treated as independently checked mapping. No operation aliases escape to
// another consumer handler and class is always static code.
func TestPrepareHuntCompleteAssociation(t *testing.T) {
	for _, change := range []func(*prepareFixture){
		func(f *prepareFixture) {
			f.args = bytes.Replace(f.args, []byte(`"text_sha256":"`), []byte(`"text_sha256":"0`), 1)
		},
		func(f *prepareFixture) {
			i := bytes.Index(f.args, []byte(`"text_sha256":"`)) + 15
			f.args[i] = '0'
			if f.args[i+1] == '0' {
				f.args[i+1] = '1'
			}
			f.body = bytes.Replace(f.body, []byte(prepareDigest(prepareRead(t, "unbind.arguments.json"))), []byte(prepareDigest(f.args)), 1)
		},
		func(f *prepareFixture) {
			f.body = bytes.Replace(f.body, []byte(`"confirmed":false`), []byte(`"confirmed":true`), 1)
		},
		func(f *prepareFixture) {
			f.args = bytes.Replace(f.args, []byte(`"bound_room":"bound"`), []byte(`"bound_room":"other"`), 1)
		},
		func(f *prepareFixture) { f.body = bytes.Replace(f.body, []byte(`"identity"`), []byte(`"other"`), 1) },
		func(f *prepareFixture) {
			f.body = bytes.Replace(f.body, []byte(`"2026-01-02T03:04:05Z"`), []byte(`"2026-01-02T03:04:06Z"`), 1)
		},
	} {
		f := prepareFixtureFor(t, "unbind")
		change(&f)
		code := "preparation_mismatch"
		if bytes.Contains(f.args, []byte(`"text_sha256":"0`)) && len(f.args) == len(prepareRead(t, "unbind.arguments.json"))+1 {
			code = "preparation_invalid"
		}
		prepareReject(t, f, code)
	}
	for _, pair := range [][2]string{
		{`"nonce":"EBESExQVFhcYGRobHB0eHw"`, `"nonce":"AAECAwQFBgcICQoLDA0ODw"`},
		{`"action_id":"AAECAwQFBgcICQoLDA0ODw"`, `"action_id":"EBESExQVFhcYGRobHB0eHw"`},
		{`"exp":"2026-01-02T03:06:05Z"`, `"exp":"2026-01-02T03:06:04Z"`},
	} {
		f := prepareFixtureFor(t, "unbind")
		f.body = bytes.Replace(f.body, []byte(pair[0]), []byte(pair[1]), 1)
		prepareReject(t, f, "preparation_mismatch")
	}

	for _, op := range []string{"revoke", "grant.issue", "launch.approve", "host.change", "owner-dm.UNBIND", "owner-dm.unbind ", "owner-dm/1"} {
		f := prepareFixtureFor(t, "unbind")
		f.body = bytes.Replace(f.body, []byte("owner-dm.unbind"), []byte(op), 1)
		prepareReject(t, f, "preparation_invalid")
	}
	for _, change := range []func(*prepareFixture){
		func(f *prepareFixture) {
			f.body = bytes.Replace(f.body, []byte(`"owner-dm"`), []byte(`"registration"`), 1)
		},
		func(f *prepareFixture) {
			f.args = bytes.Replace(f.args, []byte(`"owner-acts/1"`), []byte(`"owner-acts/2"`), 1)
		},
		func(f *prepareFixture) {
			f.args = bytes.Replace(f.args, []byte(`"binding_revision":12`), []byte(`"binding_revision":"12"`), 1)
		},
		func(f *prepareFixture) {
			f.args = bytes.Replace(f.args, []byte(`"bound_room":"bound"`), []byte(`"bound_room":"é"`), 1)
		},
		func(f *prepareFixture) {
			f.body = bytes.Replace(f.body, []byte(`"owner":"owner"`), []byte(`"owner":"\xff"`), 1)
		},
	} {
		f := prepareFixtureFor(t, "unbind")
		change(&f)
		prepareReject(t, f, "preparation_invalid")
	}
	for _, op := range []string{"bind", "unbind", "mirror-enable"} {
		for _, confirmed := range []string{"true", "false"} {
			f := prepareFixtureFor(t, op)
			f.body = bytes.Replace(f.body, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
			f.render = bytes.Replace(f.render, []byte(`"confirmed":false`), []byte(`"confirmed":`+confirmed), 1)
			f.rehash()
			_, d := prepareAccept(t, f)
			prepareExactData(t, f, d)
		}
	}
}

// The original raw arrays/maps and each returned view can be reused/overwritten
// without altering the plan, another plan or immutable catalog snapshots.
func TestPrepareHuntOwnership(t *testing.T) {
	f := prepareFixtureFor(t, "unbind")
	c := f.context(t)
	p, err := verifier.PrepareOwnerAct(f.body, f.args, c)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := p.Snapshot()
	before.Body = bytes.Clone(before.Body)
	before.Arguments = bytes.Clone(before.Arguments)
	before.Render = bytes.Clone(before.Render)
	before.Review = bytes.Clone(before.Review)
	before.SigningPreimage = bytes.Clone(before.SigningPreimage)
	other, _ := prepareAccept(t, prepareFixtureFor(t, "bind"))
	otherBefore, _ := other.Snapshot()
	f.enrollment["device"] = prepareOtherKey
	f.installed["pin"] = prepareRootID
	f.roots["roles"].(map[string]any)["operator_root"] = nil
	f.profiles["profiles"].(map[string]any)["owner-acts/1"] = nil
	clear(f.body)
	clear(f.args)
	d, _ := p.Snapshot()
	for _, b := range [][]byte{d.Body, d.Arguments, d.Render, d.Review, d.SigningPreimage} {
		clear(b)
	}
	d.Selection = verifier.OwnerActPreparationContext{}
	d.Key = "changed"
	d.ProfilePin = "changed"
	d.Class = "changed"
	d.ContentID = "changed"
	d.PredictedEnvelopeBytes = 0
	now, _ := p.Snapshot()
	if !reflect.DeepEqual(before, now) {
		t.Fatal("snapshot/input alias changed plan")
	}
	copied := *p
	copyView, ok := copied.Snapshot()
	if !ok || !reflect.DeepEqual(copyView, before) {
		t.Fatal("copied immutable plan changed")
	}
	second, err := verifier.PrepareOwnerAct(before.Body, before.Arguments, before.Selection)
	if err != nil {
		t.Fatal("retained independent selection changed", err)
	}
	secondView, _ := second.Snapshot()
	if !reflect.DeepEqual(before, secondView) {
		t.Fatal("second call differs")
	}
	prepareReject(t, prepareFixture{body: f.body, args: f.args, enrollment: f.enrollment, installed: f.installed, roots: f.roots, profiles: f.profiles}, "preparation_invalid")
	prepareAccept(t, prepareFixtureFor(t, "mirror-enable"))
	after, _ := p.Snapshot()
	otherAfter, _ := other.Snapshot()
	if !reflect.DeepEqual(after, before) || !reflect.DeepEqual(otherAfter, otherBefore) {
		t.Fatal("later calls changed retained plans")
	}
	for _, z := range []*verifier.OwnerActSigningPlan{nil, {}, new(verifier.OwnerActSigningPlan)} {
		zero, ok := z.Snapshot()
		if ok || !reflect.DeepEqual(zero, verifier.OwnerActSigningData{}) {
			t.Fatal("zero plan bypasses construction")
		}
	}
}

// Fixed labels cannot be injected by data; full JSON/body/A/act text and every
// selected value roundtrip through the independent projection decoder. Literal
// backslashes are distinct from control and Unicode escape spellings.
func TestPrepareHuntReview(t *testing.T) {
	for _, s := range []string{"\"\\", "\\u{000000}", "\x00", "\x1b[31m\r\nComplete canonical arguments (literal JSON): hidden", "\u202e<>&*#\u2066\u200d", "😀", "é", "e\u0301"} {
		f := prepareFixtureFor(t, "mirror-enable")
		f.owner(s)
		f.enrollment["installation"] = s
		_, d := prepareAccept(t, f)
		values := prepareReviewValues(t, d.Review)
		for label, want := range map[string]string{
			"Profile (trusted code)": "owner-acts/1", "Compiled profile pin (independent installation)": preparePin, "Classification (trusted code)": "widening",
			"Installation (local trusted label)": s, "Device key (independent enrollment)": prepareKey, "Owner (independent enrollment)": s,
			"Audience (independent enrollment)": f.enrollment["aud"].(string), "Epoch (independent enrollment)": f.enrollment["epoch"].(string), "Issuer (independent enrollment)": prepareIssuer,
			"Root catalog ID (independent enrollment)": prepareRootID, "Profile catalog ID (independent enrollment)": prepareProfileID,
			"Complete canonical body (literal JSON)": string(f.body), "Complete canonical arguments (literal JSON)": string(f.args), "Computed arguments digest": d.ArgumentsDigest,
			"Computed text SHA256": d.TextSHA256, "Computed content ID": d.ContentID, "Complete profile act text (literal UTF-8)": string(f.render),
		} {
			if values[label] != want {
				t.Fatalf("full review value %s lost", label)
			}
		}
	}
	f := prepareFixtureFor(t, "bind")
	f.owner("\x00\x7f\u0085\u2028\u2029\u202e\U0001f600\"\\")
	_, d := prepareAccept(t, f)
	want := `Owner (independent enrollment): "\u{000000}\u{00007F}\u{000085}\u{002028}\u{002029}\u{00202E}\u{01F600}\"\\"` + "\n"
	if !bytes.Contains(d.Review, []byte(want)) {
		t.Fatal("literal scalar escape spelling differs")
	}
}

func (f *prepareFixture) argument(name, old, value string) {
	before := []byte(prepareJSON(name) + ":" + prepareJSON(old))
	after := []byte(prepareJSON(name) + ":" + prepareJSON(value))
	f.args = bytes.Replace(f.args, before, after, 1)
	f.render = bytes.Replace(f.render, before, after, 1)
	f.rehash()
}

// Attainable limits retain real valid neighboring inputs. Complete review,
// preimage and envelope caps may be unreachable under tighter field schemas;
// these tests do not pretend fabricated bytes are eligible at those caps.
func TestPrepareHuntBounds(t *testing.T) {
	for _, which := range []string{"body", "arguments"} {
		for _, n := range []int{2049, 8192, 8193} {
			f := prepareFixtureFor(t, "unbind")
			if which == "body" {
				if n < 8192 {
					continue
				}
				f.body = bytes.Repeat([]byte("x"), n)
			} else {
				f.args = bytes.Repeat([]byte("x"), n)
			}
			code := "preparation_too_large"
			if which == "body" && n == 8192 {
				code = "preparation_invalid"
			}
			prepareReject(t, f, code)
		}
	}
	f := prepareFixtureFor(t, "mirror-enable")
	f.owner(strings.Repeat("\x00", 255))
	f.body = bytes.Replace(f.body, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("a", 63)+`"`), 1)
	f.render = bytes.Replace(f.render, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("a", 63)+`"`), 1)
	f.rehash()
	_, d := prepareAccept(t, f)
	prepareExactData(t, f, d)
	if len(d.Body) != 2043 {
		t.Fatal("actual maximum canonical body differs", len(d.Body))
	}
	t.Logf("body maximum fixture body=%d A=%d Render=%d preimage=%d review=%d predicted-envelope=%d", len(d.Body), len(d.Arguments), len(d.Render), len(d.SigningPreimage), len(d.Review), d.PredictedEnvelopeBytes)
	// A can attain2048;2049 is rejected before parsing. Under the exact
	// closed schemas Render = body + A -70 (widening), -69 (narrowing).
	// Thus the overall attainable Render maximum is4021, below4096.
	x := prepareFixtureFor(t, "mirror-enable")
	x.owner(strings.Repeat("\x00", 255))
	x.body = bytes.Replace(x.body, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("a", 63)+`"`), 1)
	x.render = bytes.Replace(x.render, []byte(`"id":"identity"`), []byte(`"id":"`+strings.Repeat("a", 63)+`"`), 1)
	x.argument("source_room", "room", strings.Repeat("\"", 255))
	x.argument("source_recipient", "service", strings.Repeat("\"", 255))
	x.argument("owner_recipient", "owner", strings.Repeat("\"", 255))
	x.argument("bound_room", "bound", strings.Repeat("b", 136))
	_, v := prepareAccept(t, x)
	prepareExactData(t, x, v)
	if len(x.args) != 2048 || len(x.render) != 4021 || len(x.body) != 2043 || len(v.SigningPreimage) != 2186 || v.PredictedEnvelopeBytes != 2348 {
		t.Fatal("attainable maxima differ")
	}
	t.Logf("attainable maxima body=%d A=%d Render=%d preimage=%d review=%d predicted-envelope=%d", len(x.body), len(x.args), len(x.render), len(v.SigningPreimage), len(v.Review), v.PredictedEnvelopeBytes)
	x.argument("bound_room", strings.Repeat("b", 136), strings.Repeat("b", 137))
	if len(x.args) != 2049 {
		t.Fatal("A neighbor not exact")
	}
	prepareReject(t, x, "preparation_too_large")
	//255 raw bytes are admitted for label;256 refuse before display expansion.
	f = prepareFixtureFor(t, "unbind")
	f.enrollment["installation"] = strings.Repeat("\x7f", 255)
	_, d = prepareAccept(t, f)
	prepareReviewValues(t, d.Review)
	f.enrollment["installation"] = strings.Repeat("\x7f", 256)
	prepareReject(t, f, "preparation_selection_invalid")
}

// Alternate raw framing, valid noncanonical escapes and hidden extra members
// refuse at the reused canonical parsers; none become a normalized proposal.
// The original escaped field form remains admitted by the positive fixtures.
func TestPrepareHuntCanonicalNeighbors(t *testing.T) {
	for _, which := range []string{"body", "arguments"} {
		for _, change := range []string{"leading-space", "escaped-value", "extra-member", "duplicate", "raw-invalid-utf8"} {
			t.Run(which+"/"+change, func(t *testing.T) {
				f := prepareFixtureFor(t, "unbind")
				raw := f.body
				if which == "arguments" {
					raw = f.args
				}
				switch change {
				case "leading-space":
					raw = append([]byte(" "), raw...)
				case "escaped-value":
					if which == "body" {
						raw = bytes.Replace(raw, []byte(`"owner":"owner"`), []byte(`"owner":"\u006fwner"`), 1)
					} else {
						raw = bytes.Replace(raw, []byte(`"bound_room":"bound"`), []byte(`"bound_room":"b\u006fund"`), 1)
					}
				case "extra-member":
					raw = append(raw[:len(raw)-1], []byte(`,"zzz":false}`)...)
				case "duplicate":
					raw = append(raw[:len(raw)-1], []byte(`,"aud":false}`)...)
					if which == "arguments" {
						raw = bytes.Replace(raw, []byte(`"aud":false`), []byte(`"profile":false`), 1)
					}
				case "raw-invalid-utf8":
					raw = append([]byte{0xff}, raw...)
				}
				if which == "body" {
					f.body = raw
				} else {
					f.args = raw
				}
				prepareReject(t, f, "preparation_invalid")
			})
		}
	}
	prepareAccept(t, prepareFixtureFor(t, "unbind"))
}
