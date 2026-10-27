package verifier

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/owneracts"
	"github.com/relux-works/swarma-envelope/record"
)

// OwnerActPreparationContext contains independently authenticated, immutable
// in-process snapshots. Enrollment selects the key/owner/installation and exact
// catalogs; InstalledProfile independently pins the installed reviewed build.
// The schemas and provenance obligations are in README.md. Present alone proves
// neither provenance, enrollment eligibility, native installation nor authority.
// No snapshot may be populated from received body/A as its expected source.
type OwnerActPreparationContext struct {
	Enrollment       Evidence
	InstalledProfile Evidence
	RootCatalog      Evidence
	ProfileCatalog   Evidence
}

// OwnerActPreparationError is a fixed local failure, never a wire verdict or
// received data. Codes: preparation_too_large, preparation_invalid,
// preparation_selection_invalid, preparation_mismatch. Failure returns nil.
type OwnerActPreparationError struct{ Code string }

func (e *OwnerActPreparationError) Error() string { return e.Code }

// OwnerActSigningPlan retains an immutable unsigned review proposal. Only
// PrepareOwnerAct constructs a usable plan. A zero value is invalid; copying a
// valid value shares immutable state. It confers no confirmation, presence,
// key-use permission, current rights, signature or effect authority.
type OwnerActSigningPlan struct{ state *ownerActPrepared }
type ownerActPrepared struct{ data OwnerActSigningData }

// OwnerActSigningData is an ordinary detached view, not validation evidence or
// a signing capability. Byte buffers are independent copies on each Snapshot;
// Selection contains the original immutable Evidence snapshots. Render is the
// unchanged delivered profile text; Review is the distinct full review view.
type OwnerActSigningData struct {
	Selection              OwnerActPreparationContext
	Key                    string
	ProfilePin             string
	Class                  string
	ReviewVersion          string
	Body                   []byte
	Arguments              []byte
	Render                 []byte
	Review                 []byte
	ArgumentsDigest        string
	TextSHA256             string
	ContentID              string
	SigningPreimage        []byte
	PredictedEnvelopeBytes int
}

// Snapshot returns owned bytes and immutable selection snapshots. Nil/zero plans
// return zero data and false. Editing returned data cannot alter any plan.
func (p *OwnerActSigningPlan) Snapshot() (OwnerActSigningData, bool) {
	if p == nil || p.state == nil {
		return OwnerActSigningData{}, false
	}
	d := p.state.data
	d.Body = bytes.Clone(d.Body)
	d.Arguments = bytes.Clone(d.Arguments)
	d.Render = bytes.Clone(d.Render)
	d.Review = bytes.Clone(d.Review)
	d.SigningPreimage = bytes.Clone(d.SigningPreimage)
	return d, true
}

const ownerReviewVersion = "owner-act-review/1"
const preparationSelectionCode = "preparation_selection_invalid"

// PrepareOwnerAct validates complete original canonical body and separately
// received canonical A, matches independent protected selection, and derives the
// exact static owner-acts/1 Render, digests, content ID, raw approver preimage and
// complete owner-act-review/1 projection. It neither signs nor calls a consumer
// with fabricated signatures/current facts. Inputs must stay stable during the
// call. Existing raw parsers/mapping/record helpers own their grammar and domain.
//
// Both confirmed assertions remain exact proposed data. Later native integration
// must display this contract, obtain explicit fresh confirmation, recheck the
// exact plan/enrollment/pin/key/time and never silently edit the body. Finalizing,
// native lifecycle and current consumer verification are separate obligations.
func PrepareOwnerAct(rawBody, rawArguments []byte, c OwnerActPreparationContext) (plan *OwnerActSigningPlan, err error) {
	defer func() {
		if x := recover(); x != nil {
			if code, ok := x.(refusal); ok {
				plan = nil
				err = &OwnerActPreparationError{Code: string(code)}
			} else {
				panic(x)
			}
		}
	}()
	// All raw and retained-snapshot bounds precede parsing, copying or rendering.
	need(len(rawBody) <= 8192 && len(rawArguments) <= 8192 && len(rawArguments) <= 2048, "preparation_too_large")
	for _, e := range []Evidence{c.Enrollment, c.InstalledProfile, c.RootCatalog, c.ProfileCatalog} {
		need(e.available && e.identity != nil, preparationSelectionCode)
		need(e.cost <= 1<<20, "preparation_too_large")
	}
	b, bodyErr := owneracts.ParseBody(rawBody)
	need(bodyErr == nil, "preparation_invalid")
	a, argsErr := owneracts.Parse(b.Operation, rawArguments)
	need(argsErr == nil, "preparation_invalid")
	e := exact(c.Enrollment.value, "device owner installation aud epoch issuer root_catalog_id profile_catalog_id profile profile_pin", preparationSelectionCode)
	installed := exact(c.InstalledProfile.value, "profile pin", preparationSelectionCode)
	for _, n := range strings.Fields("device owner installation aud epoch issuer root_catalog_id profile_catalog_id profile profile_pin") {
		s, ok := e[n].(string)
		need(ok && len(s) >= 1 && len(s) <= 255 && utf8.ValidString(s), preparationSelectionCode)
	}
	need(e["profile"] == "owner-acts/1" && installed["profile"] == "owner-acts/1" && isString(installed["pin"]) && record.IsContentID(str(installed["pin"])) && equal(e["profile_pin"], installed["pin"]), preparationSelectionCode)
	for _, n := range []string{"root_catalog_id", "profile_catalog_id", "profile_pin"} {
		need(record.IsContentID(str(e[n])), preparationSelectionCode)
	}
	alg, _, keyErr := record.KeyBytes(str(e["device"]))
	need(keyErr == nil && alg == "p256" && record.ValidateKey(str(e["device"])) == nil, preparationSelectionCode)
	need(record.ValidateKey(str(e["issuer"])) == nil, preparationSelectionCode)
	prepareCatalogs(c, e)
	need(e["owner"] == b.Owner && e["aud"] == b.Audience && e["epoch"] == b.Epoch, "preparation_mismatch")
	in := owneracts.MappingInput{
		Operation: b.Operation, Identity: b.Identity, Owner: b.Owner, Epoch: b.Epoch,
		Audience: b.Audience, ActionID: b.ActionID, Nonce: b.Nonce, IssuedAt: b.IssuedAt,
		ExpiresAt: b.ExpiresAt, Confirmed: b.Confirmed, Key: str(e["device"]),
		Arguments: owneracts.ArgumentInput{SourceRoom: a.SourceRoom, SourceRecipient: a.SourceRecipient,
			AuthorityRevision: a.AuthorityRevision, IdentityGeneration: a.IdentityGeneration,
			BindingRevision: a.BindingRevision, OwnerRecipient: a.OwnerRecipient, BoundRoom: a.BoundRoom,
			Mirror: a.Mirror, AudienceRevision: a.AudienceRevision, AudienceDigest: a.AudienceDigest},
	}
	m, mapErr := owneracts.Map(in)
	if local, ok := mapErr.(*owneracts.MappingError); ok && local.Code == "mapping_too_large" {
		need(false, "preparation_too_large")
	}
	need(mapErr == nil, "preparation_invalid")
	// Full A (including computed text hash) and original body must both match.
	need(bytes.Equal(m.Arguments, rawArguments) && bytes.Equal(m.Body, rawBody) && m.ArgumentsDigest == b.ArgumentsDigest && record.Digest(rawArguments) == b.ArgumentsDigest, "preparation_mismatch")
	need(len(m.Render) <= 4096 && len(m.SigningPreimage) <= 12288, "preparation_too_large")
	class := "widening"
	if b.Operation == "owner-dm.unbind" {
		class = "narrowing"
	}
	size := preparedEnvelopeSize(len(rawBody), len(m.ContentID), len(str(e["device"])))
	need(size <= 8192, "preparation_too_large")
	textHash := strings.TrimPrefix(record.Digest(m.Render), "sha256:")
	need(textHash == a.TextSHA256, "preparation_mismatch")
	review := prepareReview(e, class, rawBody, rawArguments, m.Render, m.ArgumentsDigest, textHash, m.ContentID)
	// Map's buffers are fresh owned allocations and are not exposed directly.
	return &OwnerActSigningPlan{state: &ownerActPrepared{data: OwnerActSigningData{
		Selection: c, Key: str(e["device"]), ProfilePin: str(e["profile_pin"]), Class: class,
		ReviewVersion: ownerReviewVersion, Body: m.Body, Arguments: m.Arguments, Render: m.Render,
		Review: review, ArgumentsDigest: m.ArgumentsDigest, TextSHA256: textHash,
		ContentID: m.ContentID, SigningPreimage: m.SigningPreimage, PredictedEnvelopeBytes: size,
	}}}, nil
}

// These are existing protected catalog shapes, not a policy document parser or
// authenticity/current-rights check. Null optional roles explicitly mean absent.
func prepareCatalogs(c OwnerActPreparationContext, e map[string]any) {
	roots := exact(c.RootCatalog.value, "id roles", preparationSelectionCode)
	profiles := exact(c.ProfileCatalog.value, "id profiles", preparationSelectionCode)
	need(equal(roots["id"], e["root_catalog_id"]) && equal(profiles["id"], e["profile_catalog_id"]), preparationSelectionCode)
	roles := exact(roots["roles"], "service_root agent_revocation_root operator_root root commit_signing_key enrollment_publisher service_authority service_attestations", preparationSelectionCode)
	need(equal(roles["operator_root"], e["issuer"]), preparationSelectionCode)
	pins := obj(profiles["profiles"])
	need(pins != nil && len(pins) > 0, preparationSelectionCode)
	for n, pin := range pins {
		need(len(n) > 0 && len(n) <= 255 && isString(pin) && record.IsContentID(str(pin)), preparationSelectionCode)
	}
	need(equal(pins["owner-acts/1"], e["profile_pin"]), preparationSelectionCode)
	// Validate all named role values; no unknown role silently disappears. Signed
	// service evidence stays opaque here: consumer verification remains mandatory.
	f := facts{}
	for n, v := range roles {
		if v != nil {
			f[n] = v
		}
	}
	for _, n := range []string{"operator_root", "root", "commit_signing_key", "enrollment_publisher"} {
		if v := roles[n]; v != nil {
			prepareRoleKey(v, e["device"])
		}
	}
	if v := roles["service_root"]; v != nil {
		r := exact(v, "key purpose", preparationSelectionCode)
		need(isInt(r["purpose"]) && num(r["purpose"]) == 5, preparationSelectionCode)
		prepareRoleKey(r["key"], e["device"])
	}
	if v := roles["agent_revocation_root"]; v != nil {
		r := exact(v, "key purpose attestation_root", preparationSelectionCode)
		need(r["purpose"] == "registry-revocation" && obj(roles["service_root"]) != nil && equal(r["attestation_root"], obj(roles["service_root"])["key"]), preparationSelectionCode)
		prepareRoleKey(r["key"], e["device"])
	}
	if v := roles["service_authority"]; v != nil {
		r := exact(v, "key purpose owner", preparationSelectionCode)
		need(r["purpose"] == "grant-service" && equal(r["key"], roles["root"]) && isString(r["owner"]) && len(str(r["owner"])) >= 1 && len(str(r["owner"])) <= 255, preparationSelectionCode)
		prepareRoleKey(r["key"], e["device"])
	}
	if v := roles["service_attestations"]; v != nil {
		records, ok := v.(map[string]any)
		need(ok, preparationSelectionCode)
		for k, wire := range records {
			prepareRoleKey(k, e["device"])
			alg, _, keyErr := record.KeyBytes(k)
			raw, ok := wire.([]byte)
			need(keyErr == nil && alg == "ed25519" && ok && len(raw) > 0 && len(raw) <= 8192 && roles["service_authority"] != nil, preparationSelectionCode)
		}
	}
	mapped(func() bool { distinct(f); return true }, "*", preparationSelectionCode)
}
func prepareRoleKey(value, device any) {
	need(isString(value) && record.ValidateKey(str(value)) == nil && !equal(value, device), preparationSelectionCode)
}

// Count closed canonical syntax without constructing an envelope or signature.
// A canonical P256 raw64 signature has exactly86 unpadded base64url characters.
func preparedEnvelopeSize(body, id, key int) int {
	return len(`{"body":`) + body + len(`,"id":"`) + id + len(`","signatures":[{"key":"`) + key + len(`","role":"approver","sig":"`) + 86 + len(`"}],"version":"swarm-envelope/2"}`)
}

type reviewPart struct{ label, value string }

func prepareReview(e map[string]any, class string, body, arguments, render []byte, argumentHash, textHash, id string) []byte {
	parts := []reviewPart{
		{"Profile (trusted code)", "owner-acts/1"}, {"Compiled profile pin (independent installation)", str(e["profile_pin"])}, {"Classification (trusted code)", class},
		{"Installation (local trusted label)", str(e["installation"])}, {"Device key (independent enrollment)", str(e["device"])},
		{"Owner (independent enrollment)", str(e["owner"])}, {"Audience (independent enrollment)", str(e["aud"])}, {"Epoch (independent enrollment)", str(e["epoch"])},
		{"Issuer (independent enrollment)", str(e["issuer"])}, {"Root catalog ID (independent enrollment)", str(e["root_catalog_id"])}, {"Profile catalog ID (independent enrollment)", str(e["profile_catalog_id"])},
		{"Complete canonical body (literal JSON)", string(body)}, {"Complete canonical arguments (literal JSON)", string(arguments)},
		{"Computed arguments digest", argumentHash}, {"Computed text SHA256", textHash}, {"Computed content ID", id},
		{"Complete profile act text (literal UTF-8)", string(render)},
	}
	// Exact escaped length, including labels/separators, is checked before the
	// output allocation. Inputs already bounded/UTF8 validated by shared parsers.
	total := len(ownerReviewVersion) + 1
	for _, p := range parts {
		total += len(p.label) + 2 + reviewQuotedSize(p.value) + 1
	}
	need(total <= 65536, "preparation_too_large")
	var out strings.Builder
	out.Grow(total)
	out.WriteString(ownerReviewVersion + "\n")
	for _, p := range parts {
		out.WriteString(p.label + ": ")
		reviewQuote(&out, p.value)
		out.WriteByte('\n')
	}
	return []byte(out.String())
}
func reviewQuotedSize(s string) int {
	n := 2
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			n += 2
		case r <= 0x20 || r >= 0x7f:
			n += 10
		default:
			n++
		}
	}
	return n
}
func reviewQuote(out *strings.Builder, s string) {
	const hex = "0123456789ABCDEF"
	out.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case r <= 0x20 || r >= 0x7f:
			out.WriteString(`\u{`)
			for shift := 20; shift >= 0; shift -= 4 {
				out.WriteByte(hex[(r>>shift)&15])
			}
			out.WriteByte('}')
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
}
