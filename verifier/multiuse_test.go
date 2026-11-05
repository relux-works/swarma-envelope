package verifier_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
)

// Public test seed i from vectors/keys/README.md: SHA-256("waggle public test seed i").
func muSeedKey(i int) (ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte("waggle public test seed " + string(rune('0'+i))))
	k := ed25519.NewKeyFromSeed(seed[:])
	return k, "ed25519:" + base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

// muP256 derives a synthetic, test-only P-256 key from a label.
func muP256(label string) (*ecdsa.PrivateKey, string) {
	n := elliptic.P256().Params().N
	h := sha256.Sum256([]byte("multi-use test p256 " + label))
	d := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	k := &ecdsa.PrivateKey{D: d}
	k.PublicKey.Curve = elliptic.P256()
	k.PublicKey.X, k.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	return k, "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y))
}

// muSign wraps body as a single-signature envelope signed by an Ed25519 key.
func muSign(t *testing.T, kind string, body map[string]any, priv ed25519.PrivateKey, key string) []byte {
	t.Helper()
	id, err := record.ContentID(kind, body)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := record.SigningPreimage(kind, key, "author", body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := record.Canonical(map[string]any{"body": body, "id": id, "version": "swarm-envelope/2",
		"signatures": []any{map[string]any{"key": key, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, pre))}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func muID(t *testing.T, raw []byte) string {
	t.Helper()
	p, err := record.Parse(raw, 65536, 16)
	if err != nil {
		t.Fatal(err)
	}
	return p.(map[string]any)["id"].(string)
}

func muCaveats(use string) map[string]any {
	return map[string]any{"lang": "caveats/v2", "not_before": "2025-12-31T00:00:00Z", "expires": "2026-01-02T00:00:00Z", "use": use}
}

// muGrantBody is a single root-issued link (depth 0, no parent) inside the
// PG1 fixture's trusted time window and audience.
func muGrantBody(subject string, actions []any, targets []any, caveats any) map[string]any {
	return map[string]any{
		"type": "grant/1", "aud": "service-a", "nonce": "BwcHBwcHBwcHBwcHBwcHBw",
		"iat": "2025-12-31T00:00:00Z", "exp": "2026-01-02T00:00:00Z", "not_before": "2025-12-31T00:00:00Z", "expires": "2026-01-02T00:00:00Z",
		"issuer": "", "subject": subject, "actions": actions, "targets": targets,
		"depth": int64(0), "parent": nil, "min_assurance": map[string]any{"level": "A1", "presence": false}, "caveats": caveats,
	}
}

var muProduct = map[string]any{"kind": "product", "id": "swarma-platform"}

// muAuthorize runs Authorize through the conformance harness with a
// single-link chain, the given request and optional fixture edits.
func muAuthorize(t *testing.T, chain []byte, request map[string]any, edit func(map[string]any)) expected {
	t.Helper()
	v := load(t, "../vectors/swarm-envelope-2/1-positive/PG1.json")
	v.Input["chain"] = []any{base64.RawURLEncoding.EncodeToString(chain)}
	v.Fixture["request"] = request
	if edit != nil {
		edit(v.Fixture)
	}
	return derive(t, v)
}

func muRootGrant(t *testing.T, subject string, actions, targets []any, caveats any) []byte {
	t.Helper()
	priv, root := muSeedKey(0)
	b := muGrantBody(subject, actions, targets, caveats)
	b["issuer"] = root
	return muSign(t, "grant/1", b, priv, root)
}

// Claim: a root-issued vocabulary-v2 grant with caveats/v2 is authorized for
// a covered request and the plan returns the owner-signed use policy; the same
// shape with caveats/v1 or no caveats returns no policy (v1 unchanged).
func TestMultiUseGrantVocabularyV2(t *testing.T) {
	_, agent := muSeedKey(2)
	req := map[string]any{"key": agent, "action": "work.assign", "target": muProduct}
	for use, caveats := range map[string]any{"until_expiry": muCaveats("until_expiry"), "once": muCaveats("once"), "": nil} {
		got := muAuthorize(t, muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, caveats), req, nil)
		if got.Code != "accept" || (got.Plan["use"] != nil && got.Plan["use"] != use) || (use != "" && got.Plan["use"] != use) {
			t.Fatalf("use=%q: %+v", use, got)
		}
	}
	v1 := muCaveats("")
	delete(v1, "use")
	v1["lang"] = "caveats/v1"
	if got := muAuthorize(t, muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, v1), req, nil); got.Code != "accept" || got.Plan["use"] != nil {
		t.Fatalf("caveats/v1 neighbour: %+v", got)
	}
}

// Claim: vocabulary v2 stays closed and paired with its target kinds, and
// caveats/v2 admits only the two policies and no other member.
func TestMultiUseGrantRefusals(t *testing.T) {
	_, agent := muSeedKey(2)
	req := map[string]any{"key": agent, "action": "work.assign", "target": muProduct}
	extra := muCaveats("until_expiry")
	extra["count"] = int64(3)
	cases := map[string]struct {
		grant []byte
		req   map[string]any
		want  string
	}{
		"unknown-policy":   {muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, muCaveats("unlimited")), req, "envelope_malformed"},
		"counter-member":   {muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, extra), req, "envelope_malformed"},
		"unregistered":     {muRootGrant(t, agent, []any{"repository.delete"}, []any{muProduct}, muCaveats("once")), req, "action_unregistered"},
		"kind-mismatch":    {muRootGrant(t, agent, []any{"work.assign"}, []any{map[string]any{"kind": "account-scope", "id": "owner-alexis"}}, muCaveats("once")), req, "grant_target_invalid"},
		"action-uncovered": {muRootGrant(t, agent, []any{"work.accept"}, []any{muProduct}, muCaveats("once")), req, "grant_not_authorized"},
		"target-uncovered": {muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, muCaveats("once")), map[string]any{"key": agent, "action": "work.assign", "target": map[string]any{"kind": "product", "id": "other-platform"}}, "grant_not_authorized"},
		"bad-target-id":    {muRootGrant(t, agent, []any{"account.manage"}, []any{map[string]any{"kind": "account-scope", "id": "owner:alexis"}}, muCaveats("once")), req, "envelope_malformed"},
	}
	for name, c := range cases {
		if got := muAuthorize(t, c.grant, c.req, nil); got.Code != c.want {
			t.Errorf("%s: got %+v want %s", name, got, c.want)
		}
	}
}

// muMacAttestation is an attestation/1 for a P-256 agent key under the Mac
// profile, signed by signer.
func muMacAttestation(t *testing.T, key string, pub []byte, iat, exp string, binding map[string]any, signer int) []byte {
	t.Helper()
	priv, issuer := muSeedKey(signer)
	_, root := muSeedKey(0)
	body := map[string]any{"type": "attestation/1", "issuer": root,
		"subject":   map[string]any{"algorithm": "P-256", "key_id": key, "public_bytes": base64.RawURLEncoding.EncodeToString(pub)},
		"key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"},
		"iat": iat, "exp": exp, "binding": binding}
	return muSign(t, "attestation/1", body, priv, issuer)
}

// Claim: a root-issued grant to a P-256 agent key is authorized when that key
// carries a Mac profile attestation signed by the grant root, inside its
// window, with matching active-generation evidence; each broken premise
// refuses with the key-binding code, beside the valid control.
func TestMultiUseMacAgentProfile(t *testing.T) {
	k, mac := muP256("meta")
	pub := elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	binding := map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1)}
	active := map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "active": true}
	grant := muRootGrant(t, mac, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	req := map[string]any{"key": mac, "action": "work.assign", "target": muProduct}
	with := func(att []byte, act map[string]any) func(map[string]any) {
		return func(f map[string]any) {
			id := muID(t, att)
			f["attestations"].(map[string]any)[id] = base64.RawURLEncoding.EncodeToString(att)
			f["agent_attestation_ids"].(map[string]any)[mac] = id
			if act != nil {
				f["active_generations"].(map[string]any)[mac] = act
			}
		}
	}
	good := muMacAttestation(t, mac, pub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", binding, 0)
	if got := muAuthorize(t, grant, req, with(good, active)); got.Code != "accept" || got.Plan["use"] != "until_expiry" {
		t.Fatalf("valid Mac agent: %+v", got)
	}
	wrongGen := map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(2), "active": true}
	wrongMXID := map[string]any{"profile": "mac-se-1", "mxid": "@other:example.invalid", "generation": int64(1), "active": true}
	inactive := map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "active": false}
	cases := map[string]struct {
		att  []byte
		act  map[string]any
		want string
	}{
		"window-over-366d": {muMacAttestation(t, mac, pub, "2025-06-01T00:00:00Z", "2026-06-03T00:00:00Z", binding, 0), active, "key_binding_invalid"},
		"not-root-signed":  {muMacAttestation(t, mac, pub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", binding, 1), active, "key_binding_invalid"},
		"generation":       {good, wrongGen, "key_binding_invalid"},
		"mxid":             {good, wrongMXID, "key_binding_invalid"},
		"inactive":         {good, inactive, "key_binding_invalid"},
		"no-active":        {good, nil, "key_binding_unavailable"},
		"extra-binding":    {muMacAttestation(t, mac, pub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "uid": int64(5)}, 0), active, "key_binding_invalid"},
	}
	for name, c := range cases {
		got := muAuthorize(t, grant, req, with(c.att, c.act))
		if got.Code == "accept" || (c.want != "" && got.Code != c.want) {
			t.Errorf("%s: got %+v want %s", name, got, c.want)
		}
	}
}

// muDeviceKey is public test key test-6 (vectors/keys/README.md): scalar
// 1 + SHA-256("waggle public test p256 seed") mod (n-1).
func muDeviceKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	n := elliptic.P256().Params().N
	h := sha256.Sum256([]byte("waggle public test p256 seed"))
	d := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	k := &ecdsa.PrivateKey{D: d}
	k.PublicKey.Curve = elliptic.P256()
	k.PublicKey.X, k.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	id := "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y))
	if id != "p256:AtvuKbwrlJKTmC1cFKDUv9lAx4xolphryoTXkRZN0Ayl" {
		t.Fatal("test-6 derivation premise", id)
	}
	return k, id
}

// muSignP256 wraps body signed by a P-256 key as raw64 low-S.
func muSignP256(t *testing.T, kind string, body map[string]any, k *ecdsa.PrivateKey, key string) []byte {
	t.Helper()
	id, err := record.ContentID(kind, body)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := record.SigningPreimage(kind, key, "author", body)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(pre)
	r, s, err := ecdsa.Sign(rand0{}, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s.Sub(n, s)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	raw, err := record.Canonical(map[string]any{"body": body, "id": id, "version": "swarm-envelope/2",
		"signatures": []any{map[string]any{"key": key, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rand0 is a deterministic test-only entropy source; never a production signer.
type rand0 struct{}

func (rand0) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i*7 + 1)
	}
	return len(p), nil
}

// Claim: along a two-link chain a child never drops or widens its parent's
// signed use policy: once under once and once under until_expiry are
// authorized and report the leaf policy; until_expiry under once, no policy
// under until_expiry are refused as not narrowing; a policy under a v1 parent
// is a narrowing and is authorized.
func TestMultiUseUseNarrowing(t *testing.T) {
	rootPriv, root := muSeedKey(0)
	device, deviceKey := muDeviceKey(t)
	_, agent := muSeedKey(2)
	chain := func(parentUse, childUse string) []any {
		cav := func(use string, nb, ex string) any {
			if use == "" {
				return nil
			}
			return map[string]any{"lang": "caveats/v2", "not_before": nb, "expires": ex, "use": use}
		}
		pb := muGrantBody(deviceKey, []any{"work.assign"}, []any{muProduct}, cav(parentUse, "2025-12-31T00:00:00Z", "2026-01-02T00:00:00Z"))
		pb["issuer"], pb["depth"] = root, int64(3)
		parent := muSign(t, "grant/1", pb, rootPriv, root)
		cb := muGrantBody(agent, []any{"work.assign"}, []any{muProduct}, cav(childUse, "2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z"))
		cb["issuer"], cb["depth"], cb["parent"] = deviceKey, int64(2), muID(t, parent)
		cb["iat"], cb["not_before"], cb["exp"], cb["expires"] = "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z", "2026-01-01T00:02:00Z"
		leaf := muSignP256(t, "grant/1", cb, device, deviceKey)
		return []any{base64.RawURLEncoding.EncodeToString(leaf), base64.RawURLEncoding.EncodeToString(parent)}
	}
	req := map[string]any{"key": agent, "action": "work.assign", "target": muProduct}
	for _, c := range []struct{ parent, child, want, use string }{
		{"once", "once", "accept", "once"},
		{"until_expiry", "once", "accept", "once"},
		{"until_expiry", "until_expiry", "accept", "until_expiry"},
		{"", "until_expiry", "accept", "until_expiry"},
		{"once", "until_expiry", "grant_not_narrowing", ""},
		{"until_expiry", "", "grant_not_narrowing", ""},
		{"once", "", "grant_not_narrowing", ""},
	} {
		v := load(t, "../vectors/swarm-envelope-2/1-positive/PG1.json")
		v.Input["chain"] = chain(c.parent, c.child)
		v.Fixture["request"] = req
		got := derive(t, v)
		if got.Code != c.want || (c.want == "accept" && got.Plan["use"] != c.use) {
			t.Errorf("parent=%q child=%q: got %+v want %s/%s", c.parent, c.child, got, c.want, c.use)
		}
	}
}

// Claim: VerifyMessage accepts a message/1 authored by a P-256 key that holds
// a root-signed Mac agent attestation, with a vocabulary-v2 action and target.
// A P-256 author whose declared attestation is not a Mac profile keeps the v0
// refusal (signature_profile_invalid), and a Mac attestation for another key
// is refused.
func TestMultiUseMacMessageAuthor(t *testing.T) {
	k, mac := muP256("meta")
	pub := elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	binding := map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1)}
	active := map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "active": true}
	att := muMacAttestation(t, mac, pub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", binding, 0)
	run := func(author string, attID string, attRaw []byte, signer *ecdsa.PrivateKey) expected {
		v := load(t, "../vectors/swarm-envelope-2/1-positive/PA1.json")
		raw, err := b64(v.Input["envelope"])
		if err != nil {
			t.Fatal(err)
		}
		p, err := record.Parse(raw, 65536, 16)
		if err != nil {
			t.Fatal(err)
		}
		b := p.(map[string]any)["body"].(map[string]any)
		b["author"], b["author_attestation"] = author, attID
		b["action"], b["target"] = "work.assign", muProduct
		v.Input["envelope"] = base64.RawURLEncoding.EncodeToString(muSignP256(t, "message/1", b, signer, author))
		f := v.Fixture
		f["attestations"].(map[string]any)[attID] = base64.RawURLEncoding.EncodeToString(attRaw)
		f["agent_attestation_ids"].(map[string]any)[author] = attID
		f["active_generations"].(map[string]any)[author] = active
		f["known_keys"] = append(f["known_keys"].([]any), author)
		return derive(t, v)
	}
	if got := run(mac, muID(t, att), att, k); got.Code != "accept" {
		t.Fatalf("Mac P-256 author: %+v", got)
	}
	// A non-Mac (Keymaker-shaped) binding for the same P-256 key.
	_, root := muSeedKey(0)
	rootPriv, _ := muSeedKey(0)
	keymaker := muSign(t, "attestation/1", map[string]any{"type": "attestation/1", "issuer": root,
		"subject":   map[string]any{"algorithm": "P-256", "key_id": mac, "public_bytes": base64.RawURLEncoding.EncodeToString(pub)},
		"key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"},
		"iat": "2026-01-01T00:00:00Z", "exp": "2026-01-01T12:00:00Z",
		"binding": map[string]any{"uid": int64(1), "generation": "g", "registration_number": int64(1), "master_epoch": "e", "owner": "o", "path": "p"}}, rootPriv, root)
	if got := run(mac, muID(t, keymaker), keymaker, k); got.Code != "signature_profile_invalid" {
		t.Errorf("P-256 author without Mac profile: %+v", got)
	}
	other, otherKey := muP256("other")
	if got := run(otherKey, muID(t, att), att, other); got.Code == "accept" {
		t.Errorf("Mac attestation for another key accepted: %+v", got)
	}
}
