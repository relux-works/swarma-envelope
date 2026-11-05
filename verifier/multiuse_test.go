package verifier_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
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
	for _, use := range []string{"until_expiry", "once"} {
		got := muAuthorize(t, muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, muCaveats(use)), req, nil)
		if got.Code != "accept" || got.Plan["use"] != use {
			t.Fatalf("use=%q: %+v", use, got)
		}
	}
	// B2: a vocabulary-v2 grant without a signed use policy never authorizes.
	v1 := muCaveats("")
	delete(v1, "use")
	v1["lang"] = "caveats/v1"
	for name, caveats := range map[string]any{"none": nil, "caveats-v1": v1} {
		if got := muAuthorize(t, muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, caveats), req, nil); got.Code != "grant_use_missing" {
			t.Fatalf("v2 grant with %s: %+v", name, got)
		}
	}
	// B1: the contract target account-scope/owner:alexis docks.
	owner := map[string]any{"kind": "account-scope", "id": "owner:alexis"}
	if got := muAuthorize(t, muRootGrant(t, agent, []any{"account.manage"}, []any{owner}, muCaveats("until_expiry")), map[string]any{"key": agent, "action": "account.manage", "target": owner}, nil); got.Code != "accept" {
		t.Fatalf("account-scope/owner:alexis: %+v", got)
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
		"two-qualifiers":   {muRootGrant(t, agent, []any{"account.manage"}, []any{map[string]any{"kind": "account-scope", "id": "owner:alexis:x"}}, muCaveats("once")), req, "envelope_malformed"},
		"slash-id":         {muRootGrant(t, agent, []any{"account.manage"}, []any{map[string]any{"kind": "account-scope", "id": "owner/alexis"}}, muCaveats("once")), req, "envelope_malformed"},
		"uppercase-id":     {muRootGrant(t, agent, []any{"account.manage"}, []any{map[string]any{"kind": "account-scope", "id": "Owner:alexis"}}, muCaveats("once")), req, "envelope_malformed"},
		"product-pattern":  {muRootGrant(t, agent, []any{"work.assign"}, []any{map[string]any{"kind": "product", "id": "swarma/*"}}, muCaveats("once")), req, "envelope_malformed"},
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
		{"", "until_expiry", "grant_use_missing", ""},
		{"once", "until_expiry", "grant_not_narrowing", ""},
		{"until_expiry", "", "grant_use_missing", ""},
		{"once", "", "grant_use_missing", ""},
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

// muPublisher returns the publisher key, its owner-root attestation and a
// helper that installs both plus a publisher snapshot issued at issued with
// the given entries into a fixture (removing the root's own snapshot).
func muPublisher(t *testing.T, signer int, domain string, iat, exp string) (*ecdsa.PrivateKey, string, []byte) {
	t.Helper()
	k, key := muP256("publisher")
	pub := elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	priv, issuer := muSeedKey(signer)
	if domain == "" {
		_, domain = muSeedKey(0)
	}
	att := muSign(t, "attestation/1", map[string]any{"type": "attestation/1", "issuer": issuer,
		"subject":   map[string]any{"algorithm": "P-256", "key_id": key, "public_bytes": base64.RawURLEncoding.EncodeToString(pub)},
		"key_class": "revocation-publisher", "purpose": "grant-revocation", "roles": []any{"author"}, "actions": []any{"revocation.sign"},
		"iat": iat, "exp": exp, "binding": map[string]any{"profile": "grant-revocation-1", "domain": domain}}, priv, issuer)
	return k, key, att
}

func muPublisherFixture(t *testing.T, k *ecdsa.PrivateKey, key string, att []byte, issued string, entries []any) func(map[string]any) {
	t.Helper()
	snap := muSignP256(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": key, "issued_at": issued, "complete": true, "entries": entries}, k, key)
	return func(f map[string]any) {
		_, root := muSeedKey(0)
		f["grant_revocation_publisher"] = base64.RawURLEncoding.EncodeToString(att)
		rev := f["revocations"].(map[string]any)
		delete(rev, root)
		rev[key] = map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": base64.RawURLEncoding.EncodeToString(snap)}
	}
}

// Claim (r5 constraints 1, 4, 7): with a pinned owner-root-attested publisher,
// grant-domain revocation is checked against the publisher's snapshot, not the
// root's (the root snapshot is removed). A 59 s old snapshot is accepted and a
// 61 s one refused (fail closed); a snapshot listing the grant revokes it; an
// attestation not signed by the root, for another domain, or longer than 366
// days refuses.
func TestMultiUseRevocationPublisher(t *testing.T) {
	_, agent := muSeedKey(2)
	grant := muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	req := map[string]any{"key": agent, "action": "work.assign", "target": muProduct}
	k, key, att := muPublisher(t, 0, "", "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z")
	if got := muAuthorize(t, grant, req, muPublisherFixture(t, k, key, att, "2026-01-01T00:00:01Z", []any{})); got.Code != "accept" {
		t.Fatalf("59 s publisher snapshot: %+v", got)
	}
	if got := muAuthorize(t, grant, req, muPublisherFixture(t, k, key, att, "2025-12-31T23:59:59Z", []any{})); got.Code != "revocation_unavailable" {
		t.Errorf("61 s publisher snapshot: %+v", got)
	}
	revoked := []any{map[string]any{"kind": "record", "id": muID(t, grant), "from": "2025-12-31T00:00:00Z"}}
	if got := muAuthorize(t, grant, req, muPublisherFixture(t, k, key, att, "2026-01-01T00:00:30Z", revoked)); got.Code != "revoked" {
		t.Errorf("publisher revocation ignored: %+v", got)
	}
	_, other := muSeedKey(1)
	for name, a := range map[string][]byte{
		"not-root-signed": func() []byte {
			_, _, x := muPublisher(t, 1, "", "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z")
			return x
		}(),
		"other-domain": func() []byte {
			_, _, x := muPublisher(t, 0, other, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z")
			return x
		}(),
		"window-367d": func() []byte {
			_, _, x := muPublisher(t, 0, "", "2025-06-01T00:00:00Z", "2026-06-03T00:00:00Z")
			return x
		}(),
	} {
		if got := muAuthorize(t, grant, req, muPublisherFixture(t, k, key, a, "2026-01-01T00:00:30Z", []any{})); got.Code == "accept" {
			t.Errorf("%s publisher attestation accepted: %+v", name, got)
		}
	}
}

// Claim (r5 constraint 1): the publisher key signs nothing but grant-domain
// snapshots: as a grant issuer it refuses signature_profile_invalid, and a
// Mac agent attestation signed by it is not admitted.
func TestMultiUsePublisherPurposeSeparation(t *testing.T) {
	_, agent := muSeedKey(2)
	k, key, att := muPublisher(t, 0, "", "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z")
	install := muPublisherFixture(t, k, key, att, "2026-01-01T00:00:30Z", []any{})
	b := muGrantBody(agent, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	b["issuer"] = key
	byPublisher := muSignP256(t, "grant/1", b, k, key)
	req := map[string]any{"key": agent, "action": "work.assign", "target": muProduct}
	if got := muAuthorize(t, byPublisher, req, install); got.Code != "signature_profile_invalid" {
		t.Errorf("grant signed by publisher: %+v", got)
	}
	mk, mac := muP256("meta")
	pub := elliptic.MarshalCompressed(elliptic.P256(), mk.PublicKey.X, mk.PublicKey.Y)
	_, root := muSeedKey(0)
	macAtt := muSignP256(t, "attestation/1", map[string]any{"type": "attestation/1", "issuer": key,
		"subject":   map[string]any{"algorithm": "P-256", "key_id": mac, "public_bytes": base64.RawURLEncoding.EncodeToString(pub)},
		"key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"},
		"iat": "2025-06-01T00:00:00Z", "exp": "2026-06-01T00:00:00Z",
		"binding": map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1)}}, k, key)
	grant := muRootGrant(t, mac, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	got := muAuthorize(t, grant, map[string]any{"key": mac, "action": "work.assign", "target": muProduct}, func(f map[string]any) {
		install(f)
		id := muID(t, macAtt)
		f["attestations"].(map[string]any)[id] = base64.RawURLEncoding.EncodeToString(macAtt)
		f["agent_attestation_ids"].(map[string]any)[mac] = id
		f["active_generations"].(map[string]any)[mac] = map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "active": true}
	})
	if got.Code == "accept" || root == key {
		t.Errorf("Mac attestation signed by publisher accepted: %+v", got)
	}
}

// muRootSnapshot replaces the grant root's own snapshot with one listing
// entries (root-signed, fresh at the fixture's time).
func muRootSnapshot(t *testing.T, entries []any) func(map[string]any) {
	t.Helper()
	priv, root := muSeedKey(0)
	snap := muSign(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": root, "issued_at": "2026-01-01T00:01:00Z", "complete": true, "entries": entries}, priv, root)
	return func(f map[string]any) {
		row := f["revocations"].(map[string]any)[root].(map[string]any)
		row["snapshot"] = base64.RawURLEncoding.EncodeToString(snap)
	}
}

// Claim (N3, N4): a Mac agent attestation revoked by record or by key in the
// root's snapshot refuses as revoked; generation 0, a malformed MXID and a
// wrong class, roles or actions refuse key_binding_invalid; a grant reaching
// outside the attestation window refuses; the valid attestation is accepted.
func TestMultiUseMacAttestationEdges(t *testing.T) {
	k, mac := muP256("meta")
	pub := elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	rootPriv, root := muSeedKey(0)
	active := map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "active": true}
	att := func(mutate func(map[string]any)) []byte {
		body := map[string]any{"type": "attestation/1", "issuer": root,
			"subject":   map[string]any{"algorithm": "P-256", "key_id": mac, "public_bytes": base64.RawURLEncoding.EncodeToString(pub)},
			"key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"},
			"iat": "2025-06-01T00:00:00Z", "exp": "2026-06-01T00:00:00Z",
			"binding": map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1)}}
		if mutate != nil {
			mutate(body)
		}
		return muSign(t, "attestation/1", body, rootPriv, root)
	}
	install := func(a []byte, act map[string]any, extra func(map[string]any)) func(map[string]any) {
		return func(f map[string]any) {
			id := muID(t, a)
			f["attestations"].(map[string]any)[id] = base64.RawURLEncoding.EncodeToString(a)
			f["agent_attestation_ids"].(map[string]any)[mac] = id
			f["active_generations"].(map[string]any)[mac] = act
			if extra != nil {
				extra(f)
			}
		}
	}
	grant := muRootGrant(t, mac, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	req := map[string]any{"key": mac, "action": "work.assign", "target": muProduct}
	good := att(nil)
	if got := muAuthorize(t, grant, req, install(good, active, nil)); got.Code != "accept" {
		t.Fatalf("valid control: %+v", got)
	}
	from := "2025-12-31T00:00:00Z"
	if got := muAuthorize(t, grant, req, install(good, active, muRootSnapshot(t, []any{map[string]any{"kind": "record", "id": muID(t, good), "from": from}}))); got.Code != "revoked" {
		t.Errorf("attestation revoked by record: %+v", got)
	}
	if got := muAuthorize(t, grant, req, install(good, active, muRootSnapshot(t, []any{map[string]any{"kind": "key", "id": mac, "from": from}}))); got.Code != "revoked" {
		t.Errorf("attestation revoked by key: %+v", got)
	}
	gen0 := map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(0), "active": true}
	cases := map[string]struct {
		a   []byte
		act map[string]any
	}{
		"generation-0": {att(func(b map[string]any) { b["binding"].(map[string]any)["generation"] = int64(0) }), gen0},
		"mxid-no-at":   {att(func(b map[string]any) { b["binding"].(map[string]any)["mxid"] = "meta:example.invalid" }), map[string]any{"profile": "mac-se-1", "mxid": "meta:example.invalid", "generation": int64(1), "active": true}},
		"mxid-space":   {att(func(b map[string]any) { b["binding"].(map[string]any)["mxid"] = "@me ta:example.invalid" }), map[string]any{"profile": "mac-se-1", "mxid": "@me ta:example.invalid", "generation": int64(1), "active": true}},
		"class":        {att(func(b map[string]any) { b["key_class"] = "operator-device" }), active},
		"roles":        {att(func(b map[string]any) { b["roles"] = []any{"approver"} }), active},
		"actions":      {att(func(b map[string]any) { b["actions"] = []any{"grant.sign"} }), active},
		"window-short": {att(func(b map[string]any) { b["exp"] = "2026-01-01T12:00:00Z" }), active},
		"window-late":  {att(func(b map[string]any) { b["iat"] = "2025-12-31T12:00:00Z" }), active},
	}
	for name, c := range cases {
		if got := muAuthorize(t, grant, req, install(c.a, c.act, nil)); got.Code != "key_binding_invalid" {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// Claim: the narrowing rule still guards v1-action chains that carry a
// caveats/v2 policy: a child without the parent's policy refuses as not
// narrowing, beside an accepted child that keeps it.
func TestMultiUseNarrowingV1Actions(t *testing.T) {
	rootPriv, root := muSeedKey(0)
	device, deviceKey := muDeviceKey(t)
	_, agent := muSeedKey(2)
	cred := map[string]any{"kind": "credential", "id": "team/*", "harness": "model-cli", "profile": "dev"}
	for _, c := range []struct {
		child any
		want  string
	}{{muCaveats("until_expiry"), "accept"}, {nil, "grant_not_narrowing"}} {
		pb := muGrantBody(deviceKey, []any{"credential.lease"}, []any{cred}, muCaveats("until_expiry"))
		pb["issuer"], pb["depth"] = root, int64(3)
		parent := muSign(t, "grant/1", pb, rootPriv, root)
		cb := muGrantBody(agent, []any{"credential.lease"}, []any{cred}, nil)
		if c.child != nil {
			cv := muCaveats("until_expiry")
			cv["not_before"], cv["expires"] = "2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z"
			cb["caveats"] = cv
		}
		cb["issuer"], cb["depth"], cb["parent"] = deviceKey, int64(2), muID(t, parent)
		cb["iat"], cb["not_before"], cb["exp"], cb["expires"] = "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z", "2026-01-01T00:02:00Z"
		leaf := muSignP256(t, "grant/1", cb, device, deviceKey)
		v := load(t, "../vectors/swarm-envelope-2/1-positive/PG1.json")
		v.Input["chain"] = []any{base64.RawURLEncoding.EncodeToString(leaf), base64.RawURLEncoding.EncodeToString(parent)}
		if got := derive(t, v); got.Code != c.want {
			t.Errorf("child caveats %v: got %+v want %s", c.child != nil, got, c.want)
		}
	}
}

// muPublisherWith builds the root-signed publisher attestation with a mutation.
func muPublisherWith(t *testing.T, mutate func(map[string]any)) (*ecdsa.PrivateKey, string, []byte) {
	t.Helper()
	k, key := muP256("publisher")
	pub := elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	priv, root := muSeedKey(0)
	body := map[string]any{"type": "attestation/1", "issuer": root,
		"subject":   map[string]any{"algorithm": "P-256", "key_id": key, "public_bytes": base64.RawURLEncoding.EncodeToString(pub)},
		"key_class": "revocation-publisher", "purpose": "grant-revocation", "roles": []any{"author"}, "actions": []any{"revocation.sign"},
		"iat": "2025-06-01T00:00:00Z", "exp": "2026-06-01T00:00:00Z", "binding": map[string]any{"profile": "grant-revocation-1", "domain": root}}
	if mutate != nil {
		mutate(body)
	}
	return k, key, muSign(t, "attestation/1", body, priv, root)
}

// Claim (N9, N10): the publisher attestation admits exactly its profile; each
// field mutation, both window edges, mismatching public bytes and a publisher
// key equal to any other pinned role key refuse, beside the valid control; a
// Mac agent attestation revoked in the publisher snapshot refuses.
func TestMultiUsePublisherAttestationFields(t *testing.T) {
	_, agent := muSeedKey(2)
	grant := muRootGrant(t, agent, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	req := map[string]any{"key": agent, "action": "work.assign", "target": muProduct}
	k, key, good := muPublisherWith(t, nil)
	if got := muAuthorize(t, grant, req, muPublisherFixture(t, k, key, good, "2026-01-01T00:00:30Z", []any{})); got.Code != "accept" {
		t.Fatalf("valid control: %+v", got)
	}
	other, _ := muP256("other")
	otherPub := elliptic.MarshalCompressed(elliptic.P256(), other.PublicKey.X, other.PublicKey.Y)
	for name, mutate := range map[string]func(map[string]any){
		"class":       func(b map[string]any) { b["key_class"] = "service" },
		"purpose":     func(b map[string]any) { b["purpose"] = "registry-revocation" },
		"roles":       func(b map[string]any) { b["roles"] = []any{"approver"} },
		"actions":     func(b map[string]any) { b["actions"] = []any{"grant.sign"} },
		"profile":     func(b map[string]any) { b["binding"].(map[string]any)["profile"] = "grant-revocation-2" },
		"not-started": func(b map[string]any) { b["iat"] = "2026-01-01T00:02:00Z" },
		"ended":       func(b map[string]any) { b["exp"] = "2026-01-01T00:00:30Z" },
		"public-bytes": func(b map[string]any) {
			b["subject"].(map[string]any)["public_bytes"] = base64.RawURLEncoding.EncodeToString(otherPub)
		},
	} {
		_, _, a := muPublisherWith(t, mutate)
		if got := muAuthorize(t, grant, req, muPublisherFixture(t, k, key, a, "2026-01-01T00:00:30Z", []any{})); got.Code == "accept" {
			t.Errorf("%s admitted: %+v", name, got)
		}
	}
	for name, edit := range map[string]func(map[string]any){
		"commit-signing-key":   func(f map[string]any) { f["commit_signing_key"] = key },
		"enrollment-publisher": func(f map[string]any) { f["enrollment_publisher"] = key },
		"service-root":         func(f map[string]any) { f["service_root"] = map[string]any{"key": key, "purpose": int64(5)} },
		"registry-revocation":  func(f map[string]any) { r := f["agent_revocation_root"].(map[string]any); r["key"] = key },
	} {
		install := muPublisherFixture(t, k, key, good, "2026-01-01T00:00:30Z", []any{})
		if got := muAuthorize(t, grant, req, func(f map[string]any) { install(f); edit(f) }); got.Code == "accept" {
			t.Errorf("publisher equal to %s admitted: %+v", name, got)
		}
	}
	mk, mac := muP256("meta")
	mpub := elliptic.MarshalCompressed(elliptic.P256(), mk.PublicKey.X, mk.PublicKey.Y)
	att := muMacAttestation(t, mac, mpub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1)}, 0)
	macGrant := muRootGrant(t, mac, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	revoked := []any{map[string]any{"kind": "record", "id": muID(t, att), "from": "2025-12-31T00:00:00Z"}}
	install := muPublisherFixture(t, k, key, good, "2026-01-01T00:00:30Z", revoked)
	got := muAuthorize(t, macGrant, map[string]any{"key": mac, "action": "work.assign", "target": muProduct}, func(f map[string]any) {
		install(f)
		f["attestations"].(map[string]any)[muID(t, att)] = base64.RawURLEncoding.EncodeToString(att)
		f["agent_attestation_ids"].(map[string]any)[mac] = muID(t, att)
		f["active_generations"].(map[string]any)[mac] = map[string]any{"profile": "mac-se-1", "mxid": "@meta:example.invalid", "generation": int64(1), "active": true}
	})
	if got.Code != "revoked" {
		t.Errorf("Mac attestation revoked by publisher: %+v", got)
	}
}

// Claim (N12): v2 id and MXID boundaries refuse, and every v2 action needs a
// signed policy, beside the valid owner:alexis control.
func TestMultiUseBoundaries(t *testing.T) {
	_, agent := muSeedKey(2)
	req := map[string]any{"key": agent, "action": "work.assign", "target": muProduct}
	scope := func(id string) []any { return []any{map[string]any{"kind": "account-scope", "id": id}} }
	for name, id := range map[string]string{"empty-qualifier": ":alexis", "empty-name": "owner:", "too-long": strings.Repeat("a", 256)} {
		if got := muAuthorize(t, muRootGrant(t, agent, []any{"account.manage"}, scope(id), muCaveats("once")), req, nil); got.Code != "envelope_malformed" {
			t.Errorf("v2 id %s: %+v", name, got)
		}
	}
	if got := muAuthorize(t, muRootGrant(t, agent, []any{"account.manage"}, scope(strings.Repeat("a", 255)), muCaveats("once")), map[string]any{"key": agent, "action": "account.manage", "target": scope(strings.Repeat("a", 255))[0]}, nil); got.Code != "accept" {
		t.Errorf("255-byte id refused: %+v", got)
	}
	for _, action := range []string{"account.manage", "room.membership"} {
		kind := map[string]string{"account.manage": "account-scope", "room.membership": "room-scope"}[action]
		if got := muAuthorize(t, muRootGrant(t, agent, []any{action}, []any{map[string]any{"kind": kind, "id": "x"}}, nil), req, nil); got.Code != "grant_use_missing" {
			t.Errorf("%s without policy: %+v", action, got)
		}
	}
	k, mac := muP256("meta")
	pub := elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	grant := muRootGrant(t, mac, []any{"work.assign"}, []any{muProduct}, muCaveats("until_expiry"))
	for name, mxid := range map[string]string{"colon-first": "@:example.invalid", "colon-last": "@meta:", "too-long": "@" + strings.Repeat("m", 250) + ":ex.in"} {
		b := map[string]any{"profile": "mac-se-1", "mxid": mxid, "generation": int64(1)}
		att := muMacAttestation(t, mac, pub, "2025-06-01T00:00:00Z", "2026-06-01T00:00:00Z", b, 0)
		got := muAuthorize(t, grant, map[string]any{"key": mac, "action": "work.assign", "target": muProduct}, func(f map[string]any) {
			f["attestations"].(map[string]any)[muID(t, att)] = base64.RawURLEncoding.EncodeToString(att)
			f["agent_attestation_ids"].(map[string]any)[mac] = muID(t, att)
			f["active_generations"].(map[string]any)[mac] = map[string]any{"profile": "mac-se-1", "mxid": mxid, "generation": int64(1), "active": true}
		})
		if got.Code != "key_binding_invalid" {
			t.Errorf("mxid %s: %+v", name, got)
		}
	}
}
