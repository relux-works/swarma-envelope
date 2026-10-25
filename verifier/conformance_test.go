package verifier_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/waggle/record"
	"github.com/relux-works/waggle/verifier"
)

type vector struct {
	ID       string         `json:"id"`
	Positive string         `json:"positive_control"`
	Mode     string         `json:"mode"`
	Input    map[string]any `json:"input"`
	Fixture  map[string]any `json:"fixture"`
	Expected expected       `json:"expected"`
}
type expected struct {
	Code string         `json:"code"`
	Plan map[string]any `json:"plan"`
}

func load(t *testing.T, path string) vector {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v vector
	if e = d.Decode(&v); e != nil {
		t.Fatal(e)
	}
	v.Input = normalize(v.Input).(map[string]any)
	v.Fixture = normalize(v.Fixture).(map[string]any)
	v.Expected.Plan = normalize(v.Expected.Plan).(map[string]any)
	return v
}
func normalize(v any) any {
	switch x := v.(type) {
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			f, _ := x.Float64()
			return f
		}
		i, _ := x.Int64()
		return i
	case map[string]any:
		for k, v := range x {
			x[k] = normalize(v)
		}
	case []any:
		for i, v := range x {
			x[i] = normalize(v)
		}
	}
	return v
}
func b64(s any) ([]byte, error) {
	text, ok := s.(string)
	if !ok {
		return nil, &record.Error{Code: "envelope_malformed"}
	}
	return record.DecodeBase64(text, -1)
}
func code(err error) string {
	if err == nil {
		return "accept"
	}
	return err.(*record.Error).Code
}
func evidence(t *testing.T, v any) verifier.Evidence {
	t.Helper()
	e, err := verifier.Present(v)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func context(t *testing.T, f map[string]any) verifier.Context {
	t.Helper()
	var c verifier.Context
	slots := map[string]*verifier.Evidence{
		"freshness_anchor": &c.FreshnessAnchor, "witness_read_at": &c.WitnessReadAt, "service_authority": &c.ServiceAuthority, "service_attestations": &c.ServiceAttestations, "registry_owner": &c.RegistryOwner, "journal_witness": &c.JournalWitness, "commit_signing_key": &c.CommitSigningKey, "enrollment_publisher": &c.EnrollmentPublisher, "audience": &c.Audience, "required_roles": &c.RequiredRoles, "known_keys": &c.AdmittedKeys, "root": &c.GrantRoot, "service_root": &c.ServiceRoot, "agent_revocation_root": &c.AgentRevocationRoot, "operator_root": &c.OperatorRoot, "operator_owner": &c.OperatorOwner, "attestations": &c.Attestations, "agent_attestation_ids": &c.AgentAttestationIDs, "operator_attestations": &c.DeviceAttestations, "active_generations": &c.CurrentGenerations, "revocations": &c.SignedSnapshots, "time": &c.Time, "now": &c.Now, "watermark_available": &c.WatermarkAvailable, "watermark": &c.Watermark, "id_journal_available": &c.IDJournalAvailable, "seen": &c.IDJournal, "replay_available": &c.ReplayAvailable, "used_actions": &c.UsedActions, "signer_facts": &c.SignerFacts, "assurance": &c.Assurance, "delivery": &c.Delivery, "binding": &c.ActBinding}
	// Fixture transport encodes bytes as base64url; production snapshot values
	// carry raw bytes. Invalid fixture encodings retain a wrong-typed marker so
	// the library, at the consuming row, produces the required invalid refusal.
	convert := func(v any) any {
		if v == nil {
			return nil
		}
		if b, e := b64(v); e == nil {
			return b
		}
		return v
	}
	for name, slot := range slots {
		v, ok := f[name]
		if !ok {
			continue
		}
		if name == "service_attestations" || name == "attestations" || name == "operator_attestations" || name == "seen" {
			if m, ok := v.(map[string]any); ok {
				n := map[string]any{}
				for k, b := range m {
					n[k] = convert(b)
				}
				v = n
			}
		}
		if name == "revocations" {
			if m, ok := v.(map[string]any); ok {
				n := map[string]any{}
				for k, r := range m {
					if row, ok := r.(map[string]any); ok {
						copy := map[string]any{}
						for p, b := range row {
							copy[p] = b
						}
						if b, ok := row["snapshot"]; ok {
							copy["snapshot"] = convert(b)
						}
						n[k] = copy
					} else {
						n[k] = r
					}
				}
				v = n
			}
		}
		if name == "delivery" {
			if m, ok := v.(map[string]any); ok {
				n := map[string]any{}
				for k, b := range m {
					n[k] = b
				}
				if b, ok := m["text"]; ok {
					n["text"] = convert(b)
				}
				v = n
			}
		}
		*slot = evidence(t, v)
	}
	return c
}
func derive(t *testing.T, v vector) expected {
	t.Helper()
	empty := func(c string) expected { return expected{c, map[string]any{}} }
	if v.Mode == "receipt" {
		return deriveReceipt(t, v)
	}
	input := v.Input
	f := v.Fixture
	if v.Mode == "signer" {
		raw, e := b64(input["preimage"])
		if e != nil {
			return empty(code(e))
		}
		p := record.IdentityPolicy{}
		for name, slot := range map[string]*bool{"identity_check": &p.Check, "multi_agent": &p.MultiAgent} {
			if b, ok := f[name]; ok {
				value, ok := b.(bool)
				if !ok {
					p.Invalid = true
				} else {
					*slot = value
				}
			}
		}
		p.CallerKey, _ = f["caller_key_id"].(string)
		p.CallerAttestationID, _ = f["caller_attestation_id"].(string)
		a, e := record.AdmitSigner(raw, p)
		if e != nil {
			return empty(code(e))
		}
		return expected{"accept", map[string]any{"tag": a.Tag, "preimage_sha256": a.PreimageSHA256}}
	}
	if v.Mode == "domain" {
		tag, _ := f["expected_tag"].(string)
		if !record.Registered(tag) {
			return empty("domain_unknown")
		}
		raw, e := b64(input["preimage"])
		if e != nil {
			return empty(code(e))
		}
		sig, e := b64(input["sig"])
		if e != nil {
			return empty(code(e))
		}
		key, _ := input["key"].(string)
		if e = record.CheckDomain(raw, tag, key, sig); e != nil {
			return empty(code(e))
		}
		return expected{"accept", map[string]any{"tag": tag, "key": key}}
	}
	lib := verifier.New(context(t, f))
	var r verifier.Result
	if v.Mode == "freshness" || v.Mode == "freshness-reanchor" {
		var chain [][]byte
		for _, value := range input["chain"].([]any) {
			raw, e := b64(value)
			if e != nil {
				return empty("freshness_malformed")
			}
			chain = append(chain, raw)
		}
		cp, e := b64(input["checkpoint"])
		if e != nil {
			return empty("freshness_malformed")
		}
		stringsIn := func(value any) []string {
			var out []string
			for _, v := range value.([]any) {
				out = append(out, v.(string))
			}
			return out
		}
		if v.Mode == "freshness-reanchor" {
			if len(chain) != 1 {
				return empty("freshness_malformed")
			}
			r = lib.VerifyFreshnessReanchor(chain[0], cp, stringsIn(input["ids"]), stringsIn(input["keys"]))
		} else {
			r = lib.VerifyFreshness(chain, cp, stringsIn(input["ids"]), stringsIn(input["keys"]))
		}
	} else if v.Mode == "journal" {
		values, _ := input["entries"].([]any)
		raws := make([][]byte, len(values))
		for i, x := range values {
			raw, e := b64(x)
			if e != nil {
				return empty("journal_malformed")
			}
			raws[i] = raw
		}
		cp, e := b64(input["checkpoint"])
		if e != nil {
			return empty("journal_malformed")
		}
		var conflict []byte
		if value, ok := input["conflict"]; ok {
			var err error
			conflict, err = b64(value)
			if err != nil {
				return empty("journal_malformed")
			}
		}
		r = lib.VerifyJournal(raws, cp, conflict)
	} else if v.Mode == "grant" {
		entries, _ := input["chain"].([]any)
		chain := make([][]byte, len(entries))
		for i, x := range entries {
			b, e := b64(x)
			if e != nil {
				return empty(code(e))
			}
			chain[i] = b
		}
		request := verifier.Evidence{}
		if value, ok := f["request"]; ok {
			request = evidence(t, value)
		}
		r = lib.Authorize(chain, request)
	} else {
		raw, e := b64(input["envelope"])
		if e != nil {
			return empty(code(e))
		}
		if v.Mode == "operator" {
			r = lib.VerifyOperator(raw)
		} else {
			r = lib.VerifyMessage(raw)
		}
	}
	b, e := json.Marshal(r.Plan)
	if e != nil {
		t.Fatal(e)
	}
	var plan map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&plan); e != nil {
		t.Fatal(e)
	}
	return expected{r.Code, normalize(plan).(map[string]any)}
}
func namedPaths(t *testing.T, root string) []string {
	t.Helper()
	paths, e := filepath.Glob(filepath.Join(root, "swarm-envelope-2", "*", "*.json"))
	if e != nil {
		t.Fatal(e)
	}
	sort.Strings(paths)
	return paths
}
func runVectors(t *testing.T, paths []string) {
	t.Helper()
	positives := map[string]bool{}
	ids := map[string]bool{}
	for _, p := range paths {
		v := load(t, p)
		if ids[v.ID] {
			t.Fatalf("duplicate id %s", v.ID)
		}
		ids[v.ID] = true
		if v.Expected.Code == "accept" {
			positives[v.ID] = true
		}
	}
	for _, p := range paths {
		v := load(t, p)
		t.Run(v.ID, func(t *testing.T) {
			if v.Expected.Code != "accept" && !positives[v.Positive] {
				t.Fatalf("missing accepted control %s", v.Positive)
			}
			if v.Expected.Code == "accept" && v.Positive != "" {
				t.Fatal("unexpected positive pairing")
			}
			got := derive(t, v)
			if !reflect.DeepEqual(got, v.Expected) {
				t.Fatalf("derived=%+v expected=%+v", got, v.Expected)
			}
		})
	}
}

// All committed named witnesses must retain their exact refusal and plan.
// This is the named subset; TestConformance adds the manifest-bound sweeps.
func TestNamed(t *testing.T) {
	paths := namedPaths(t, "../vectors")
	if len(paths) != 1052 {
		t.Fatalf("named count %d", len(paths))
	}
	runVectors(t, paths)
}

// Independently evaluate all named and generated cases, with every generated
// byte and expected code bound to the COMMITTED manifest and its digest. This
// test and its generator child must run under the host's heavy resource slot.
func TestConformance(t *testing.T) {
	root := os.Getenv("WAGGLE_VECTORS")
	if root == "" {
		root = filepath.Join(t.TempDir(), "corpus")
		goTool := os.Getenv("CURATOR_GO")
		if goTool == "" && runtime.GOROOT() != "" {
			goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
		}
		if goTool == "" {
			var err error
			goTool, err = exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(goTool, "run", "./tools/vectors", "-sweeps", "-out", root)
		cmd.Dir = ".."
		cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("generator: %v\n%s", e, out)
		}
	}
	manifest, e := os.ReadFile("../vectors/swarm-envelope-2/sweeps.tsv")
	if e != nil {
		t.Fatal(e)
	}
	digest, e := os.ReadFile("../vectors/swarm-envelope-2/sweeps.sha256")
	if e != nil {
		t.Fatal(e)
	}
	want := fmt.Sprintf("%x  sweeps.tsv\n", sha256.Sum256(manifest))
	if string(digest) != want {
		t.Fatal("committed manifest digest mismatch")
	}
	generated, e := os.ReadFile(filepath.Join(root, "swarm-envelope-2", "sweeps.tsv"))
	if e != nil || !bytes.Equal(generated, manifest) {
		t.Fatal("generated manifest differs from committed manifest")
	}
	paths := namedPaths(t, root)
	index := map[string]string{}
	for _, p := range paths {
		index[load(t, p).ID] = p
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n") {
		cols := strings.Split(line, "\t")
		if len(cols) != 3 {
			t.Fatal("manifest row")
		}
		raw, e := os.ReadFile(index[cols[0]])
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != cols[2] {
			t.Fatalf("sweep bytes mismatch %s", cols[0])
		}
		if load(t, index[cols[0]]).Expected.Code != cols[1] {
			t.Fatalf("sweep verdict mismatch %s", cols[0])
		}
		count++
	}
	for _, p := range namedPaths(t, "../vectors") {
		base, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := os.ReadFile(index[load(t, p).ID])
		if e != nil || !bytes.Equal(base, actual) {
			t.Fatalf("named corpus bytes mismatch %s", p)
		}
	}
	if count != 1688 || len(paths) != 2740 {
		t.Fatalf("counts named1052 sweeps%d total%d", count, len(paths))
	}
	t.Logf("named=1052 generated=%s total=%d", strconv.Itoa(count), len(paths))
	runVectors(t, paths)
}

// Keep the fixture decoder honest about transport alphabet; it must not silently
// accept padding that production byte APIs do not receive.
func TestFixtureDecoder(t *testing.T) {
	_, e := b64(base64.URLEncoding.EncodeToString([]byte{1}))
	if e == nil {
		t.Fatal("padded fixture accepted")
	}
}
