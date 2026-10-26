package verifier

import (
	"fmt"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
)

// Evidence is an immutable snapshot. Its zero value explicitly means unavailable,
// never an empty collection. Present(nil) represents available JSON null and is
// still refused wherever a required fact is consumed. Construct with Present.
type Evidence struct {
	available bool
	value     any
	identity  *byte
	cost      int
}

// IsAvailable reports snapshot availability, not validity or authority.
func (e Evidence) IsAvailable() bool { return e.available }

// Present copies a protected value. Supported values are CCJ-shaped maps,
// arrays, strings, booleans, int64, nil and byte slices; int and float64 are
// retained for runtime invalid-provider classification. It rejects unsupported
// Go values, cycles/depth above32 and more than1MiB of snapshot content.
// Signed evidence and journal entries use raw []byte values, never base64 hints.
func Present(value any) (Evidence, error) {
	budget := 1 << 20
	v, err := freeze(value, 0, &budget)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{available: true, value: v, identity: new(byte), cost: (1 << 20) - budget}, nil
}
func freeze(value any, d int, budget *int) (any, error) {
	if d > 32 || *budget < 0 {
		return nil, fmt.Errorf("evidence bounds")
	}
	*budget -= 16
	if *budget < 0 {
		return nil, fmt.Errorf("evidence bounds")
	}
	switch v := value.(type) {
	case nil:
		return nil, nil
	case string:
		*budget -= len(v)
		if !utf8.ValidString(v) || *budget < 0 {
			return nil, fmt.Errorf("evidence string")
		}
		return v, nil
	case bool, int64, int, float64:
		return v, nil
	case []byte:
		if v == nil {
			return nil, nil
		}
		*budget -= len(v)
		if *budget < 0 {
			return nil, fmt.Errorf("evidence bytes")
		}
		return append([]byte{}, v...), nil
	case []any:
		if v == nil {
			return nil, nil
		}
		if len(v) > *budget/16 {
			return nil, fmt.Errorf("evidence array")
		}
		out := make([]any, len(v))
		for i, x := range v {
			n, e := freeze(x, d+1, budget)
			if e != nil {
				return nil, e
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		if v == nil {
			return nil, nil
		}
		if len(v) > *budget/16 {
			return nil, fmt.Errorf("evidence object")
		}
		out := make(map[string]any, len(v))
		for k, x := range v {
			*budget -= len(k)
			if !utf8.ValidString(k) {
				return nil, fmt.Errorf("evidence name")
			}
			n, e := freeze(x, d+1, budget)
			if e != nil {
				return nil, e
			}
			out[k] = n
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported evidence type")
	}
}

// Context contains caller-owned protected facts, resolved before verification.
// Each Evidence uses explicit availability. Object member schemas are described
// in this package's README; these are in-process snapshot values, not a new wire
// or native request grammar. No field is inferred from a received signature.
type Context struct {
	RegistryCurrencyVersion int
	SnapshotJournal         Evidence
	FreshnessReceipt        *FreshnessReceipt
	RequireFreshnessReceipt bool
	FreshnessMarginSeconds  int64
	FreshnessAnchor         Evidence
	WitnessReadAt           Evidence
	ServiceAuthority        Evidence
	ServiceAttestations     Evidence
	RegistryOwner           Evidence
	JournalWitness          Evidence
	CommitSigningKey        Evidence
	EnrollmentPublisher     Evidence
	Audience                Evidence
	RequiredRoles           Evidence
	AdmittedKeys            Evidence
	GrantRoot               Evidence
	ServiceRoot             Evidence
	AgentRevocationRoot     Evidence
	OperatorRoot            Evidence
	OperatorOwner           Evidence
	Attestations            Evidence
	AgentAttestationIDs     Evidence
	DeviceAttestations      Evidence
	CurrentGenerations      Evidence
	SignedSnapshots         Evidence
	Time                    Evidence
	Now                     Evidence
	WatermarkAvailable      Evidence
	Watermark               Evidence
	IDJournalAvailable      Evidence
	IDJournal               Evidence
	ReplayAvailable         Evidence
	UsedActions             Evidence
	SignerFacts             Evidence
	Assurance               Evidence
	Delivery                Evidence
	ActBinding              Evidence
}

// FreshnessReanchorPlan records the explicit continuity waiver. SkippedPublications
// counts positions strictly between the retained anchor and admitted tip.
// Checkpoint IDs bind the corresponding registry heads by content hash.
type FreshnessReanchorPlan struct {
	OldSnapshots               []SnapshotBinding `json:"old_snapshots,omitempty"`
	NewSnapshots               []SnapshotBinding `json:"new_snapshots,omitempty"`
	OldRegistryCurrencyVersion int               `json:"old_registry_currency_version,omitempty"`
	NewRegistryCurrencyVersion int               `json:"new_registry_currency_version,omitempty"`
	Reanchored                 bool              `json:"reanchored"`
	SkippedPublications        int64             `json:"skipped_publications"`
	OldFreshnessID             string            `json:"old_freshness_id"`
	NewFreshnessID             string            `json:"new_freshness_id"`
	OldCheckpointID            string            `json:"old_checkpoint_id"`
	NewCheckpointID            string            `json:"new_checkpoint_id"`
}

// Plan is a candidate persistence transaction, not a committed effect permit.
// Every refusal returns its zero value. IDs retain leaf-first order.
type Plan struct {
	SnapshotJournal *SnapshotJournalState  `json:"snapshot_journal,omitempty"`
	Reanchor        *FreshnessReanchorPlan `json:"reanchor,omitempty"`
	IDs             []string               `json:"ids,omitempty"`
	Watermark       string                 `json:"watermark,omitempty"`
	ActionID        string                 `json:"action_id,omitempty"`
}

// Result holds the exact stable refusal code, or accept plus a candidate plan.
type Result struct {
	FreshnessReceipt *FreshnessReceipt `json:"-"`
	Code             string            `json:"code"`
	Plan             Plan              `json:"plan"`
}

// Verifier holds only immutable snapshots and is safe for concurrent use.
// It does not refresh facts. Callers must re-resolve current facts and serialize
// Commit and the effect as required by the specification.
type Verifier struct{ context Context }

// New binds an immutable context. Missing facts fail when their ordered row is reached.
func New(context Context) Verifier { return Verifier{context: context} }
func (v Verifier) facts() facts {
	c := v.context
	f := facts{"_currencyVersion": c.RegistryCurrencyVersion}
	names := []string{"audience", "required_roles", "known_keys", "root", "service_root", "agent_revocation_root", "operator_root", "operator_owner", "attestations", "agent_attestation_ids", "operator_attestations", "active_generations", "revocations", "time", "now", "watermark_available", "watermark", "id_journal_available", "seen", "replay_available", "used_actions", "signer_facts", "assurance", "delivery", "binding", "service_authority", "service_attestations", "registry_owner", "journal_witness", "commit_signing_key", "enrollment_publisher", "freshness_anchor", "witness_read_at", "snapshot_journal"}
	values := []Evidence{c.Audience, c.RequiredRoles, c.AdmittedKeys, c.GrantRoot, c.ServiceRoot, c.AgentRevocationRoot, c.OperatorRoot, c.OperatorOwner, c.Attestations, c.AgentAttestationIDs, c.DeviceAttestations, c.CurrentGenerations, c.SignedSnapshots, c.Time, c.Now, c.WatermarkAvailable, c.Watermark, c.IDJournalAvailable, c.IDJournal, c.ReplayAvailable, c.UsedActions, c.SignerFacts, c.Assurance, c.Delivery, c.ActBinding, c.ServiceAuthority, c.ServiceAttestations, c.RegistryOwner, c.JournalWitness, c.CommitSigningKey, c.EnrollmentPublisher, c.FreshnessAnchor, c.WitnessReadAt, c.SnapshotJournal}
	for i, e := range values {
		if e.available {
			f[names[i]] = e.value
		}
	}
	return f
}

// OperatorRecordCode maps fine audit reasons to Keymaker's two public refusals.
// An accept returns accept; unavailable verifier/Commit inputs must be passed
// explicitly as state_unavailable (or an empty code), never treated as accept.
func OperatorRecordCode(code string) string {
	if code == "accept" {
		return code
	}
	switch code {
	case "", "operator_record_unavailable", "signer_unavailable", "key_binding_unavailable", "time_unavailable", "watermark_unavailable", "revocation_unavailable", "id_journal_unavailable", "replay_unavailable", "state_unavailable":
		return "operator_record_unavailable"
	}
	return "operator_record_invalid"
}

type facts map[string]any
type refusal string

func need(ok bool, code string) {
	if !ok {
		panic(refusal(code))
	}
}
func must[T any](v T, e error) T {
	if e != nil {
		if r, ok := e.(*record.Error); ok {
			panic(refusal(r.Code))
		}
		panic(e)
	}
	return v
}
func errorCode(e error) string {
	if e == nil {
		return "accept"
	}
	if r, ok := e.(*record.Error); ok {
		return r.Code
	}
	panic(e)
}
func decide(fn func() Plan) (r Result) {
	defer func() {
		if x := recover(); x != nil {
			if c, ok := x.(refusal); ok {
				r = Result{Code: string(c)}
			} else {
				panic(x)
			}
		}
	}()
	return Result{Code: "accept", Plan: fn()}
}
func mapped[T any](fn func() T, from, to string) (result T) {
	defer func() {
		if x := recover(); x != nil {
			if c, ok := x.(refusal); ok && (from == "*" || string(c) == from) {
				panic(refusal(to))
			}
			panic(x)
		}
	}()
	return fn()
}
func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func array(v any) []any        { a, _ := v.([]any); return a }
func str(v any) string         { s, _ := v.(string); return s }
func isString(v any) bool      { _, ok := v.(string); return ok }
func isBool(v any) bool        { _, ok := v.(bool); return ok }
func isInt(v any) bool         { _, ok := v.(int64); return ok }
func num(v any) int64          { i, _ := v.(int64); return i }
