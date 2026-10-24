// Package verifier implements the ordered v0 receiver, grant, operator and
// signed-evidence pipelines in spec/swarm-envelope-2.md at the library's pinned
// source revision. Every refusal has an empty persistence plan. An accept is
// a candidate decision, never an effect permit or a completed transaction.
//
// Evidence values are immutable snapshots with explicit unavailable states.
// No nil interface or missing collection stands for empty trusted evidence.
// The package performs no I/O, network, fetching, signing, ambient clock access,
// persistence, reservation or effect execution and has no mutable global state.
// Caller adapters own provider resolution, freshness and continuity, Commit,
// serialized rechecks, online checks for critical effects and durable effects.
// A3 widening is unconditionally inactive in v0.
//
// Stability: public API or behavior changes require their own reviewed pull
// request. Consumers pin a reviewed commit landed on main and raise that pin in
// their own review. api.txt and TestAPISurface guard exported names, fields and
// methods only; the inventory does not grant approval for semantic changes.
package verifier
