// Package record implements platform slice v0 byte encoding, domain separation,
// strict Ed25519/P-256 signature verification and message-provider admission.
// Canonicalization and duplicate-free parsing use the pinned registrar CCJ-1.
// Generic signature validity confers no profile, identity, grant or effect
// authority; use package verifier for receiver and authorization pipelines.
//
// This package performs no I/O or network access, uses no private keys, and has
// no mutable global or process state. Inputs and returned values are caller-owned.
//
// Stability: public API or behavior changes require their own reviewed pull
// request. Consumers pin a reviewed commit landed on main and update that pin
// in their own review. api.txt and TestAPISurface guard exported names, fields
// and methods only; an unchanged inventory does not approve semantic changes.
package record
