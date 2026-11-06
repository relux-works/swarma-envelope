---
name: swarma-envelope
description: Use Swarma Envelope's pure Go APIs for signed platform records, verification and owner-act preparation, or its offline conformance tools.
---

# Swarma Envelope

Choose the implemented boundary that matches the request:

- Read [Go API usage](references/go-api.md) for byte admission, protected evidence,
  receiver/grant/operator verification, currency receipts or owner-act preparation
  and assembly. It includes an inert positive example and its adjacent refusal.
- Read [offline tooling](references/offline-tools.md) for the existing vector
  generator and independent checker, their flags and qualification limits.

The module is `github.com/relux-works/swarma-envelope` (Go 1.26.0 in
[go.mod](../../../go.mod)). Public packages are `record`, `owneracts` and
`verifier`. Start from their linked source and package contracts; the
[platform specification](../../../spec/swarm-envelope-2.md) supplies formats and
ordered refusals. The historical [SSHSIG/provider proposal](../../../spec/waggle.md)
is a separate design, not an implemented platform signer, transport or service.

Use caller-supplied protected snapshots through the actual Go API. There is no
plugin registration API, ambient clock, automatic evidence fetch or signer
callback in the pure verifier. Never turn received IDs, `confirmed=true`,
available evidence or a successful mathematical check into protected authority.

Return the exact local error or verifier code and distinguish an unsigned
proposal, correctly formed signed intent and a candidate transaction plan.
Native custody/presence, protected enrollment/currentness, complete durable
history, replay handling, serialized consumer effects, critical online checks
and deployment qualification remain external obligations. Owner-sitting key,
confirmation and landing operations belong to the responsible owner; this skill
does not authorize an agent to perform them. Documentation checks establish no
new security property.
