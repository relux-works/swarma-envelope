# Open decisions and adopted defaults

These defaults make the proposed v0 contract reviewable. They are not consumer
activation decisions. The normative details are in
[the platform slice](spec/swarm-envelope-2.md).

| Decision | Adopted default | Remaining decision / activation evidence |
| --- | --- | --- |
| D1 — relation to v5.2 | CCJ-1 plus domain tag and role-bound signatures supersede SSHSIG for platform services. Existing SSHSIG/A1 remains a separate repository/offline proposal with explicit channel selection. | Accept the new platform domain; no fallback or automatic A1 translation. |
| D2 — assurance | Key-authenticated authorized content (A2), plus exact-content operator confirmation format/provider requirement (A3). Carrier encryption (A1) excluded. | Qualify signer-provider enrollment and exact-content rendering; an ordinary signature/boolean cannot prove presence. |
| D3 — grant encoding | CCJ-1 closed record; keys only; time-window-only caveats/v1; no counters, roles or rule language. Biscuit deferred. | A later reviewed version may extend the language; do not reinterpret this one. |
| D4 — root and revocation | Protected owner root pin; authenticated caller snapshot, complete and rollback-safe; configured maximum age required, at most 60 seconds. No owner registry. | Approve the freshness ceiling; qualify external rollback witnesses and restore fencing. |
| D5 — terminal fallback | Unsigned authentication creates no operator-act/1. Consumers may separately authorize unsigned narrowing. Persistent Keymaker revoke has no such path; widening always needs a signed act and confirmation. | Publish any separate narrowing fallback in its consumer, without weakening this format. |
| D6 — ownership | waggle owns format and future pure verifier; consumers import a reviewed pinned main commit. | Publish the library API in the next slice, then review consumer pin/integration changes. |
| D7 — action registry | Closed `credential.lease`, `agent.spawn`, `message.deliver`; no dynamic namespace registration. Targets are typed correlated tuples; only trailing `/*` in grant ids. | Approve vocabulary/versioning and any additional action profiles. Message delivery grants never authorize arbitrary execution. |
| D8 — generation subjects | No roles or `agent:` subjects in the general v0 slice. | Publish a versioned broker/dispatcher generation-to-key adapter before replacing generation-bound bindings. Do not discard generation checks. |
| D9 — signature construction | Id hashes `waggle <type>` + LF + CCJ-1(body); signatures bind version, type, role, key and body under a separate exact preimage (§2.2). | Approve the precise role-bound preimage. It intentionally cannot reuse broker signatures. |
| D10 — state and retry | Pure verification returns a persistence plan. Caller atomically reserves act id and advances durable watermark before effect; identical act reuse refuses. Outer consumer request retry may return an already committed outcome. | Qualify crash/concurrency integration and rollback-resistant journal retention. Offline fixtures do not prove durability. |
| D11 — Keymaker Q7 | Exact opaque object mapping and refusal translation in §4.2; positive safe integer registration numbers remain integers; semantic epoch maps to native master_epoch. | Format proposal alone closes no runtime gate: library, device signer, clock/revocation and durable journal integration remain required. |
| D12 — broker transition | R1 remains unchanged in broker v0. Later adapter re-signs, maps ids/revocations, replaces bindings, accepts both roots only for a bounded interval. | Publish exact migration/binding version, transition bounds, generation adapter and reconciliation evidence. |
| D13 — time | Use shared time-policy provider and stricter-only protected policy, with max(now,W) for expiry and min(now,W) for starts. No new clock source. | Pinned time-policy proposal must land and consumers must qualify continuity, watermark durability and provider activation. |
| D14 — carrier | Completed bytes carried unchanged; no transport-specific authority. | Transport owner must publish actual Matrix event budget and authenticated bounded pointer form if needed. No pointer wire schema is invented here. |
| D15 — size and retention | 65,536 bytes/envelope, 8,192/operator record, depth 16, chain 4; consumer also bounds complete embedded frame. Consumed ids survive admissible replay/restore horizons. | Consumers must publish/qualify retention horizons and prove whole-frame budgets. Time expiry alone cannot erase recovery evidence. |

No owner registry, phone enrollment protocol, production verifier, migration
executable, Matrix extension or consumer activation is delivered by this slice.
All vector inputs are synthetic public test data.
