# waggle

A secure agent coordination and communication protocol: signed messages between agents. waggle defines one message envelope, one verification pipeline and one delivery model for agent orchestrators that share a project. Orchestrators coordinate with each other, first on one machine, then across a few operators over the internet, later with other organizations. Orchestrators also send one-way commands (clarify, reprioritize, cancel, halt) to their own workers; workers can never instruct orchestrators. The original repository/offline proposal uses SSHSIG. The proposed platform slice uses CCJ-1 records with role-bound signatures, grants and operator acts. Agent authors use Ed25519 under the exact `swarma-msg/2` tag; operator device keys use P-256. Consumers select their protocol explicitly.

## Status

**Draft design with offline conformance tooling.** The platform slice specifies `swarm-envelope/2`, general `grant/1`, `operator-act/1`, root-signed `attestation/1` and shared `revocation/1`. Its 2217 vectors (2120 negative, 97 positive) have a Go generator and independent Python checker. The tree retains 557 named semantic vectors; 1660 mechanical sweep cases are represented by a checked SHA-256 manifest and materialized on demand. No production verifier, consumer integration or activation is implemented. The Go module currently contains tools only; the public library is a later slice. Broker v0 retains static R1 admission; Keymaker persistent revoke remains gated on verifier integration. Attested agent messages provide A1 provenance; widening is inactive because v0 has no qualified A3 provider.

## Layout

| Path | Contents |
| --- | --- |
| [`spec/swarm-envelope-2.md`](spec/swarm-envelope-2.md) | Proposed normative platform records, refusal order, pure verifier boundary, exact tag registry, signed attestations/revocation, message delivery binding and assurance contracts, Keymaker mapping and later broker adapter; supersedes SSHSIG only for platform services |
| [`UNRESOLVED_QUESTIONS.md`](UNRESOLVED_QUESTIONS.md) | Adopted defaults and remaining publication/activation decisions |
| [`vectors/swarm-envelope-2/`](vectors/swarm-envelope-2/) | Negative-first paired format and authorization witnesses |
| [`vectors/keys/`](vectors/keys/) | Public test-only seeds and key provenance |
| [`tools/vectors/`](tools/vectors/) | Deterministic Go fixture generator, signed-evidence builders and byte-for-byte inventory check |
| [`tools/vectorcheck/`](tools/vectorcheck/) | Independent Python codec, strict crypto and ordered authorization checker |
| [`spec/waggle.md`](spec/waggle.md) | the specification (draft v5.2): two layers; principals and roster, envelope and multi-signature, verification pipeline, signature policy, signer providers and key assurance, message classes, injection defense, conversation model, providers and their capabilities, delivery through the session host; coordination vocabulary and quorum decisions, scope leases, the protocol lab; phases; Amendment A1 for board processes (board acts, confirmations of process versions, signed external events, service principals, the hand-off result, user verification in board policy, the companion app, delegation) |
| [`spec/track.md`](spec/track.md) | the delivery track: why, the design on one screen, the fast path to internet coordination, milestones CM0–CM4, decisions |
| [`spec/waggle.ru.md`](spec/waggle.ru.md), [`spec/track.ru.md`](spec/track.ru.md) | Russian translations; the English files are canonical |

## Original SSHSIG proposal in brief

- **Signatures travel inside every message.** An envelope is the exact payload bytes plus one or more SSHSIG signatures, each with a role: `author`, `approver` or `endorser`. The signature namespace binds message class and role, so a signature made in one role or for one class cannot be reused for another.
- **The roster is a stock OpenSSH `allowed_signers` file** committed in the project, next to a revocation list and a policy file that says which message types need which signatures. Adding a teammate is a reviewed pull request.
- **Sessions sign, agents compose.** The host creates a short-lived certified key for each orchestrator session and signs what the agent writes; the agent never holds a key. A worker's certificate allows reports only, so a worker cannot produce a command or a coordination message over any transport.
- **Any key hardware, one format.** Signer providers are plugins: `ssh-agent`, Apple Secure Enclave, FIDO keys, later TPM and PIV, with an ordinary key as the fallback. The offline v0 platform slice admits raw P-256 device signatures only; FIDO/WebAuthn assertions require a future proof profile. Each enrolled key gets an assurance level (`software`, `hardware-bound`, `attested`), and the policy says which level an approval needs.
- **Delivery is a doorbell plus a pull, behind layered injection defense.** A fixed-template doorbell enters the agent loop and the agent pulls messages as untrusted data. Authority stays outside the model (gates, scope leases, supervisor-executed cancel and halt); inspectors, guards and quarantine are optional layers on top.
- **Two layers.** A communication layer moves signed messages between principals; a coordination layer built on it decides who works on what, with scope leases and quorum decisions.
- **Scope leases decide, messages negotiate; providers are untrusted pipes.** Orchestrators lease parts of a project with a term and a token in a compare-and-set store. Providers sit behind one interface: carriers deliver the signed bytes (a local mailbox, then NATS JetStream for the internet, XMPP for federation later), consoles render messages for people, gateways (A2A) translate at the edge, and chats such as Slack or Telegram can be adapters because authority comes from signatures, never from the provider.

## Tools

Run from the repository root. Go 1.26.0 or newer is required; the validated
toolchain was 1.26.10, selected through `CURATOR_GO`. Python validation used
Python 3.14.4 and the already present cryptography 46.0.5 for P-256.

| Tool | Purpose and exact entry point | Output |
| --- | --- | --- |
| Go generator | `GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors` | Writes named JSON, sweep manifest/digest and public keys under `vectors/` |
| Go inventory check | `GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -check` | Regenerates all cases; compares named JSON and sweep manifest/digest without writing |
| Independent Python checker | `python3 -B tools/vectorcheck/check.py` | Checks supplied cases (557 named by default); nonzero failure or PENDING |
| Go vet | `GOMAXPROCS=2 "$CURATOR_GO" vet ./tools/vectors` | Narrow tool validation; stdout/stderr and exit status |
| Go formatting | `"$CURATOR_GO" fmt ./tools/vectors` | Formats generator source |
| Git | `git diff --check`, `git diff --stat` | Whitespace validation and scoped change review |

The full conformance gate includes the generated sweeps:

```sh
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -check
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all
GOMAXPROCS=2 "$CURATOR_GO" run ./tools/vectors -sweeps -out .tmp/vectors-all -check
python3 -B tools/vectorcheck/check.py --vectors .tmp/vectors-all
```

On a resource-managed host, run each generator/checker command through its
required serialized resource runner, sequentially. `-out DIR` selects the
fixture root; `-sweeps` includes all T/B/Z/U JSON for independent implementations.
Keep logs and tamper controls in ignored `.tmp/`. The manifest format and
signature/manifest/byte control procedures are documented in the
[generator guide](tools/vectors/README.md) and
[vector contract](vectors/swarm-envelope-2/README.md). No full project suite or
consumer service is required for this specification-only slice.

## Consumers

- **task-board**: orchestrator and worker messaging through `task-board mail`. It will consume this module through `go.mod` at tags, the same way it consumes [skill-agents-management](https://github.com/relux-works/skill-agents-management).
- **Apiary** (later): the agent host and coordinator of the Curator agent runtime.
- **Process configuration** ([curator-playbook](https://github.com/relux-works/curator-playbook)): board approvals, delegated acts, confirmations of process versions, signed external events and hand-off results across boards (Amendment A1). What those acts mean — who counts as a person, the floor of a confirmation, narrowing acts — is the trust design in [curator-trust](https://github.com/relux-works/curator-trust) (`spec/trust.md`).

## Links

- Specification: [`spec/waggle.md`](spec/waggle.md)
- Track and milestones: [`spec/track.md`](spec/track.md)
- In Russian: [`spec/waggle.ru.md`](spec/waggle.ru.md), [`spec/track.ru.md`](spec/track.ru.md)
- The SSHSIG format used by `ssh-keygen -Y sign` and `-Y verify`: [PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)

## License

Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE).
