# Nono sandbox provider for Kandev

This repository contains the optional Nono provider. Core command wrapping works without this plugin.

The provider compiles canonical grants for pinned Nono 0.81.0 on Linux amd64. It translates file approval requests and decision replies. It verifies audit event chains and proposes grants from explicitly selected denial records. Kandev owns process launch, operator authority, ceilings, persistence, and cleanup.

## Current status

The baseline host integration has recorded managed acceptance with Nono 0.80.0, Pi ACP 0.0.34, and Pi 1.3.0. Those historical receipts cover ACP/native tools and MCP, same-session restart, cancellation, sibling isolation, and cleanup. They are recorded in the host's `docs/plans/nono-sandbox-integration/acceptance.md`.

The 0.81.0 candidate passes baseline runtime conformance and the plugin's real compiled-policy race tests. The manifest now requires sandbox protocol major 2. The compiler still accepts policy schema 1 and file approvals only. The public standalone SDK pin includes the major 2 contract. Typed audit reports pass the real runtime and packaged host integration checks. Current-pair managed acceptance, signature verification, and broader approvals remain pending in the expansion package. Source support for a request kind does not enable it in this plugin.

A session registry record has no policy digest. Normalization can return supervisor, child, and provider session identity for a matching core-owned process. It returns no confinement evidence. Core must verify birth identity and ancestry before using those identities. Audit reports remain partial because the event log does not record every denied operation.

Protocol major 2 runtime observations parse the conditional `sandbox_runtime` audit event from the captured provider session's file. The provider verifies the event chain and retains the original timestamp, platform, optional detected Landlock ABI, optional execute-enforcement claim, and command-mediation state. A missing event yields no observations. A sibling or nested session file cannot describe the captured supervisor. These historical facts contain no current-policy attestation and cannot activate the shield. Kandev separately reports physical process ownership and its completed launch preparation checks.

Network grants use protocol `tcp`. Nono 0.81.0 removes ports from plain `allow_domain` entries, so the provider requires Kandev's `egress_proxy` capability for exact host/port enforcement. Core supplies a private upstream CONNECT relay. They do not enforce the application protocol. HTTP/HTTPS-specific grants remain unsupported. Kandev MCP uses its explicit logical grant and current private relay. Managed acceptance for the upgraded pair remains pending.

## Develop

The plugin imports the standalone `github.com/kdlbs/kandev/pluginsdk` module at an exact public commit version. It has no backend module dependency or local replacement. `sh scripts/check-sdk-consumer.sh` copies the consumer into a temporary directory and builds it without a host checkout. This is an experimental contract pin, not a Stable SDK compatibility claim.

Only packaging needs the separately pinned host `plugin-pack` tool. The default `KANDEV_PACK_TOOL` is `../kdlbs-kandev/apps/backend`; override it for another checkout of the revision in `.kandev-sdk-ref`. CI checks out that packaging source separately. Go module resolution supplies the SDK independently.

Run `make validate`. Run actual runtime checks with the verified executable:

```bash
NONO_ACCEPTANCE_BINARY=/absolute/path/to/nono go test ./server -run TestPinnedRuntime -count=1 -v
```

The tests verify the executable SHA-256 before starting it. They use private temporary data and no provider credentials.

## Package

`make verify-package` builds the Linux plugin, downloads the pinned Nono release, verifies the archive and executable digests, and produces `kandev-plugin-nono-0.1.0.tar.gz`. Set `NONO_RUNTIME_ARCHIVE` to an already downloaded pinned archive for an offline package build. The plugin does not download a runtime during launch.

The package includes the Nono Apache 2.0 license and `runtime-lock.json` provenance. Plugin code uses the repository MIT license.

`.kandev-sdk-ref` records the SDK source commit and the matching packaging-tool source used by CI. `go.mod` pins the corresponding standalone module version. There is no stable Kandev release compatibility claim yet. The manifest capability negotiation rejects hosts without this extension.

Source review is open in [draft PR #2](https://github.com/kdlbs/kandev-plugin-nono/pull/2). No marketplace entry or release is published.

### Agent session state

An explicit host `agent_state` grant gives the child a separate home. The compiler binds core-owned home, config, state, and temporary directory references to Nono `environment.set_vars`. Nono 0.81.0 applies these values after inherited-variable filtering. The supervisor keeps its private home and state directories. The plugin does not copy credentials or allocate directories. Kandev owns session retention and cleanup.

The pinned source contract is [EnvironmentConfig at the runtime commit](https://github.com/nolabs-ai/nono/blob/b2d859deeb7a65f9ca5b334eb8726637ba76c866/crates/nono-cli/src/profile/mod.rs). Actual runtime verification is recorded in the host acceptance log.

### Loopback MCP clients

Nono 0.81.0 injects loopback `NO_PROXY` entries after profile environment settings. The plugin clears `NO_PROXY`, `no_proxy`, and `NONO_NO_PROXY` inside the sandbox before launching an MCP-enabled child. Standard clients must reach the approved relay through the enforced proxy. Direct connections remain blocked. Network grants and the core exact-destination relay do not change.

This launch uses the host `env` tool with `-u` support from the child `PATH`. The operator must grant read and execution access to that tool and its runtime libraries, as for the agent executable. Compilation refuses an unavailable `env` tool. The plugin does not add filesystem permissions. Policies without the Kandev MCP grant do not require this launcher.

The pinned [proxy child environment](https://github.com/nolabs-ai/nono/blob/b2d859deeb7a65f9ca5b334eb8726637ba76c866/crates/nono-proxy/src/server.rs) and [environment application order](https://github.com/nolabs-ai/nono/blob/b2d859deeb7a65f9ca5b334eb8726637ba76c866/crates/nono-cli/src/exec_strategy.rs) explain why profile `set_vars` cannot clear the injected bypass entries.

## Typed report support

The protocol major 2 capability `kandev.sandbox.report.v2` accepts core-frozen,
session-bound sources in chunks of at most 256 KiB. Collection is bounded to
32 files and 32 MiB. The reader checks sequence, source digest, artifact-set
digest, captured session, event hashes, and chain links. Final `session.json`
metadata additionally binds the event count, chain head, and Merkle root.

Reports include recorded filesystem, network, command, and HTTP-endpoint
decisions. Each class has partial coverage. Nono does not record every denied
operation. Command events expose the command ID and caller. They do not expose
raw arguments, environment values, or working-directory paths. Pending command
invocation outcomes are omitted until a supported terminal record exists.
Endpoint query values and unusable hostnames are not reconstructed. Incomplete
identities remain readable evidence and cannot authorize policy learning.

Live records, finalization, and chain integrity are separate facts. This report
reader does not assert signature validity, signer trust, ledger validity, or
continuous kernel confinement. A changed or unsupported source fails the read.
The host retains the last successful report and its original read time.
