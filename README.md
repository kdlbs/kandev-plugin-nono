# Nono sandbox provider for Kandev

This repository contains the optional Nono provider. Core command wrapping works without this plugin.

The provider compiles canonical grants for pinned Nono 0.80.0 on Linux amd64. It translates file approval requests and decision replies. It verifies audit event chains and proposes grants from explicitly selected denial records. Kandev owns process launch, operator authority, ceilings, persistence, and cleanup.

## Current status

Implementation is in progress. Real compiled-policy checks cover permitted filesystem work, denied outside access, exact proxy destinations, blocked direct networking, environment filtering, and audit parsing. Full Kandev lifecycle, ACP, terminal, MCP, approval ownership, UI, packaging installation, and recovery acceptance remain pending.

A session registry record has no policy digest. Normalization can return supervisor, child, and provider session identity for a matching core-owned process. It returns no confinement evidence. Core must verify birth identity and ancestry before using those identities. Audit reports remain partial because the event log does not record every denied operation.

Network grants use protocol `tcp`. Nono 0.80.0 removes ports from plain `allow_domain` entries, so the provider requires Kandev's `egress_proxy` capability for exact host/port enforcement. Core supplies a private upstream CONNECT relay. They do not enforce the application protocol. HTTP/HTTPS-specific grants remain unsupported. Kandev MCP uses its explicit logical grant and current private relay. Full managed-agent acceptance remains pending.

## Develop

Place this checkout beside `kdlbs-kandev`, which supplies the public Go SDK:

```text
workspace/
  kdlbs-kandev/apps/backend/
  kandev-plugin-nono/
```

Run `make validate`. Run actual runtime checks with the verified executable:

```bash
NONO_ACCEPTANCE_BINARY=/absolute/path/to/nono go test ./server -run TestPinnedRuntime -count=1 -v
```

The tests verify the executable SHA-256 before starting it. They use private temporary data and no provider credentials.

## Package

`make verify-package` builds the Linux plugin, downloads the pinned Nono release, verifies the archive and executable digests, and produces `kandev-plugin-nono-0.1.0.tar.gz`. Set `NONO_RUNTIME_ARCHIVE` to an already downloaded pinned archive for an offline package build. The plugin does not download a runtime during launch.

The package includes the Nono Apache 2.0 license and `runtime-lock.json` provenance. Plugin code uses the repository MIT license.

`.kandev-sdk-ref` identifies the committed host contract used by CI. There is no stable Kandev release compatibility claim yet. The manifest capability negotiation rejects hosts without this extension.

Source review is open in [draft PR #2](https://github.com/kdlbs/kandev-plugin-nono/pull/2). No marketplace entry or release is published.

### Agent session state

An explicit host `agent_state` grant gives the child a separate home. The compiler binds core-owned home, config, state, and temporary directory references to Nono `environment.set_vars`. Nono 0.80.0 applies these values after inherited-variable filtering. The supervisor keeps its private home and state directories. The plugin does not copy credentials or allocate directories. Kandev owns session retention and cleanup.

The pinned source contract is [EnvironmentConfig at the runtime commit](https://github.com/nolabs-ai/nono/blob/8bb041356d48f771a221e58c98d9b1ff442e76fe/crates/nono-cli/src/profile/mod.rs). Actual runtime verification is recorded in the host acceptance log.

### Loopback MCP clients

Nono 0.80.0 injects loopback `NO_PROXY` entries after profile environment settings. The plugin clears `NO_PROXY`, `no_proxy`, and `NONO_NO_PROXY` inside the sandbox before launching an MCP-enabled child. Standard clients must reach the approved relay through the enforced proxy. Direct connections remain blocked. Network grants and the core exact-destination relay do not change.

This launch uses the host `env` tool with `-u` support from the child `PATH`. The operator must grant read and execution access to that tool and its runtime libraries, as for the agent executable. Compilation refuses an unavailable `env` tool. The plugin does not add filesystem permissions. Policies without the Kandev MCP grant do not require this launcher.

The pinned [proxy child environment](https://github.com/nolabs-ai/nono/blob/8bb041356d48f771a221e58c98d9b1ff442e76fe/crates/nono-proxy/src/server.rs) and [environment application order](https://github.com/nolabs-ai/nono/blob/8bb041356d48f771a221e58c98d9b1ff442e76fe/crates/nono-cli/src/exec_strategy.rs) explain why profile `set_vars` cannot clear the injected bypass entries.
