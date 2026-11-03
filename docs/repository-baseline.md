# Repository baseline

This local checkout started from `kdlbs/kandev-plugin-template` commit `805d2018773bf3c6f594f5c4f9e1b2d07e71bc48`.

Template UI, webhooks, event state, and source-control recipes were removed. The production provider uses only the public `pkg/pluginsdk` contract. It declares managed API version 2 and sandbox protocol major 1.

Nono source: `nolabs-ai/nono` commit `8bb041356d48f771a221e58c98d9b1ff442e76fe`. Runtime pins are in `runtime-lock.json`. The audit event fixture comes from that revision's `crates/nono/src/audit.rs` wire-format test. Its known leaf digest is retained in the fixture.

Core owns the experimental feature flag and all operator-facing interfaces. This plugin does not implement a separate settings UI or permission server.
