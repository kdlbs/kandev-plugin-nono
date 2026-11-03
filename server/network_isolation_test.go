package main

import (
	"encoding/json"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
	"github.com/stretchr/testify/require"
)

func TestCompileRequiresNetworkNamespaceForProxyAccess(t *testing.T) {
	for _, kind := range []string{"blocked", "tcp", "mcp"} {
		t.Run(kind, func(t *testing.T) {
			request := compileRequest(t)
			switch kind {
			case "tcp":
				request.Policy.Grants.Network = []*pluginsdk.SandboxNetworkGrant{{Host: "example.test", Port: 443, Protocol: "tcp"}}
			case "mcp":
				request.Policy.Grants.KandevMcp = true
				request.Endpoints = []*pluginsdk.SandboxEndpoint{{Key: "kandev.mcp", Host: "127.0.0.1", Port: 32123, Scheme: "http", Path: "/mcp"}}
			}
			response, err := (&nonoPlugin{}).CompileSandboxPolicy(t.Context(), request)
			require.NoError(t, err)
			var profile struct {
				Linux struct {
					Isolate struct {
						Network  bool `json:"network"`
						Loopback bool `json:"loopback"`
					} `json:"isolate"`
				} `json:"linux"`
			}
			require.NoError(t, json.Unmarshal([]byte(response.Compiled.Artifacts[0].ContentUtf8), &profile))
			require.Equal(t, kind != "blocked", profile.Linux.Isolate.Network,
				"proxy access must not expose host services on the proxy's TCP port")
			require.False(t, profile.Linux.Isolate.Loopback)
		})
	}
}
