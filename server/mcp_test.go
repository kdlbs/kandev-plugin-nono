package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
)

func TestCompileMCPRequiresExplicitLogicalGrantAndCurrentRelay(t *testing.T) {
	for _, kind := range []string{"valid", "missing-grant", "wrong-service", "backend-route", "non-loopback", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			request := compileRequest(t)
			request.Policy.Grants.KandevMcp = true
			request.Endpoints = []*pluginsdk.SandboxEndpoint{{Key: "kandev.mcp", Host: "127.0.0.1", Port: 31234, Scheme: "http", Path: "/mcp"}}
			switch kind {
			case "missing-grant":
				request.Policy.Grants.KandevMcp = false
			case "wrong-service":
				request.Endpoints[0].Key = "approval"
			case "backend-route":
				request.Endpoints[0].Path = "/api"
			case "non-loopback":
				request.Endpoints[0].Host = "example.com"
			case "duplicate":
				request.Endpoints = append(request.Endpoints, request.Endpoints[0])
			}
			response, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), request)
			if kind != "valid" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			var profile struct {
				Network struct {
					AllowDomain []string `json:"allow_domain"`
					Block       bool
				}
			}
			require.NoError(t, json.Unmarshal([]byte(response.Compiled.Artifacts[0].ContentUtf8), &profile))
			require.False(t, profile.Network.Block)
			require.Equal(t, []string{"127.0.0.1:31234"}, profile.Network.AllowDomain)
			require.Contains(t, response.Compiled.RequiredCapabilities, "egress_proxy")
			require.True(t, response.Compiled.EffectiveGrants.KandevMcp)
			require.Empty(t, response.Compiled.EffectiveGrants.Network, "ephemeral endpoints must not become durable policy grants")
		})
	}
}
