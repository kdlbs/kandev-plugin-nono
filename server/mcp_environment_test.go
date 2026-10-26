package main

import (
	"strings"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCompileMCPClearsInjectedProxyBypass(t *testing.T) {
	request := compileRequest(t)
	request.Policy.Grants.KandevMcp = true
	request.Endpoints = []*pluginsdk.SandboxEndpoint{{Key: "kandev.mcp", Host: "127.0.0.1", Port: 31234, Scheme: "http", Path: "/mcp"}}
	response, err := (&nonoPlugin{}).CompileSandboxPolicy(t.Context(), request)
	require.NoError(t, err)
	var tokens []string
	for _, argument := range response.Compiled.Prefix {
		tokens = append(tokens, argument.GetLiteral())
	}
	require.Contains(t, strings.Join(tokens, " "), "-- env -u NO_PROXY -u no_proxy -u NONO_NO_PROXY --")
	require.Equal(t, request.Policy.Grants.Network, response.Compiled.EffectiveGrants.Network)
	t.Setenv("PATH", "")
	_, err = (&nonoPlugin{}).CompileSandboxPolicy(t.Context(), request)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	request.Policy.Grants.KandevMcp = false
	request.Endpoints = nil
	_, err = (&nonoPlugin{}).CompileSandboxPolicy(t.Context(), request)
	require.NoError(t, err, "ordinary policies must not require the proxy environment launcher")
}
