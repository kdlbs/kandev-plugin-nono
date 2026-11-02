package main

import (
	"context"
	"encoding/json"
	"github.com/kdlbs/kandev/pluginsdk"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"testing"
	"time"
)

func requestContext() *pluginsdk.SandboxRequestContext {
	return &pluginsdk.SandboxRequestContext{ProtocolMajor: 1, ProviderKey: "nono", InstallationId: "installation", OperationId: "operation", AttemptId: "attempt", Generation: 1, DeadlineUnixMs: time.Now().Add(time.Minute).UnixMilli()}
}
func compileRequest(t *testing.T) *pluginsdk.CompileSandboxPolicyRequest {
	t.Helper()
	return &pluginsdk.CompileSandboxPolicyRequest{Context: requestContext(), Runtime: &pluginsdk.SandboxRuntimeFacts{Os: "linux", Architecture: "amd64", Transport: "local", RuntimeVersion: "0.81.0", RuntimeDigest: "2d3c29641c87921f7cd469387e4838b1676d54edb7291aebda7a780787d7c1b2"}, Policy: &pluginsdk.SandboxPolicySnapshot{PolicyId: "policy", Revision: 1, Digest: "policy-digest", CeilingDigest: "ceiling", Grants: &pluginsdk.SandboxGrants{Filesystem: []*pluginsdk.SandboxFilesystemGrant{{Path: t.TempDir(), Writable: true}}}}}
}

func TestDescribePinsPackagedLinuxRuntime(t *testing.T) {
	p := &nonoPlugin{}
	req := compileRequest(t)
	result, err := p.DescribeSandboxProvider(context.Background(), &pluginsdk.DescribeSandboxProviderRequest{Context: req.Context, Runtime: req.Runtime})
	require.NoError(t, err)
	require.Equal(t, "0.81.0", result.Description.RuntimeVersion)
	require.Equal(t, "runtime/nono-linux-amd64", result.Description.RuntimeArtifact.RelativePath)
	require.Equal(t, "2d3c29641c87921f7cd469387e4838b1676d54edb7291aebda7a780787d7c1b2", result.Description.RuntimeArtifact.Sha256)
	require.Equal(t, "operation", result.Context.OperationId)
	require.Equal(t, []string{"filesystem"}, result.Description.ReportClasses)
}

func TestCompileRemovesImplicitGrantsAndBlocksNetwork(t *testing.T) {
	req := compileRequest(t)
	before := proto.Clone(req)
	result, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.NoError(t, err)
	require.True(t, proto.Equal(req, before))
	require.True(t, proto.Equal(req.Policy.Grants, result.Compiled.EffectiveGrants))
	var profile struct {
		Groups     struct{ Exclude []string }
		Filesystem struct {
			Allow []string
			Read  []string
		}
		Network struct {
			Block       bool
			AllowDomain []string `json:"allow_domain"`
		}
		Workdir     struct{ Access string }
		Environment struct {
			AllowVars []string `json:"allow_vars"`
		}
		Security struct {
			CapabilityElevation bool `json:"capability_elevation"`
		}
	}
	require.Len(t, result.Compiled.Artifacts, 1)
	require.NoError(t, json.Unmarshal([]byte(result.Compiled.Artifacts[0].ContentUtf8), &profile))
	require.ElementsMatch(t, []string{"system_read_macos", "system_read_linux_core", "system_write_macos", "system_write_linux", "user_tools", "homebrew_macos", "homebrew_linux", "dangerous_commands", "dangerous_commands_macos", "dangerous_commands_linux"}, profile.Groups.Exclude)
	require.Equal(t, []string{req.Policy.Grants.Filesystem[0].Path}, profile.Filesystem.Allow)
	require.Empty(t, profile.Filesystem.Read)
	require.True(t, profile.Network.Block)
	require.Empty(t, profile.Network.AllowDomain)
	require.Equal(t, "none", profile.Workdir.Access)
	require.NotNil(t, profile.Environment.AllowVars)
	require.NotContains(t, profile.Environment.AllowVars, "*")
	require.True(t, profile.Security.CapabilityElevation)
	require.Equal(t, "sandbox.runtime", result.Compiled.Prefix[0].GetRuntimeReference())
	require.Equal(t, "--", result.Compiled.Prefix[len(result.Compiled.Prefix)-1].GetLiteral())
	require.Equal(t, "sandbox.approval.endpoint", result.Compiled.Artifacts[0].Bindings[0].RuntimeReference)
}

func TestCompileRefusesUnverifiedRuntimeOrExpansion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*pluginsdk.CompileSandboxPolicyRequest)
	}{
		{"other platform", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Runtime.Os = "darwin" }},
		{"remote", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Runtime.Transport = "ssh" }},
		{"other binary", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Runtime.RuntimeDigest = "unverified" }},
		{"expand variable", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Policy.Grants.Filesystem[0].Path = "/tmp/$HOME" }},
		{"expand tilde", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Policy.Grants.Filesystem[0].Path = "~/secret" }},
		{"unknown authority", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Context.ProtocolMajor = 3 }},
		{"expired", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Context.DeadlineUnixMs = 1 }},
		{"missing policy", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Policy = nil }},
		{"mcp without endpoint", func(r *pluginsdk.CompileSandboxPolicyRequest) { r.Policy.Grants.KandevMcp = true }},
		{"http protocol promise", func(r *pluginsdk.CompileSandboxPolicyRequest) {
			r.Policy.Grants.Network = []*pluginsdk.SandboxNetworkGrant{{Host: "example.com", Port: 443, Protocol: "https"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := compileRequest(t)
			tc.mutate(req)
			result, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
}

func TestCompileLimitsProxyToExactDestinations(t *testing.T) {
	req := compileRequest(t)
	req.Policy.Grants.Network = []*pluginsdk.SandboxNetworkGrant{{Host: "example.com", Port: 443, Protocol: "tcp"}}
	result, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.NoError(t, err)
	var profile struct {
		Network struct {
			Block       bool
			AllowDomain []string `json:"allow_domain"`
			OpenPort    []uint32 `json:"open_port"`
			ConnectPort []uint32 `json:"connect_port"`
		}
	}
	require.NoError(t, json.Unmarshal([]byte(result.Compiled.Artifacts[0].ContentUtf8), &profile))
	require.Equal(t, []string{"example.com:443"}, profile.Network.AllowDomain)
	require.Empty(t, profile.Network.OpenPort)
	require.Empty(t, profile.Network.ConnectPort)
	require.False(t, profile.Network.Block)
}

func TestCompileRejectsUnsafeProxyDestinations(t *testing.T) {
	for _, host := range []string{"*", "*.example.com", "https://example.com", "example.com/path", "example.com:443", "127.0.0.1\n", "0.0.0.0", "::", "user@example.com"} {
		req := compileRequest(t)
		req.Policy.Grants.Network = []*pluginsdk.SandboxNetworkGrant{{Host: host, Port: 443, Protocol: "tcp"}}
		result, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
		require.Error(t, err, host)
		require.Nil(t, result)
	}
}

func TestApprovedCredentialKeysReachOnlyChildAllowlist(t *testing.T) {
	req := compileRequest(t)
	req.Policy.Grants.EnvironmentKeys = []string{"OPENAI_API_KEY"}
	result, err := (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.NoError(t, err)
	var profile struct {
		Environment struct {
			AllowVars []string `json:"allow_vars"`
		}
	}
	require.NoError(t, json.Unmarshal([]byte(result.Compiled.Artifacts[0].ContentUtf8), &profile))
	require.Contains(t, profile.Environment.AllowVars, "OPENAI_API_KEY")
	req.Policy.Grants.EnvironmentKeys = []string{"NONO_ALLOW_NET"}
	result, err = (&nonoPlugin{}).CompileSandboxPolicy(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
}

func TestNetworkCompilationRequiresCoreEgressPortEnforcement(t *testing.T) {
	req := compileRequest(t)
	req.Policy.Grants.Network = []*pluginsdk.SandboxNetworkGrant{{Host: "127.0.0.1", Port: 12345, Protocol: "tcp"}}
	result, err := (&nonoPlugin{}).CompileSandboxPolicy(t.Context(), req)
	require.NoError(t, err)
	require.Contains(t, result.Compiled.RequiredCapabilities, "egress_proxy")
	found := false
	for _, binding := range result.Compiled.Artifacts[0].Bindings {
		if binding.RuntimeReference == "sandbox.egress.endpoint" {
			found = true
			require.Equal(t, []string{"network", "upstream_proxy"}, binding.Path)
		}
	}
	require.True(t, found, "Nono host-only allow rules require core port enforcement")
	var profile map[string]any
	require.NoError(t, json.Unmarshal([]byte(result.Compiled.Artifacts[0].ContentUtf8), &profile))
	require.Equal(t, "", profile["network"].(map[string]any)["upstream_proxy"])
}

func TestDescribeMajorTwoDeclaresOnlyImplementedPolicySchema(t *testing.T) {
	request := compileRequest(t)
	request.Context.ProtocolMajor = 2
	result, err := (&nonoPlugin{}).DescribeSandboxProvider(context.Background(), &pluginsdk.DescribeSandboxProviderRequest{Context: request.Context, Runtime: request.Runtime})
	require.NoError(t, err)
	require.Equal(t, uint32(2), result.Context.SchemaVersion)
	require.Equal(t, []uint32{1}, result.Description.CapabilitiesV2.PolicySchemas)
	require.Equal(t, []string{"nono.audit.v1"}, result.Description.CapabilitiesV2.ObservationSchemas)
	require.Equal(t, []string{pluginsdk.SandboxReportSchemaV2}, result.Description.CapabilitiesV2.ReportSchemas)
	require.Len(t, result.Description.RuntimeSources, 3)
	require.Equal(t, uint32(32<<20), result.Description.RuntimeSources[1].MaxBytes)
	require.Equal(t, "audit_final", result.Description.RuntimeSources[2].Kind)
}
