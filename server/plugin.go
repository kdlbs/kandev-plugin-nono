package main

import (
	"context"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	providerVersion  = "0.1.0"
	runtimeVersion   = "0.80.0"
	runtimeDigest    = "a66396777ed756dff196ef61cf704abd4feebf58599d41e2da3363bbe90e22af"
	approvalEndpoint = "sandbox.approval.endpoint"
)

type nonoPlugin struct{ pluginsdk.UnimplementedPlugin }

func replyContext(ctx context.Context, req *pluginsdk.SandboxRequestContext) (*pluginsdk.SandboxResponseContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil || req.ProtocolMajor != 1 || req.ProviderKey != "nono" || req.InstallationId == "" || req.OperationId == "" || req.AttemptId == "" || req.Generation == 0 || req.DeadlineUnixMs <= time.Now().UnixMilli() {
		return nil, status.Error(codes.InvalidArgument, "invalid sandbox operation")
	}
	return &pluginsdk.SandboxResponseContext{SchemaVersion: 1, OperationId: req.OperationId}, nil
}

func supportedHost(runtime *pluginsdk.SandboxRuntimeFacts) bool {
	return runtime != nil && runtime.Os == "linux" && runtime.Architecture == "amd64" && (runtime.Transport == "local" || runtime.Transport == "worktree")
}

func (*nonoPlugin) DescribeSandboxProvider(ctx context.Context, req *pluginsdk.DescribeSandboxProviderRequest) (*pluginsdk.DescribeSandboxProviderResponse, error) {
	reply, err := replyContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if !supportedHost(req.Runtime) {
		return nil, status.Error(codes.FailedPrecondition, "unsupported sandbox host")
	}
	return &pluginsdk.DescribeSandboxProviderResponse{Context: reply, Description: &pluginsdk.SandboxProviderDescription{
		DisplayName: "Nono", ProviderVersion: providerVersion, RuntimeVersion: runtimeVersion,
		RuntimeSources: []*pluginsdk.SandboxRuntimeSource{
			{Key: "nono.session-registry.v1", Kind: "identity", RelativeDirectory: "nono/sessions", FilenameSuffix: ".json", MaxDepth: 1, MaxFiles: 16, MaxBytes: 64 << 10},
			{Key: "nono.audit.v1", Kind: "audit", RelativeDirectory: "nono/audit", FilenameSuffix: "audit-events.ndjson", MaxDepth: 2, MaxFiles: 16, MaxBytes: 1 << 20},
		},
		ApprovalWire:        &pluginsdk.SandboxApprovalWire{ContentType: "application/json", AllowOnceBodyUtf8: `{"decision":"granted"}`, DenyBodyUtf8: `{"decision":"denied"}`, TimeoutBodyUtf8: `{"decision":"timeout"}`},
		RuntimeArtifact:     &pluginsdk.SandboxRuntimeArtifact{RelativePath: "runtime/nono-linux-amd64", Sha256: runtimeDigest},
		SupportedTransports: []string{"local", "worktree"},
		SupportedFeatures:   []string{"filesystem", "network_proxy", "approval_webhook"},
		ReportClasses:       []string{"filesystem"},
		Limitations:         []string{"Linux amd64 only. Kernel enforcement is verified at launch.", "Network grants authorize destination TCP connections through the proxy.", "Audit reports cover filesystem capability decisions only. Other denials are not recorded."},
	}}, nil
}
