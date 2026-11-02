package main

import (
	"context"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	providerVersion  = "0.1.0"
	runtimeVersion   = "0.81.0"
	runtimeDigest    = "2d3c29641c87921f7cd469387e4838b1676d54edb7291aebda7a780787d7c1b2"
	approvalEndpoint = "sandbox.approval.endpoint"
)

type nonoPlugin struct {
	pluginsdk.UnimplementedPlugin
	reports reportStreamCache
}

func replyContext(ctx context.Context, req *pluginsdk.SandboxRequestContext) (*pluginsdk.SandboxResponseContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil || (req.ProtocolMajor != 1 && req.ProtocolMajor != 2) || req.ProviderKey != "nono" || req.InstallationId == "" || req.OperationId == "" || req.AttemptId == "" || req.Generation == 0 || req.DeadlineUnixMs <= time.Now().UnixMilli() {
		return nil, status.Error(codes.InvalidArgument, "invalid sandbox operation")
	}
	return &pluginsdk.SandboxResponseContext{SchemaVersion: req.ProtocolMajor, OperationId: req.OperationId}, nil
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
	result := &pluginsdk.DescribeSandboxProviderResponse{Context: reply, Description: &pluginsdk.SandboxProviderDescription{
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
		Limitations:         []string{"Linux amd64 only. Process ownership and launch checks do not attest current kernel confinement.", "Network grants authorize destination TCP connections through the proxy.", "Audit reports cover filesystem capability decisions only. Other denials are not recorded."},
	}}
	if req.Context.ProtocolMajor == 2 {
		result.Description.CapabilitiesV2 = &pluginsdk.SandboxCapabilitiesV2{PolicySchemas: []uint32{1}, OperationKinds: []string{"filesystem"}, ActorKinds: []string{"child_process"}, NetworkMode: "static_egress", ObservationSchemas: []string{"nono.audit.v1"}, ReportSchemas: []string{pluginsdk.SandboxReportSchemaV2}}
		result.Description.CapabilitiesV2.AuditVerificationFormats = []string{"nono.audit-session.alpha"}
		result.Description.RuntimeSources[1].MaxBytes = maximumReportBytes
		result.Description.RuntimeSources = append(result.Description.RuntimeSources, &pluginsdk.SandboxRuntimeSource{Key: "nono.session.v1", Kind: "audit_final", RelativeDirectory: "nono/audit", FilenameSuffix: "session.json", MaxDepth: 2, MaxFiles: 16, MaxBytes: 8 << 20})
		result.Description.RuntimeSources = append(result.Description.RuntimeSources,
			&pluginsdk.SandboxRuntimeSource{Key: "nono.attestation.v1", Kind: "audit_final", RelativeDirectory: "nono/audit", FilenameSuffix: "audit-attestation.bundle", MaxDepth: 2, MaxFiles: 16, MaxBytes: 8 << 20},
			&pluginsdk.SandboxRuntimeSource{Key: "nono.ledger.v1", Kind: "audit_final", RelativeDirectory: "nono/audit", FilenameSuffix: "ledger.ndjson", MaxDepth: 1, MaxFiles: 1, MaxBytes: maximumReportBytes})
		result.Description.Limitations[2] = "Typed reports cover recorded filesystem, network, command and endpoint decisions. Coverage is partial. Redacted identities cannot authorize policy learning."
	}
	return result, nil
}
