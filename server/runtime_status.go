package main

import (
	"encoding/json"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type runtimeAuditEvent struct {
	Type  string `json:"type"`
	Event struct {
		Timestamp        string  `json:"timestamp"`
		Platform         string  `json:"platform"`
		LandlockABI      *string `json:"landlock_abi"`
		ExecuteEnforced  *bool   `json:"landlock_execute_enforced"`
		CommandMediation *bool   `json:"tool_sandbox_active"`
	} `json:"event"`
}

func normalizeRuntimeStatus(req *pluginsdk.NormalizeSandboxStatusRequest, reply *pluginsdk.SandboxResponseContext) (*pluginsdk.NormalizeSandboxStatusResponse, error) {
	if req.Process == nil || req.Process.Pid <= 0 || req.Process.BirthId == "" || !boundedIdentity(req.ProviderSessionIdV2) || strings.ContainsAny(req.ProviderSessionIdV2, "/\\") || !validAuditSource(req.SourceRelativePathV2) {
		return nil, status.Error(codes.InvalidArgument, "invalid runtime source binding")
	}
	result := &pluginsdk.NormalizeSandboxStatusResponse{Context: reply}
	// Audit entries contain no session identity. Only core's captured session path binds them.
	if req.SourceRelativePathV2 != "nono/audit/"+req.ProviderSessionIdV2+"/audit-events.ndjson" {
		return result, nil
	}
	events, err := verifyAuditChain(req.Evidence)
	if err != nil {
		return nil, err
	}
	for _, raw := range events {
		var event runtimeAuditEvent
		if json.Unmarshal(raw, &event) != nil {
			return nil, invalidAudit()
		}
		if event.Type != "sandbox_runtime" {
			continue
		}
		if len(result.ObservationsV2) != 0 || decodeStrictJSON(raw, &event) != nil {
			return nil, invalidAudit()
		}
		fact, err := runtimeObservation(event)
		if err != nil {
			return nil, err
		}
		result.ObservationsV2 = append(result.ObservationsV2, fact)
	}
	return result, nil
}

func validAuditSource(value string) bool {
	return value != "" && len(value) <= 512 && !path.IsAbs(value) && path.Clean(value) == value && !strings.Contains(value, "\\") && !strings.HasPrefix(value, "../")
}

func runtimeObservation(event runtimeAuditEvent) (*pluginsdk.SandboxRuntimeObservationV2, error) {
	observed, err := time.Parse(time.RFC3339Nano, event.Event.Timestamp)
	if err != nil || observed.UnixMilli() <= 0 || observed.After(time.Now()) || event.Event.Platform != "linux" || event.Event.CommandMediation == nil {
		return nil, invalidAudit()
	}
	fact := &pluginsdk.SandboxRuntimeObservationV2{SourceId: "nono.audit.v1", ObservedAtUnixMs: observed.UnixMilli(), Platform: event.Event.Platform, ExecuteEnforced: event.Event.ExecuteEnforced, CommandMediationActive: event.Event.CommandMediation, Limitations: []string{"historical-runtime-event", "no-current-policy-attestation"}}
	if event.Event.LandlockABI != nil {
		raw := *event.Event.LandlockABI
		abi, err := strconv.ParseUint(strings.TrimPrefix(raw, "v"), 10, 32)
		if err != nil || abi == 0 || raw != "v"+strconv.FormatUint(abi, 10) {
			return nil, invalidAudit()
		}
		value := uint32(abi)
		fact.LandlockAbi = &value
	}
	return fact, nil
}
