package main

import (
	"encoding/json"

	"github.com/kdlbs/kandev/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type approvalAuditEvent struct {
	Entry struct {
		Timestamp struct {
			Seconds int64 `json:"secs_since_epoch"`
			Nanos   int64 `json:"nanos_since_epoch"`
		} `json:"timestamp"`
		Request  json.RawMessage `json:"request"`
		Decision json.RawMessage `json:"decision"`
	} `json:"entry"`
}

func normalizeCapabilityReport(raw json.RawMessage, result *pluginsdk.SandboxAuditEventV2, session string) error {
	var event approvalAuditEvent
	if json.Unmarshal(raw, &event) != nil || event.Entry.Timestamp.Seconds < 0 || event.Entry.Timestamp.Seconds > 9223372036854774 || event.Entry.Timestamp.Nanos < 0 || event.Entry.Timestamp.Nanos >= 1e9 {
		return invalidAudit()
	}
	var kind struct {
		Type      string `json:"capability_type"`
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(event.Entry.Request, &kind) != nil || !boundedIdentity(kind.RequestID) {
		return invalidAudit()
	}
	result.RecordId = kind.RequestID
	result.OccurredAtUnixMs = event.Entry.Timestamp.Seconds*1000 + event.Entry.Timestamp.Nanos/1e6
	decision, reason, err := approvalReportDecision(event.Entry.Decision)
	if err != nil {
		return err
	}
	result.Decision, result.ReasonCode = decision, reason
	switch kind.Type {
	case "capability":
		var request capabilityRequest
		if json.Unmarshal(event.Entry.Request, &request) != nil || !validCapabilityRequest(request) || request.SessionID != session {
			return invalidAudit()
		}
		access := "read"
		if request.Access == "Write" {
			access = "write"
		} else if request.Access == "ReadWrite" {
			access = "read_write"
		}
		result.Operation = &pluginsdk.SandboxOperationV2{Value: &pluginsdk.SandboxOperationV2_Filesystem{Filesystem: &pluginsdk.SandboxFilesystemOperationV2{Path: request.Path, Access: access}}}
		result.ExactTarget = true
	case "network":
		return normalizeNetworkApprovalReport(event.Entry.Request, result)
	case "command":
		return normalizeCommandApprovalReport(event.Entry.Request, result)
	case "endpoint":
		return normalizeEndpointApprovalReport(event.Entry.Request, result)
	default:
		return status.Error(codes.Unimplemented, "unsupported capability audit kind")
	}
	return nil
}

func approvalReportDecision(raw json.RawMessage) (string, string, error) {
	var name string
	if json.Unmarshal(raw, &name) != nil {
		var value map[string]json.RawMessage
		if json.Unmarshal(raw, &value) != nil || len(value) != 1 || value["Denied"] == nil {
			return "", "", invalidAudit()
		}
		name = "Denied"
	}
	switch name {
	case "Granted", "GrantedForSession":
		return "approval_granted", "approval_granted", nil
	case "Denied", "DeniedForSession":
		return "approval_denied", "approval_denied", nil
	case "Timeout":
		return "approval_denied", "approval_timeout", nil
	default:
		return "", "", status.Error(codes.Unimplemented, "unsupported capability audit decision")
	}
}

func normalizeNetworkApprovalReport(raw json.RawMessage, result *pluginsdk.SandboxAuditEventV2) error {
	var request struct {
		Host     string `json:"host"`
		Port     uint32 `json:"port"`
		Protocol string `json:"protocol"`
	}
	if json.Unmarshal(raw, &request) != nil || request.Protocol != "tcp" || !validDestination(request.Host, request.Port) {
		return invalidAudit()
	}
	result.Operation = &pluginsdk.SandboxOperationV2{Value: &pluginsdk.SandboxOperationV2_Tcp{Tcp: &pluginsdk.SandboxTCPDestinationV2{Host: request.Host, Port: request.Port, Transport: "tcp"}}}
	result.ExactTarget = true
	return nil
}

func normalizeCommandApprovalReport(raw json.RawMessage, result *pluginsdk.SandboxAuditEventV2) error {
	var request struct {
		Command string `json:"command"`
		Caller  string `json:"caller"`
	}
	if json.Unmarshal(raw, &request) != nil || !safeCommandReportName(request.Command) || !safeReportLabel(request.Caller) {
		return invalidAudit()
	}
	result.Operation = &pluginsdk.SandboxOperationV2{Value: &pluginsdk.SandboxOperationV2_Command{Command: &pluginsdk.SandboxCommandInvocationV2{CommandId: request.Command, Caller: request.Caller}}}
	return nil
}

func normalizeEndpointApprovalReport(raw json.RawMessage, result *pluginsdk.SandboxAuditEventV2) error {
	var request struct {
		RouteID  string `json:"route_id"`
		Upstream string `json:"upstream"`
		Method   string `json:"method"`
	}
	if json.Unmarshal(raw, &request) != nil {
		return invalidAudit()
	}
	// Approval audit requests can contain unsanitized path/argv. Inspect only bounded scope.
	endpoint, err := partialAuditEndpoint(&request.Upstream, &request.RouteID, request.Method, "")
	if err != nil {
		return err
	}
	result.Operation = &pluginsdk.SandboxOperationV2{Value: &pluginsdk.SandboxOperationV2_HttpEndpoint{HttpEndpoint: endpoint}}
	return nil
}
