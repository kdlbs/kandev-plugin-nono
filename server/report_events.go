package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func normalizeReportEvent(raw json.RawMessage, sequence uint64, req *pluginsdk.ReadSandboxReportRequest) (*pluginsdk.SandboxAuditEventV2, error) {
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return nil, invalidAudit()
	}
	event := &pluginsdk.SandboxAuditEventV2{RecordId: fmt.Sprintf("event-%d", sequence), SourceId: req.ChunkV2.SourceId, Sequence: sequence, PolicyDigest: req.Policy.Digest, AttemptId: req.Context.AttemptId, Generation: req.Context.Generation}
	var err error
	switch header.Type {
	case "session_started", "session_ended", "sandbox_runtime":
		return nil, nil
	case "network":
		err = normalizeNetworkReport(raw, event)
	case "command_policy":
		err = normalizeCommandReport(raw, event)
	case "capability_decision":
		err = normalizeCapabilityReport(raw, event, req.ChunkV2.ProviderSessionId)
	case "url_open":
		return nil, status.Error(codes.Unimplemented, "URL-open audit evidence is unsupported")
	default:
		return nil, status.Error(codes.Unimplemented, "unsupported sandbox audit event")
	}
	if err != nil {
		return nil, err
	}
	if event.Operation == nil {
		return nil, nil
	}
	if event.OccurredAtUnixMs <= 0 || event.OccurredAtUnixMs > time.Now().Add(5*time.Second).UnixMilli() {
		return nil, invalidAudit()
	}
	return event, nil
}

type networkReportEvent struct {
	Event struct {
		Timestamp      uint64  `json:"timestamp_unix_ms"`
		Mode           string  `json:"mode"`
		Decision       string  `json:"decision"`
		Target         string  `json:"target"`
		Port           *uint16 `json:"port"`
		Method         *string `json:"method"`
		Path           *string `json:"path"`
		Upstream       *string `json:"upstream"`
		RouteID        *string `json:"route_id"`
		DenialCategory *string `json:"denial_category"`
	} `json:"event"`
}

func normalizeNetworkReport(raw json.RawMessage, result *pluginsdk.SandboxAuditEventV2) error {
	var event networkReportEvent
	if json.Unmarshal(raw, &event) != nil || event.Event.Timestamp > 1<<63-1 {
		return invalidAudit()
	}
	value := event.Event
	result.OccurredAtUnixMs = int64(value.Timestamp)
	decision, reason, err := networkReportDecision(value.Decision)
	if err != nil {
		return err
	}
	result.Decision, result.ReasonCode = decision, reason
	if value.DenialCategory != nil {
		result.ReasonCode = networkReportReason(*value.DenialCategory, reason)
	}
	if value.Method != nil && value.Path != nil {
		operation, err := partialAuditEndpoint(value.Upstream, value.RouteID, *value.Method, *value.Path)
		if err != nil {
			return err
		}
		result.Operation = &pluginsdk.SandboxOperationV2{Value: &pluginsdk.SandboxOperationV2_HttpEndpoint{HttpEndpoint: operation}}
		return nil
	}
	port := uint32(0)
	if value.Port != nil {
		port = uint32(*value.Port)
	}
	host := strings.ToLower(value.Target)
	hostKnown := validDestination(host, max(port, 1))
	if !hostKnown {
		host = ""
	}
	result.Operation = &pluginsdk.SandboxOperationV2{Value: &pluginsdk.SandboxOperationV2_Tcp{Tcp: &pluginsdk.SandboxTCPDestinationV2{Host: host, Port: port, Transport: "tcp"}}}
	result.ExactTarget = port != 0 && hostKnown
	return nil
}

func networkReportDecision(value string) (string, string, error) {
	switch value {
	case "allow":
		return "allowed", "", nil
	case "deny":
		return "denied", "permission_denied", nil
	case "approve_requested":
		return "approval_requested", "", nil
	case "approve_granted":
		return "approval_granted", "approval_granted", nil
	case "approve_denied":
		return "approval_denied", "approval_denied", nil
	case "approve_timeout":
		return "approval_denied", "approval_timeout", nil
	case "approve_error":
		return "error", "upstream_unavailable", nil
	default:
		return "", "", status.Error(codes.Unimplemented, "unsupported network audit decision")
	}
}

func networkReportReason(category, fallback string) string {
	switch category {
	case "authentication_failed", "managed_credential_unavailable":
		return "authentication_failed"
	case "upstream_connect_failed", "intercept_handshake_failed", "external_proxy_rejected":
		return "upstream_unavailable"
	case "connect_bypasses_l7", "unsupported_upgrade":
		return "unsupported_protocol"
	case "endpoint_policy", "host_denied":
		return "permission_denied"
	default:
		return fallback
	}
}
