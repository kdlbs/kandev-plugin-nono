package main

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/kdlbs/kandev/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type commandReportEvent struct {
	Event struct {
		Timestamp string `json:"timestamp"`
		Command   string `json:"command"`
		Caller    string `json:"caller"`
		Decision  string `json:"decision"`
	} `json:"event"`
}

func normalizeCommandReport(raw json.RawMessage, result *pluginsdk.SandboxAuditEventV2) error {
	var event commandReportEvent
	if json.Unmarshal(raw, &event) != nil {
		return invalidAudit()
	}
	value := event.Event
	observed, err := time.Parse(time.RFC3339Nano, value.Timestamp)
	if err != nil || !safeCommandReportName(value.Command) || !safeReportLabel(value.Caller) {
		return invalidAudit()
	}
	result.OccurredAtUnixMs = observed.UnixMilli()
	decision, reason, err := commandReportDecision(value.Decision)
	if err != nil {
		return err
	}
	if decision == "" {
		return nil
	}
	result.Decision, result.ReasonCode = decision, reason
	// The event contains redacted display strings and hashes, not exact argv or resources.
	result.Operation = &pluginsdk.SandboxOperationV2{Value: &pluginsdk.SandboxOperationV2_Command{Command: &pluginsdk.SandboxCommandInvocationV2{CommandId: value.Command, Caller: value.Caller}}}
	return nil
}

func commandReportDecision(value string) (string, string, error) {
	switch value {
	case "allow", "allowed", "capture", "capture_credential", "capture_credential_cached", "exec", "respond":
		return "allowed", "", nil
	case "deny", "denied", "invocation_denied":
		return "denied", "permission_denied", nil
	case "approve_denied", "invocation_approve_denied":
		return "approval_denied", "approval_denied", nil
	case "approve_granted", "invocation_allowed", "invocation_approve_granted":
		return "", "", nil
	default:
		return "", "", status.Error(codes.Unimplemented, "unsupported command audit decision")
	}
}

func safeCommandReportName(value string) bool {
	return safeReportLabel(value) && !strings.ContainsAny(value, "/\\ ")
}
func safeReportLabel(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsFunc(value, unicode.IsControl)
}
