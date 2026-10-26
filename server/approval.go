package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type approvalEvent struct {
	Backend string            `json:"backend"`
	Request capabilityRequest `json:"request"`
}
type capabilityRequest struct {
	CapabilityType string  `json:"capability_type"`
	RequestID      string  `json:"request_id"`
	SessionID      string  `json:"session_id"`
	ChildPID       int64   `json:"child_pid"`
	Path           string  `json:"path"`
	Access         string  `json:"access"`
	Reason         *string `json:"reason"`
}

func (*nonoPlugin) NormalizeSandboxApproval(ctx context.Context, req *pluginsdk.NormalizeSandboxApprovalRequest) (*pluginsdk.NormalizeSandboxApprovalResponse, error) {
	reply, err := replyContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	var event approvalEvent
	if req.Policy == nil || len(req.VerifiedEvent) > 64<<10 || decodeStrictJSON(req.VerifiedEvent, &event) != nil || event.Backend != "kandev" || !validCapabilityRequest(event.Request) {
		return nil, status.Error(codes.InvalidArgument, "invalid sandbox approval event")
	}
	access := "read"
	if event.Request.Access != "Read" {
		access = "write"
	}
	return &pluginsdk.NormalizeSandboxApprovalResponse{Context: reply, Operation: &pluginsdk.SandboxApprovalOperation{
		RequestId: event.Request.RequestID, ProviderSessionId: event.Request.SessionID, ChildPid: event.Request.ChildPID,
		Kind: pluginsdk.SandboxOperationFilesystem, Target: event.Request.Path, Access: access,
		SupportedDecisions: []string{pluginsdk.SandboxDecisionDeny, pluginsdk.SandboxDecisionAllowOnce},
	}}, nil
}

func validCapabilityRequest(req capabilityRequest) bool {
	return req.CapabilityType == "capability" && boundedIdentity(req.RequestID) && boundedIdentity(req.SessionID) && req.ChildPID > 0 && req.ChildPID < 1<<31 &&
		filepath.IsAbs(req.Path) && filepath.Clean(req.Path) == req.Path && len(req.Path) <= 4096 && !strings.ContainsFunc(req.Path, unicode.IsControl) &&
		(req.Access == "Read" || req.Access == "Write" || req.Access == "ReadWrite")
}
func boundedIdentity(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsFunc(value, unicode.IsControl)
}
func decodeStrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return status.Error(codes.InvalidArgument, "invalid JSON framing")
	}
	return nil
}
