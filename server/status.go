package main

import (
	"context"
	"encoding/json"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type sessionRegistryRecord struct {
	SessionID       string          `json:"session_id"`
	Name            *string         `json:"name"`
	SupervisorPID   int64           `json:"supervisor_pid"`
	ChildPID        int64           `json:"child_pid"`
	Started         string          `json:"started"`
	StartedEpoch    uint64          `json:"started_epoch"`
	Status          string          `json:"status"`
	Attachment      string          `json:"attachment"`
	ExitCode        *int            `json:"exit_code"`
	Command         json.RawMessage `json:"command"`
	Profile         *string         `json:"profile"`
	WorkDir         string          `json:"workdir"`
	Network         string          `json:"network"`
	RollbackSession *string         `json:"rollback_session"`
}

func (*nonoPlugin) NormalizeSandboxStatus(ctx context.Context, req *pluginsdk.NormalizeSandboxStatusRequest) (*pluginsdk.NormalizeSandboxStatusResponse, error) {
	reply, err := replyContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if req.Process == nil || req.Process.Pid <= 0 || req.Process.BirthId == "" || req.EvidenceSchema != "nono.session-registry.v1" || len(req.Evidence) > 64<<10 {
		return nil, status.Error(codes.InvalidArgument, "invalid runtime identity evidence")
	}
	var record sessionRegistryRecord
	if decodeStrictJSON(req.Evidence, &record) != nil || !validRegistryIdentity(record, req.Process.Pid) {
		return nil, status.Error(codes.InvalidArgument, "runtime identity does not match the owned supervisor")
	}
	return &pluginsdk.NormalizeSandboxStatusResponse{Context: reply, Identity: &pluginsdk.SandboxRuntimeIdentity{SupervisorPid: record.SupervisorPID, ChildPid: record.ChildPID, ProviderSessionId: record.SessionID}}, nil
}

func validRegistryIdentity(record sessionRegistryRecord, supervisor int64) bool {
	return record.SupervisorPID == supervisor && record.ChildPID > 0 && record.ChildPID < 1<<31 && record.ChildPID != supervisor && boundedIdentity(record.SessionID) && record.StartedEpoch > 0 &&
		(record.Status == "running" || record.Status == "paused") && record.ExitCode == nil
}
