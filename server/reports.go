package main

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var _ pluginsdk.SandboxProviderPlugin = (*nonoPlugin)(nil)

func (*nonoPlugin) ReadSandboxReport(ctx context.Context, req *pluginsdk.ReadSandboxReportRequest) (*pluginsdk.ReadSandboxReportResponse, error) {
	reply, err := replyContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if req.Policy == nil || req.Policy.Digest == "" {
		return nil, status.Error(codes.InvalidArgument, "report policy is required")
	}
	records, err := verifyAuditChain(req.Audit)
	if err != nil {
		return nil, err
	}
	offset := 0
	if req.Cursor != "" {
		offset, err = strconv.Atoi(req.Cursor)
		if err != nil || offset < 0 || offset > len(records) {
			return nil, status.Error(codes.InvalidArgument, "invalid report cursor")
		}
	}
	result := &pluginsdk.ReadSandboxReportResponse{Context: reply, Integrity: pluginsdk.SandboxReportPartial}
	for index := offset; index < len(records); index++ {
		record, err := denialRecord(records[index], req)
		if err != nil {
			return nil, err
		}
		if record == nil {
			continue
		}
		result.Records = append(result.Records, record)
		if len(result.Records) > 1000 || proto.Size(result) > 250<<10 {
			result.Records = result.Records[:len(result.Records)-1]
			result.NextCursor = strconv.Itoa(index)
			break
		}
	}
	return result, nil
}

type capabilityAuditEvent struct {
	Type  string `json:"type"`
	Entry struct {
		Timestamp struct {
			Seconds int64 `json:"secs_since_epoch"`
			Nanos   int64 `json:"nanos_since_epoch"`
		} `json:"timestamp"`
		Request  capabilityRequest `json:"request"`
		Decision json.RawMessage   `json:"decision"`
	} `json:"entry"`
}

func denialRecord(raw json.RawMessage, req *pluginsdk.ReadSandboxReportRequest) (*pluginsdk.SandboxDenialRecord, error) {
	var event capabilityAuditEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, invalidAudit()
	}
	if event.Type != "capability_decision" || event.Entry.Request.CapabilityType != "capability" {
		return nil, nil
	}
	var decision map[string]json.RawMessage
	if json.Unmarshal(event.Entry.Decision, &decision) != nil || decision["Denied"] == nil {
		return nil, nil
	}
	if !validCapabilityRequest(event.Entry.Request) || event.Entry.Timestamp.Seconds < 0 || event.Entry.Timestamp.Seconds > 9223372036854774 || event.Entry.Timestamp.Nanos < 0 || event.Entry.Timestamp.Nanos >= 1e9 {
		return nil, invalidAudit()
	}
	operation := "read"
	if event.Entry.Request.Access != "Read" {
		operation = "write"
	}
	return &pluginsdk.SandboxDenialRecord{RecordId: event.Entry.Request.RequestID, Operation: operation, Target: event.Entry.Request.Path, OccurredAtUnixMs: event.Entry.Timestamp.Seconds*1000 + event.Entry.Timestamp.Nanos/1e6, PolicyDigest: req.Policy.Digest, AttemptId: req.Context.AttemptId}, nil
}
