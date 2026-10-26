package main

import (
	"context"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (p *nonoPlugin) ProposeSandboxRevision(ctx context.Context, req *pluginsdk.ProposeSandboxRevisionRequest) (*pluginsdk.ProposeSandboxRevisionResponse, error) {
	reply, err := replyContext(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	if req.Policy == nil || req.Policy.Grants == nil || len(req.SelectedRecords) == 0 || len(req.SelectedRecords) > 256 {
		return nil, status.Error(codes.InvalidArgument, "selected denial records are required")
	}
	added := &pluginsdk.SandboxGrants{}
	ids := make([]string, 0, len(req.SelectedRecords))
	seen := map[string]bool{}
	for _, record := range req.SelectedRecords {
		if record == nil || !boundedIdentity(record.RecordId) || seen[record.RecordId] || record.PolicyDigest != req.Policy.Digest || record.AttemptId != req.Context.AttemptId || (record.Operation != "read" && record.Operation != "write") {
			return nil, status.Error(codes.InvalidArgument, "invalid selected denial record")
		}
		seen[record.RecordId] = true
		ids = append(ids, record.RecordId)
		added.Filesystem = append(added.Filesystem, &pluginsdk.SandboxFilesystemGrant{Path: record.Target, Writable: record.Operation == "write"})
	}
	candidate := proto.Clone(req.Policy).(*pluginsdk.SandboxPolicySnapshot)
	proto.Merge(candidate.Grants, added)
	compiled, err := p.CompileSandboxPolicy(ctx, &pluginsdk.CompileSandboxPolicyRequest{Context: req.Context, Policy: candidate, Runtime: req.Runtime, References: req.References, Endpoints: req.Endpoints})
	if err != nil {
		return nil, err
	}
	return &pluginsdk.ProposeSandboxRevisionResponse{Context: reply, AddedGrants: added, SourceRecordIds: ids, Compiled: compiled.Compiled}, nil
}
