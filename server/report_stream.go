package main

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const maximumReportBytes = 32 << 20
const maximumReportSources = 32
const maximumReportStreams = 8
const maximumReportEvents = 65536

type reportStreamCache struct {
	mu      sync.Mutex
	streams map[string]*auditReportStream
}

type auditReportStream struct {
	context                 *pluginsdk.SandboxRequestContext
	policy                  *pluginsdk.SandboxPolicySnapshot
	handle, digest, session string
	sourceCount             uint32
	sequence                uint64
	totalBytes              uint64
	source                  *auditStreamSource
	bindings                []auditSourceBinding
	seenIDs                 map[string]bool
	eventCount              uint64
	hasAudit                bool
	previous                *string
	leaves                  [][32]byte
	tail                    bool
	complete                bool
	timer                   *time.Timer
	metadata                *auditSessionSummary
	verify                  bool
	trust                   *pluginsdk.SandboxAuditTrustV2
	artifacts               map[string][]byte
}

type auditSourceBinding struct {
	ID     string `json:"id"`
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

func (p *nonoPlugin) readStreamReport(ctx context.Context, req *pluginsdk.ReadSandboxReportRequest, reply *pluginsdk.SandboxResponseContext) (*pluginsdk.ReadSandboxReportResponse, error) {
	if err := validateReportChunk(req); err != nil {
		return nil, err
	}
	p.reports.mu.Lock()
	defer p.reports.mu.Unlock()
	if p.reports.streams == nil {
		p.reports.streams = make(map[string]*auditReportStream)
	}
	stream, err := p.admitReportStream(req)
	if err != nil {
		return nil, err
	}
	result, err := stream.consume(ctx, req)
	if err != nil {
		stream.release()
		return nil, err
	}
	response := &pluginsdk.ReadSandboxReportResponse{Context: reply, ReportV2: result}
	if proto.Size(response) > 250<<10 {
		stream.release()
		return nil, status.Error(codes.ResourceExhausted, "sandbox report output limit exceeded")
	}
	return response, nil
}

func (p *nonoPlugin) admitReportStream(req *pluginsdk.ReadSandboxReportRequest) (*auditReportStream, error) {
	chunk := req.ChunkV2
	if stream := p.reports.streams[chunk.OperationHandle]; stream != nil {
		if !stream.matches(req) {
			return nil, invalidAudit()
		}
		if stream.complete || stream.sequence != chunk.Sequence {
			stream.release()
			return nil, invalidAudit()
		}
		return stream, nil
	}
	if chunk.Sequence != 0 || chunk.SourceIndex != 0 {
		return nil, invalidAudit()
	}
	if len(p.reports.streams) >= maximumReportStreams {
		return nil, status.Error(codes.ResourceExhausted, "sandbox report verifier capacity exceeded")
	}
	stream := &auditReportStream{context: proto.Clone(req.Context).(*pluginsdk.SandboxRequestContext), policy: proto.Clone(req.Policy).(*pluginsdk.SandboxPolicySnapshot), handle: chunk.OperationHandle, digest: chunk.ArtifactSetDigest, session: chunk.ProviderSessionId, sourceCount: chunk.SourceCount, seenIDs: map[string]bool{}}
	stream.verify = req.VerifyAuditV2 || req.TrustV2 != nil
	if req.TrustV2 != nil {
		stream.trust = proto.Clone(req.TrustV2).(*pluginsdk.SandboxAuditTrustV2)
	}
	if stream.verify {
		stream.artifacts = map[string][]byte{}
	}
	p.reports.streams[chunk.OperationHandle] = stream
	expires := min(time.Until(time.UnixMilli(req.Context.DeadlineUnixMs)), 30*time.Second)
	handle := chunk.OperationHandle
	stream.timer = time.AfterFunc(expires, func() {
		p.reports.mu.Lock()
		defer p.reports.mu.Unlock()
		if p.reports.streams[handle] == stream {
			delete(p.reports.streams, handle)
		}
	})
	return stream, nil
}

func (s *auditReportStream) matches(req *pluginsdk.ReadSandboxReportRequest) bool {
	a, b := s.context, req.Context
	chunk := req.ChunkV2
	return a.AttemptId == b.AttemptId && a.ExecutionId == b.ExecutionId && a.Generation == b.Generation && a.InstallationId == b.InstallationId && a.ProviderKey == b.ProviderKey && proto.Equal(s.policy, req.Policy) && s.digest == chunk.ArtifactSetDigest && s.session == chunk.ProviderSessionId && s.sourceCount == chunk.SourceCount && s.verify == (req.VerifyAuditV2 || req.TrustV2 != nil) && proto.Equal(s.trust, req.TrustV2)
}

func (s *auditReportStream) release() {
	s.complete = true
	s.source = nil
	s.leaves = nil
	s.seenIDs = nil
	s.artifacts = nil
}

func (s *auditReportStream) result(ctx context.Context, events []*pluginsdk.SandboxAuditEventV2) (*pluginsdk.SandboxReportV2, error) {
	result := &pluginsdk.SandboxReportV2{Events: events, Coverage: reportCoverage(), Integrity: "unchecked", Finalization: "live", OperationHandle: s.handle, ArtifactSetDigest: s.digest, NextSequence: s.sequence}
	if uint32(len(s.bindings)) != s.sourceCount || s.source != nil {
		return result, nil
	}
	raw, err := json.Marshal(s.bindings)
	if err != nil || streamHash(raw) != s.digest {
		return nil, invalidAudit()
	}
	if !s.hasAudit {
		for _, coverage := range result.Coverage {
			coverage.Coverage = "unavailable"
		}
	}
	if s.hasAudit && !s.tail {
		result.Integrity = "valid"
	}
	if s.metadata != nil {
		if err = s.verifyFinalMetadata(); err != nil {
			return nil, err
		}
		if s.metadata.Ended != nil {
			result.Finalization = "final"
		}
	}
	if s.verify {
		if err = s.verifyArtifacts(ctx, result); err != nil {
			return nil, err
		}
	}
	s.release()
	return result, nil
}

func reportCoverage() []*pluginsdk.SandboxReportCoverageV2 {
	return []*pluginsdk.SandboxReportCoverageV2{{OperationKind: "filesystem", Coverage: "partial"}, {OperationKind: "network", Coverage: "partial"}, {OperationKind: "command", Coverage: "partial"}, {OperationKind: "http_endpoint", Coverage: "partial"}}
}
