package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"strings"
	"unicode"

	"github.com/kdlbs/kandev/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type auditStreamSource struct {
	header   *pluginsdk.SandboxAuditChunkV2
	digest   hash.Hash
	bytes    uint64
	pending  []byte
	metadata []byte
	owned    bool
}

func validateReportChunk(req *pluginsdk.ReadSandboxReportRequest) error {
	chunk := req.ChunkV2
	if req.Context.ProtocolMajor != 2 || req.Policy == nil || !validStreamDigest(req.Policy.Digest) || chunk == nil || !validStreamDigest(chunk.ArtifactSetDigest) || !validStreamDigest(chunk.SourceDigest) || !validStreamDigest(chunk.SourceId) {
		return invalidAudit()
	}
	if !boundedIdentity(chunk.OperationHandle) || !boundedIdentity(chunk.ProviderSessionId) || strings.ContainsAny(chunk.ProviderSessionId, "/\\") || !validAuditSource(chunk.SourceRelativePath) || strings.ContainsFunc(chunk.SourceRelativePath, unicode.IsControl) || chunk.SourceCount == 0 || chunk.SourceCount > maximumReportSources || chunk.SourceIndex >= chunk.SourceCount {
		return invalidAudit()
	}
	if len(chunk.Content) > 256<<10 || len(chunk.Content) == 0 && !chunk.Final || chunk.TotalBytes > maximumReportBytes || uint64(len(chunk.Content)) > chunk.TotalBytes {
		return invalidAudit()
	}
	if auditSourceFilename(chunk.SourceSchema) == "" {
		return status.Error(codes.Unimplemented, "unsupported sandbox audit source schema")
	}
	expected := streamHash([]byte(chunk.SourceSchema + "\x00" + chunk.SourceRelativePath))
	if expected != chunk.SourceId {
		return invalidAudit()
	}
	return nil
}

func (s *auditReportStream) consume(ctx context.Context, req *pluginsdk.ReadSandboxReportRequest) (*pluginsdk.SandboxReportV2, error) {
	chunk := req.ChunkV2
	if s.source == nil {
		if err := s.beginSource(chunk); err != nil {
			return nil, err
		}
	}
	source := s.source
	if !sameStreamSource(source.header, chunk) || source.bytes+uint64(len(chunk.Content)) > chunk.TotalBytes {
		return nil, invalidAudit()
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_, _ = source.digest.Write(chunk.Content)
	source.bytes += uint64(len(chunk.Content))
	events, err := s.consumeSource(ctx, req, chunk.Content)
	if err != nil {
		return nil, err
	}
	if chunk.Final {
		if err = s.finishSource(); err != nil {
			return nil, err
		}
	}
	s.sequence++
	return s.result(ctx, events)
}

func (s *auditReportStream) beginSource(chunk *pluginsdk.SandboxAuditChunkV2) error {
	if chunk.SourceIndex != uint32(len(s.bindings)) || s.totalBytes+chunk.TotalBytes > maximumReportBytes {
		return invalidAudit()
	}
	for _, source := range s.bindings {
		if source.ID == chunk.SourceId {
			return invalidAudit()
		}
	}
	header := proto.Clone(chunk).(*pluginsdk.SandboxAuditChunkV2)
	header.Content = nil
	name := auditSourceFilename(chunk.SourceSchema)
	owned := chunk.SourceRelativePath == "nono/audit/"+s.session+"/"+name
	if chunk.SourceSchema == "nono.ledger.v1" {
		owned = chunk.SourceRelativePath == "nono/audit/ledger.ndjson"
	}
	s.source = &auditStreamSource{header: header, digest: sha256.New(), owned: owned}
	if owned && chunk.SourceSchema == "nono.audit.v1" {
		s.hasAudit = true
	}
	s.totalBytes += chunk.TotalBytes
	return nil
}

func sameStreamSource(a, b *pluginsdk.SandboxAuditChunkV2) bool {
	return a.SourceId == b.SourceId && a.SourceSchema == b.SourceSchema && a.SourceRelativePath == b.SourceRelativePath && a.TotalBytes == b.TotalBytes && a.SourceDigest == b.SourceDigest && a.SourceIndex == b.SourceIndex
}

func (s *auditReportStream) consumeSource(ctx context.Context, req *pluginsdk.ReadSandboxReportRequest, content []byte) ([]*pluginsdk.SandboxAuditEventV2, error) {
	source := s.source
	if !source.owned {
		return nil, nil
	}
	if s.verify {
		s.artifacts[source.header.SourceSchema] = append(s.artifacts[source.header.SourceSchema], content...)
	}
	if source.header.SourceSchema == "nono.session.v1" {
		if len(source.metadata)+len(content) > 8<<20 {
			return nil, status.Error(codes.ResourceExhausted, "sandbox audit metadata limit exceeded")
		}
		source.metadata = append(source.metadata, content...)
		return nil, nil
	}
	if source.header.SourceSchema != "nono.audit.v1" {
		return nil, nil
	}
	source.pending = append(source.pending, content...)
	var events []*pluginsdk.SandboxAuditEventV2
	for {
		end := bytes.IndexByte(source.pending, '\n')
		if end < 0 {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if end > 1<<20 {
			return nil, invalidAudit()
		}
		line := bytes.TrimSpace(source.pending[:end])
		if len(line) > 0 {
			event, err := s.consumeRecord(req, line)
			if err != nil {
				return nil, err
			}
			if event != nil {
				events = append(events, event)
			}
		}
		source.pending = source.pending[end+1:]
		if len(events) > 1000 {
			return nil, status.Error(codes.ResourceExhausted, "sandbox report event limit exceeded")
		}
	}
	if len(source.pending) > 1<<20 {
		return nil, invalidAudit()
	}
	return events, nil
}

func auditSourceFilename(schema string) string {
	switch schema {
	case "nono.audit.v1":
		return "audit-events.ndjson"
	case "nono.session.v1":
		return "session.json"
	case "nono.attestation.v1":
		return "audit-attestation.bundle"
	case "nono.ledger.v1":
		return "ledger.ndjson"
	default:
		return ""
	}
}

func (s *auditReportStream) consumeRecord(req *pluginsdk.ReadSandboxReportRequest, line []byte) (*pluginsdk.SandboxAuditEventV2, error) {
	var record auditRecord
	if decodeStrictJSON(line, &record) != nil || record.Sequence != s.eventCount || !sameDigest(record.Previous, s.previous) || verifyAuditRecord(record, s.previous) != nil {
		return nil, invalidAudit()
	}
	if s.eventCount >= maximumReportEvents {
		return nil, status.Error(codes.ResourceExhausted, "sandbox audit event count exceeded")
	}
	leaf, err := hex.DecodeString(record.Leaf)
	if err != nil || len(leaf) != 32 {
		return nil, invalidAudit()
	}
	s.leaves = append(s.leaves, [32]byte(leaf))
	value := record.Chain
	s.previous = &value
	s.eventCount++
	event, err := normalizeReportEvent(record.Event, record.Sequence, req)
	if err != nil || event == nil {
		return event, err
	}
	if s.seenIDs[event.RecordId] {
		return nil, invalidAudit()
	}
	s.seenIDs[event.RecordId] = true
	return event, nil
}

func (s *auditReportStream) finishSource() error {
	source := s.source
	if source.bytes != source.header.TotalBytes || hex.EncodeToString(source.digest.Sum(nil)) != source.header.SourceDigest {
		return invalidAudit()
	}
	if source.owned && source.header.SourceSchema == "nono.session.v1" {
		if s.metadata != nil {
			return invalidAudit()
		}
		s.metadata = &auditSessionSummary{}
		if !uniqueJSONFields(source.metadata) || json.Unmarshal(source.metadata, s.metadata) != nil {
			return invalidAudit()
		}
	}
	if source.owned && len(bytes.TrimSpace(source.pending)) > 0 {
		s.tail = true
	}
	header := source.header
	s.bindings = append(s.bindings, auditSourceBinding{ID: header.SourceId, Schema: header.SourceSchema, Name: header.SourceRelativePath, Digest: header.SourceDigest, Size: int64(header.TotalBytes)})
	s.source = nil
	return nil
}

func streamHash(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
func validStreamDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}
