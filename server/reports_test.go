package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The event bytes and leaf hash come from Nono 0.80.0's audit.rs wire fixture.
func TestReportVerifiesEventChainAndMarksIncompleteCoverage(t *testing.T) {
	audit, err := os.ReadFile("testdata/denial.ndjson")
	require.NoError(t, err)
	req := &pluginsdk.ReadSandboxReportRequest{Context: requestContext(), Policy: compileRequest(t).Policy, Audit: audit}
	report, err := (&nonoPlugin{}).ReadSandboxReport(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "partial", report.Integrity)
	require.False(t, report.Complete)
	require.Len(t, report.Records, 1)
	record := report.Records[0]
	require.Equal(t, "write", record.Operation)
	require.Equal(t, "/tmp/example", record.Target)
	require.Equal(t, int64(5000), record.OccurredAtUnixMs)
	require.Equal(t, req.Policy.Digest, record.PolicyDigest)
	require.Equal(t, req.Context.AttemptId, record.AttemptId)
}

func TestReportRejectsTamperingAndTruncatedRecords(t *testing.T) {
	audit, err := os.ReadFile("testdata/denial.ndjson")
	require.NoError(t, err)
	for _, raw := range []string{strings.Replace(string(audit), "outside policy", "changed", 1), strings.Replace(string(audit), `"sequence":0`, `"sequence":1`, 1), string(audit) + `{"sequence":1`, "{}"} {
		report, err := (&nonoPlugin{}).ReadSandboxReport(context.Background(), &pluginsdk.ReadSandboxReportRequest{Context: requestContext(), Policy: compileRequest(t).Policy, Audit: []byte(raw)})
		require.Error(t, err)
		require.Nil(t, report)
	}
}

func TestRevisionProposalUsesOnlySelectedBoundDenials(t *testing.T) {
	req := compileRequest(t)
	record := &pluginsdk.SandboxDenialRecord{RecordId: "denial-1", Operation: "read", Target: t.TempDir(), PolicyDigest: req.Policy.Digest, AttemptId: req.Context.AttemptId}
	proposal, err := (&nonoPlugin{}).ProposeSandboxRevision(context.Background(), &pluginsdk.ProposeSandboxRevisionRequest{Context: req.Context, Policy: req.Policy, Runtime: req.Runtime, SelectedRecords: []*pluginsdk.SandboxDenialRecord{record}})
	require.NoError(t, err)
	require.Equal(t, []string{"denial-1"}, proposal.SourceRecordIds)
	require.Len(t, proposal.AddedGrants.Filesystem, 1)
	require.Equal(t, record.Target, proposal.AddedGrants.Filesystem[0].Path)
	require.False(t, proposal.AddedGrants.Filesystem[0].Writable)
	require.Len(t, req.Policy.Grants.Filesystem, 1)
	record.PolicyDigest = "other-policy"
	proposal, err = (&nonoPlugin{}).ProposeSandboxRevision(context.Background(), &pluginsdk.ProposeSandboxRevisionRequest{Context: req.Context, Policy: req.Policy, Runtime: req.Runtime, SelectedRecords: []*pluginsdk.SandboxDenialRecord{record}})
	require.Error(t, err)
	require.Nil(t, proposal)
}

func TestRegistryAloneCannotCertifyPolicy(t *testing.T) {
	result, err := (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), &pluginsdk.NormalizeSandboxStatusRequest{Context: requestContext(), EvidenceSchema: "nono.session-registry.v1", Evidence: []byte(`{"supervisor_pid":42,"status":"running"}`)})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Nil(t, result)
}
