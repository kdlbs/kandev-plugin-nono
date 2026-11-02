package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const finalMetadataFixture = `{"session_id":"sess-1","ended":"2026-04-21T20:00:00Z","audit_event_count":1,"audit_integrity":{"hash_algorithm":"sha256","event_count":1,"chain_head":"d3b0133e85e9a31783a8821b68d5295f14b91263bc2636e66fcbe40398708812","merkle_root":"fb0ff01abb9de69f3c50deb6b828a25d941d7541856d81b8fa3da84b95aa125a"}}`

func TestFinalReportChecksMetadataWithoutClaimingSignerTrust(t *testing.T) {
	requests := finalReportRequests(t, []byte(finalMetadataFixture))
	result, err := consumeReportRequests(&nonoPlugin{}, requests)
	require.NoError(t, err)
	require.Equal(t, "valid", result.Integrity)
	require.Equal(t, "final", result.Finalization)
	require.Nil(t, result.Verification, "chain and finalization checks do not establish trusted signing")
}

func TestFinalReportRejectsModifiedSessionRootAndCounts(t *testing.T) {
	for _, change := range []string{"session", "root", "chain", "count", "ended"} {
		t.Run(change, func(t *testing.T) {
			var metadata map[string]any
			require.NoError(t, json.Unmarshal([]byte(finalMetadataFixture), &metadata))
			integrity := metadata["audit_integrity"].(map[string]any)
			switch change {
			case "session":
				metadata["session_id"] = "foreign"
			case "root":
				integrity["merkle_root"] = strings.Repeat("a", 64)
			case "chain":
				integrity["chain_head"] = strings.Repeat("b", 64)
			case "count":
				metadata["audit_event_count"] = 2
			case "ended":
				metadata["ended"] = "2026-02-30T00:00:00Z"
			}
			raw, err := json.Marshal(metadata)
			require.NoError(t, err)
			_, err = consumeReportRequests(&nonoPlugin{}, finalReportRequests(t, raw))
			require.Error(t, err)
		})
	}
}

func TestReportKeepsLivePartialLinesAndRejectsFinalizedTruncation(t *testing.T) {
	audit, err := os.ReadFile("testdata/denial.ndjson")
	require.NoError(t, err)
	audit = append(audit, []byte(`{"sequence":1`)...)
	sources := []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", audit}}
	result, err := consumeReportRequests(&nonoPlugin{}, streamFixtureRequests(t, sources, 256<<10))
	require.NoError(t, err)
	require.Equal(t, "unchecked", result.Integrity)
	require.Equal(t, "live", result.Finalization)
	sources = append(sources, streamFixtureSource{"nono.session.v1", "nono/audit/sess-1/session.json", []byte(finalMetadataFixture)})
	_, err = consumeReportRequests(&nonoPlugin{}, streamFixtureRequests(t, sources, 256<<10))
	require.Error(t, err)
}

func TestReportIgnoresSiblingFilesAndDoesNotCallThemEmptyOwnedEvidence(t *testing.T) {
	audit, err := os.ReadFile("testdata/denial.ndjson")
	require.NoError(t, err)
	result, err := consumeReportRequests(&nonoPlugin{}, streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sibling/audit-events.ndjson", audit}}, 256<<10))
	require.NoError(t, err)
	require.Empty(t, result.Events)
	require.Equal(t, "unchecked", result.Integrity)
	for _, coverage := range result.Coverage {
		require.Equal(t, "unavailable", coverage.Coverage)
	}
}

func TestReportRejectsUnknownVariantsAndTampering(t *testing.T) {
	audit := chainFixtureMany(t, []string{`{"type":"future_unknown_event","detail":"synthetic-private"}`})
	_, err := consumeReportRequests(&nonoPlugin{}, streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", audit}}, 256<<10))
	require.Equal(t, codes.Unimplemented, status.Code(err))
	require.NotContains(t, err.Error(), "synthetic-private")
	valid, err := os.ReadFile("testdata/denial.ndjson")
	require.NoError(t, err)
	changed := bytes.ReplaceAll(valid, []byte("outside policy"), []byte("changed"))
	_, err = consumeReportRequests(&nonoPlugin{}, streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", changed}}, 256<<10))
	require.Error(t, err)
}

func TestExpiredReportStreamCannotResumeWithANewCallDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		audit := chainFixtureMany(t, []string{`{"type":"session_started","started":"2026-04-21T00:00:00Z","command":["pwd"]}`})
		requests := streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", audit}}, 50)
		requests[0].Context.DeadlineUnixMs = time.Now().Add(time.Second).UnixMilli()
		plugin := &nonoPlugin{}
		_, err := plugin.ReadSandboxReport(context.Background(), requests[0])
		require.NoError(t, err)
		time.Sleep(2 * time.Second)
		requests[1].Context.DeadlineUnixMs = time.Now().Add(time.Second).UnixMilli()
		_, err = plugin.ReadSandboxReport(context.Background(), requests[1])
		require.Error(t, err)
	})
}

func finalReportRequests(t *testing.T, metadata []byte) []*pluginsdk.ReadSandboxReportRequest {
	t.Helper()
	audit, err := os.ReadFile("testdata/denial.ndjson")
	require.NoError(t, err)
	return streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", audit}, {"nono.session.v1", "nono/audit/sess-1/session.json", metadata}}, 256<<10)
}

func consumeReportRequests(plugin *nonoPlugin, requests []*pluginsdk.ReadSandboxReportRequest) (*pluginsdk.SandboxReportV2, error) {
	result := &pluginsdk.SandboxReportV2{}
	for _, request := range requests {
		response, err := plugin.ReadSandboxReport(context.Background(), request)
		if err != nil {
			return nil, err
		}
		result = response.ReportV2
	}
	return result, nil
}
