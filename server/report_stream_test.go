package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type streamFixtureSource struct {
	schema, name string
	content      []byte
}

func TestStreamedReportPreservesKindsAndRemovesPrivateDisplayFields(t *testing.T) {
	events := []string{
		`{"type":"network","event":{"timestamp_unix_ms":5,"mode":"connect","decision":"allow","target":"api.example.test","port":443,"method":null,"path":null,"status":null,"reason":null}}`,
		`{"type":"network","event":{"timestamp_unix_ms":6,"mode":"connect","decision":"deny","target":"api.example.test","port":8443,"method":null,"path":null,"status":null,"reason":"synthetic-private-detail"}}`,
		`{"type":"command_policy","event":{"timestamp":"2026-04-21T20:00:00Z","session_id":"sess-1","command":"git","caller":"session","decision":"deny","reason":"synthetic-private-detail","stdio_mode":"piped","argv_hash":"aabbcc","env_name_hash":"ddeeff","cwd_hash":"001122","argv_display":["git","synthetic-private-argument"],"env_names_display":[],"cwd_display":"/synthetic-private-directory","exit_code":null}}`,
	}
	requests := streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", chainFixtureMany(t, events)}}, 307)
	plugin := &nonoPlugin{}
	var records []*pluginsdk.SandboxAuditEventV2
	var last *pluginsdk.SandboxReportV2
	for _, req := range requests {
		result, err := plugin.ReadSandboxReport(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, result.ReportV2)
		records = append(records, result.ReportV2.Events...)
		last = result.ReportV2
	}
	require.Len(t, records, 3)
	require.Equal(t, uint32(8443), records[1].Operation.GetTcp().Port)
	require.Equal(t, "denied", records[1].Decision)
	require.True(t, records[1].ExactTarget)
	require.Equal(t, "git", records[2].Operation.GetCommand().CommandId)
	require.Empty(t, records[2].Operation.GetCommand().Argv)
	require.False(t, records[2].ExactTarget, "redacted argv does not identify an approvable invocation")
	for _, record := range records {
		raw, err := protojson.Marshal(record)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "synthetic-private")
	}
	require.Equal(t, "valid", last.Integrity)
	require.Equal(t, "live", last.Finalization)
	require.Equal(t, uint64(len(requests)), last.NextSequence)
	require.Len(t, last.Coverage, 4)
	_, err := plugin.ReadSandboxReport(context.Background(), requests[len(requests)-1])
	require.Error(t, err, "a completed sequence cannot be replayed")
}

func TestStreamedReportRejectsGapsAndChangedArtifactBindings(t *testing.T) {
	events := []string{`{"type":"session_started","started":"2026-04-21T00:00:00Z","command":["pwd"]}`}
	for _, change := range []string{"sequence", "artifact", "session", "source", "count", "size", "policy", "generation", "attempt"} {
		t.Run(change, func(t *testing.T) {
			requests := streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", chainFixtureMany(t, events)}}, 50)
			plugin := &nonoPlugin{}
			_, err := plugin.ReadSandboxReport(context.Background(), requests[0])
			require.NoError(t, err)
			next := requests[1]
			switch change {
			case "sequence":
				next.ChunkV2.Sequence++
			case "artifact":
				next.ChunkV2.ArtifactSetDigest = strings.Repeat("f", 64)
			case "session":
				next.ChunkV2.ProviderSessionId = "foreign"
			case "source":
				next.ChunkV2.SourceDigest = strings.Repeat("e", 64)
			case "count":
				next.ChunkV2.SourceCount++
			case "size":
				next.ChunkV2.TotalBytes++
			case "policy":
				next.Policy.Grants.Filesystem[0].Path = "/foreign"
			case "generation":
				next.Context.Generation++
			case "attempt":
				next.Context.AttemptId = "sibling"
			default:
				t.Fatalf("unknown mutation %s", change)
			}
			_, err = plugin.ReadSandboxReport(context.Background(), next)
			require.Error(t, err)
		})
	}
}

func TestStreamedReportCanReadMoreThanOneMiBWithoutLosingChainState(t *testing.T) {
	events := make([]string, 6000)
	for i := range events {
		events[i] = `{"type":"session_started","started":"2026-04-21T00:00:00Z","command":["pwd"]}`
	}
	audit := chainFixtureMany(t, events)
	require.Greater(t, len(audit), 1<<20)
	requests := streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", audit}}, 256<<10)
	plugin := &nonoPlugin{}
	var last *pluginsdk.SandboxReportV2
	for _, request := range requests {
		response, err := plugin.ReadSandboxReport(context.Background(), request)
		require.NoError(t, err)
		require.NotNil(t, response.ReportV2)
		last = response.ReportV2
	}
	require.Equal(t, "valid", last.Integrity)
	require.Empty(t, last.Events)
}

func chainFixtureMany(t *testing.T, events []string) []byte {
	t.Helper()
	var output []byte
	var previous *string
	for index, event := range events {
		leaf := sha256.Sum256(append([]byte("nono.audit.event.alpha\n"), []byte(event)...))
		prior := make([]byte, 32)
		if previous != nil {
			var err error
			prior, err = hex.DecodeString(*previous)
			require.NoError(t, err)
		}
		input := append([]byte("nono.audit.chain.alpha\n"), prior...)
		input = append(input, leaf[:]...)
		chain := sha256.Sum256(input)
		raw, err := json.Marshal(map[string]any{"sequence": index, "prev_chain": previous, "leaf_hash": hex.EncodeToString(leaf[:]), "chain_hash": hex.EncodeToString(chain[:]), "event_json": event, "event": json.RawMessage(event)})
		require.NoError(t, err)
		output = append(output, raw...)
		output = append(output, '\n')
		value := hex.EncodeToString(chain[:])
		previous = &value
	}
	return output
}

func streamFixtureRequests(t *testing.T, sources []streamFixtureSource, limit int) []*pluginsdk.ReadSandboxReportRequest {
	t.Helper()
	return streamFixtureRequestsForSession(t, "sess-1", sources, limit)
}

func streamFixtureRequestsForSession(t *testing.T, session string, sources []streamFixtureSource, limit int) []*pluginsdk.ReadSandboxReportRequest {
	t.Helper()
	type binding struct {
		ID     string `json:"id"`
		Schema string `json:"schema"`
		Name   string `json:"name"`
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	}
	bindings := make([]binding, 0, len(sources))
	for _, source := range sources {
		id := sha256.Sum256([]byte(source.schema + "\x00" + source.name))
		digest := sha256.Sum256(source.content)
		bindings = append(bindings, binding{hex.EncodeToString(id[:]), source.schema, source.name, hex.EncodeToString(digest[:]), int64(len(source.content))})
	}
	manifest, err := json.Marshal(bindings)
	require.NoError(t, err)
	setDigest := sha256.Sum256(manifest)
	base := compileRequest(t)
	base.Policy.Digest = strings.Repeat("c", 64)
	var requests []*pluginsdk.ReadSandboxReportRequest
	for index, source := range sources {
		for offset := 0; ; {
			end := min(offset+limit, len(source.content))
			req := proto.Clone(base).(*pluginsdk.CompileSandboxPolicyRequest)
			req.Context.ProtocolMajor = 2
			req.Context.ExecutionId = "execution"
			req.Context.OperationId = fmt.Sprintf("operation-%d", len(requests))
			req.Policy.Digest = strings.Repeat("c", 64)
			chunk := &pluginsdk.SandboxAuditChunkV2{OperationHandle: "stream-operation", ArtifactSetDigest: hex.EncodeToString(setDigest[:]), SourceId: bindings[index].ID, Sequence: uint64(len(requests)), Content: source.content[offset:end], Final: end == len(source.content), TotalBytes: uint64(len(source.content)), SourceDigest: bindings[index].Digest, SourceSchema: source.schema, SourceRelativePath: source.name, ProviderSessionId: session, SourceIndex: uint32(index), SourceCount: uint32(len(sources))}
			requests = append(requests, &pluginsdk.ReadSandboxReportRequest{Context: req.Context, Policy: req.Policy, ChunkV2: chunk})
			if end == len(source.content) {
				break
			}
			offset = end
		}
	}
	return requests
}

func TestEndpointReportsKeepTheirClassAndDiscardQueryCredentials(t *testing.T) {
	raw := chainFixtureMany(t, []string{`{"type":"network","event":{"timestamp_unix_ms":5,"mode":"reverse","decision":"deny","target":"api.example.test","port":443,"method":"POST","path":"/v1/items?access_token=synthetic-private","upstream":"https://api.example.test","route_id":"api-route","reason":"synthetic-private"}}`})
	requests := streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", raw}}, 256<<10)
	report, err := consumeReportRequests(&nonoPlugin{}, requests)
	require.NoError(t, err)
	require.Len(t, report.Events, 1)
	event := report.Events[0]
	endpoint := event.Operation.GetHttpEndpoint()
	require.NotNil(t, endpoint)
	require.Equal(t, "https://api.example.test", endpoint.Origin)
	require.Equal(t, "POST", endpoint.Method)
	require.Equal(t, "/v1/items", endpoint.Path)
	require.Empty(t, endpoint.Query)
	require.False(t, event.ExactTarget)
	encoded, err := protojson.Marshal(report)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "synthetic-private")
}

func TestRedactedNetworkTargetsRemainInspectionOnly(t *testing.T) {
	raw := chainFixtureMany(t, []string{`{"type":"network","event":{"timestamp_unix_ms":5,"mode":"connect","decision":"deny","target":"[redacted]","port":8443,"method":null,"path":null,"reason":"synthetic-private"}}`})
	report, err := consumeReportRequests(&nonoPlugin{}, streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", raw}}, 256<<10))
	require.NoError(t, err)
	require.Len(t, report.Events, 1)
	event := report.Events[0]
	require.Empty(t, event.Operation.GetTcp().Host)
	require.Equal(t, uint32(8443), event.Operation.GetTcp().Port)
	require.False(t, event.ExactTarget)
}
