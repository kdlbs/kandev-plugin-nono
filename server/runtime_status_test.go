package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
	"github.com/stretchr/testify/require"
)

func TestRuntimeMetadataRetainsOriginalTimeAndRequiresOwnedSource(t *testing.T) {
	event := `{"type":"sandbox_runtime","event":{"timestamp":"2026-04-21T00:00:00Z","platform":"linux","landlock_abi":"v5","landlock_execute_enforced":true,"tool_sandbox_active":true}}`
	request := &pluginsdk.NormalizeSandboxStatusRequest{Context: requestContext(), Process: &pluginsdk.SandboxProcessIdentity{Pid: 42, BirthId: "birth"}, EvidenceSchema: "nono.audit.v1", SourceRelativePathV2: "nono/audit/session-1/audit-events.ndjson", ProviderSessionIdV2: "session-1", Evidence: chainFixture(t, event)}
	request.Context.ProtocolMajor = 2
	result, err := (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), request)
	require.NoError(t, err)
	require.Nil(t, result.Evidence, "runtime metadata cannot satisfy current-policy attestation")
	require.Len(t, result.ObservationsV2, 1)
	fact := result.ObservationsV2[0]
	require.Equal(t, uint32(5), *fact.LandlockAbi)
	require.True(t, *fact.ExecuteEnforced)
	require.True(t, *fact.CommandMediationActive)
	observed, err := time.Parse(time.RFC3339, "2026-04-21T00:00:00Z")
	require.NoError(t, err)
	require.Equal(t, observed.UnixMilli(), fact.ObservedAtUnixMs)
	repeated, err := (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, fact.ObservedAtUnixMs, repeated.ObservationsV2[0].ObservedAtUnixMs)
	request.SourceRelativePathV2 = "nono/audit/sibling/audit-events.ndjson"
	result, err = (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), request)
	require.NoError(t, err)
	require.Empty(t, result.ObservationsV2, "nested command sessions cannot describe the captured supervisor")
	request.SourceRelativePathV2 = "../session-1/audit-events.ndjson"
	_, err = (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), request)
	require.Error(t, err)
}

func TestRuntimeMetadataDoesNotInventMissingFacts(t *testing.T) {
	request := &pluginsdk.NormalizeSandboxStatusRequest{Context: requestContext(), Process: &pluginsdk.SandboxProcessIdentity{Pid: 42, BirthId: "birth"}, EvidenceSchema: "nono.audit.v1", SourceRelativePathV2: "nono/audit/session-1/audit-events.ndjson", ProviderSessionIdV2: "session-1", Evidence: chainFixture(t, `{"type":"session_started","timestamp":"2026-04-21T00:00:00Z","command":["pwd"]}`)}
	request.Context.ProtocolMajor = 2
	result, err := (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), request)
	require.NoError(t, err)
	require.Empty(t, result.ObservationsV2)
	require.Nil(t, result.Evidence)
}

func chainFixture(t *testing.T, event string) []byte {
	t.Helper()
	leaf := sha256.Sum256(append([]byte("nono.audit.event.alpha\n"), []byte(event)...))
	input := append([]byte("nono.audit.chain.alpha\n"), make([]byte, 32)...)
	input = append(input, leaf[:]...)
	chain := sha256.Sum256(input)
	raw, err := json.Marshal(map[string]any{"sequence": 0, "prev_chain": nil, "leaf_hash": hex.EncodeToString(leaf[:]), "chain_hash": hex.EncodeToString(chain[:]), "event_json": event, "event": json.RawMessage(event)})
	require.NoError(t, err)
	return append(raw, '\n')
}

func TestRuntimeMetadataRejectsMalformedFieldsAndTampering(t *testing.T) {
	base := `{"type":"sandbox_runtime","event":{"timestamp":"2026-04-21T00:00:00Z","platform":"linux","tool_sandbox_active":false}}`
	req := &pluginsdk.NormalizeSandboxStatusRequest{Context: requestContext(), Process: &pluginsdk.SandboxProcessIdentity{Pid: 42, BirthId: "birth"}, EvidenceSchema: "nono.audit.v1", SourceRelativePathV2: "nono/audit/session-1/audit-events.ndjson", ProviderSessionIdV2: "session-1", Evidence: chainFixture(t, base)}
	req.Context.ProtocolMajor = 2
	result, err := (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), req)
	require.NoError(t, err)
	require.Nil(t, result.ObservationsV2[0].LandlockAbi)
	require.Nil(t, result.ObservationsV2[0].ExecuteEnforced)
	require.False(t, *result.ObservationsV2[0].CommandMediationActive)
	for _, event := range []string{
		strings.Replace(base, "2026-04-21T00:00:00Z", "2026-02-30T00:00:00Z", 1),
		strings.Replace(base, "linux", "unknown", 1),
		strings.Replace(base, `"tool_sandbox_active":false`, `"landlock_abi":"5"`, 1),
		strings.Replace(base, `"tool_sandbox_active":false`, `"tool_sandbox_active":false,"landlock_abi":"v0"`, 1),
	} {
		req.Evidence = chainFixture(t, event)
		_, err = (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), req)
		require.Error(t, err)
	}
	req.Evidence = bytes.Replace(chainFixture(t, base), []byte("linux"), []byte("macos"), 1)
	_, err = (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), req)
	require.Error(t, err)
}
