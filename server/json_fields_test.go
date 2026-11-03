package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecurityJSONRejectsDuplicateDecodedFieldNames(t *testing.T) {
	for _, raw := range []string{`{"session_id":"one","session_id":"two"}`, `{"nested":{"session_id":"one","session\u005fid":"two"}}`, `{"array":[{"decision":"allow","decision":"deny"}]}`} {
		var value map[string]any
		require.Error(t, decodeStrictJSON([]byte(raw), &value))
	}
	var value map[string]any
	require.NoError(t, decodeStrictJSON([]byte(`{"array":[{"key":1},{"key":2}]}`), &value))
}

func TestAuditReportRejectsDuplicateEventFieldsEvenWithValidHashes(t *testing.T) {
	event := `{"type":"network","event":{"timestamp_unix_ms":5,"mode":"connect","decision":"allow","decision":"deny","target":"api.example.test","port":443}}`
	requests := streamFixtureRequests(t, []streamFixtureSource{{"nono.audit.v1", "nono/audit/sess-1/audit-events.ndjson", chainFixtureMany(t, []string{event})}}, 256<<10)
	_, err := (&nonoPlugin{}).ReadSandboxReport(context.Background(), requests[0])
	require.Error(t, err)
	// RawMessage must remain opaque output data; duplicate checking reads its JSON structure.
	require.True(t, json.Valid([]byte(event)))
}
