package main

import (
	"context"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
)

func TestNonoRegistryIdentityIsSeparateFromConfinementEvidence(t *testing.T) {
	raw := []byte(`{"session_id":"runtime-session","name":null,"supervisor_pid":42,"child_pid":43,"started":"2026-10-23T12:00:00Z","started_epoch":1792756800,"status":"running","attachment":"attached","exit_code":null,"command":["fixture"],"profile":"private-profile","workdir":"/work","network":"blocked","rollback_session":null}`)
	request := &pluginsdk.NormalizeSandboxStatusRequest{Context: requestContext(), Process: &pluginsdk.SandboxProcessIdentity{Pid: 42, BirthId: "core-verified-birth"}, EvidenceSchema: "nono.session-registry.v1", Evidence: raw}
	response, err := (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), request)
	require.NoError(t, err)
	require.Nil(t, response.Evidence, "registry cannot prove the active policy")
	require.Equal(t, int64(42), response.Identity.SupervisorPid)
	require.Equal(t, int64(43), response.Identity.ChildPid)
	require.Equal(t, "runtime-session", response.Identity.ProviderSessionId)
	request.Process.Pid = 99
	_, err = (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), request)
	require.Error(t, err)
	request.Process.Pid = 42
	request.EvidenceSchema = "unverified"
	_, err = (&nonoPlugin{}).NormalizeSandboxStatus(context.Background(), request)
	require.Error(t, err)
}
