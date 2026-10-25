package main

import (
	"context"
	"strings"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/stretchr/testify/require"
)

const fileApproval = `{"backend":"kandev","request":{"capability_type":"capability","request_id":"request-1","path":"/workspace/outside.txt","access":"Read","reason":"Sandbox intercepted file operation (seccomp-notify)","child_pid":4242,"session_id":"session-1"}}`

func TestApprovalPreservesRuntimeIdentityAndExactOperation(t *testing.T) {
	req := &pluginsdk.NormalizeSandboxApprovalRequest{Context: requestContext(), Policy: compileRequest(t).Policy, VerifiedEvent: []byte(fileApproval)}
	response, err := (&nonoPlugin{}).NormalizeSandboxApproval(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "request-1", response.Operation.RequestId)
	require.Equal(t, "session-1", response.Operation.ProviderSessionId)
	require.Equal(t, int64(4242), response.Operation.ChildPid)
	require.Equal(t, "filesystem", response.Operation.Kind)
	require.Equal(t, "read", response.Operation.Access)
	require.Equal(t, "/workspace/outside.txt", response.Operation.Target)
	require.ElementsMatch(t, []string{"deny", "allow_once"}, response.Operation.SupportedDecisions)
}

func TestDescriptionDefinesVerifiedDecisionWire(t *testing.T) {
	req := compileRequest(t)
	response, err := (&nonoPlugin{}).DescribeSandboxProvider(context.Background(), &pluginsdk.DescribeSandboxProviderRequest{Context: req.Context, Runtime: req.Runtime})
	require.NoError(t, err)
	require.NotNil(t, response.Description.ApprovalWire)
	require.Equal(t, "application/json", response.Description.ApprovalWire.ContentType)
	require.JSONEq(t, `{"decision":"granted"}`, response.Description.ApprovalWire.AllowOnceBodyUtf8)
	require.JSONEq(t, `{"decision":"denied"}`, response.Description.ApprovalWire.DenyBodyUtf8)
	require.JSONEq(t, `{"decision":"timeout"}`, response.Description.ApprovalWire.TimeoutBodyUtf8)
}

func TestApprovalRejectsUnsupportedOrAmbiguousEvents(t *testing.T) {
	for _, body := range []string{
		strings.Replace(fileApproval, `"capability_type":"capability"`, `"capability_type":"network"`, 1),
		strings.Replace(fileApproval, `"child_pid":4242`, `"child_pid":0`, 1),
		strings.Replace(fileApproval, `"session_id":"session-1"`, `"session_id":""`, 1),
		strings.Replace(fileApproval, `"access":"Read"`, `"access":"Execute"`, 1),
		strings.Replace(fileApproval, `"backend":"kandev"`, `"backend":"terminal"`, 1),
		strings.Replace(fileApproval, `"path":"/workspace/outside.txt"`, `"path":"../outside.txt"`, 1),
		fileApproval + ` {}`,
	} {
		result, err := (&nonoPlugin{}).NormalizeSandboxApproval(context.Background(), &pluginsdk.NormalizeSandboxApprovalRequest{Context: requestContext(), Policy: compileRequest(t).Policy, VerifiedEvent: []byte(body)})
		require.Error(t, err)
		require.Nil(t, result)
	}
}
