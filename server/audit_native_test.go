package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNativeVerifierRefusesNonRegularRuntimeBeforeOpening(t *testing.T) {
	install := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(install, "runtime"), 0700))
	path := filepath.Join(install, "runtime", "nono-linux-amd64")
	require.NoError(t, syscall.Mkfifo(path, 0600))
	t.Chdir(install)
	scratch := t.TempDir()
	done := make(chan error, 1)
	go func() { _, err := copyPinnedAuditVerifier(t.Context(), scratch); done <- err }()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		// Release a blocked FIFO read before failing the deadlock guard.
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0600)
		require.NoError(t, err)
		_, err = writer.Write([]byte("invalid runtime"))
		require.NoError(t, err)
		require.NoError(t, writer.Close())
		<-done
		t.Fatal("the verifier must reject a non-regular runtime before opening it")
	}
}

func TestPinnedNativeAuditVerifierChecksSignatureResults(t *testing.T) {
	fixture, err := filepath.Abs("testdata/nono-audit-081-signed")
	require.NoError(t, err)
	install := nativeVerifierInstall(t)
	t.Chdir(install)
	for _, mutation := range []string{"valid", "signature", "untrusted", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			directory, session, key := nativeVerifierFixture(t, fixture)
			ctx := t.Context()
			switch mutation {
			case "signature":
				path := filepath.Join(directory, "state", "nono", "audit", session, "audit-attestation.bundle")
				raw, err := os.ReadFile(path)
				require.NoError(t, err)
				var bundle map[string]any
				require.NoError(t, json.Unmarshal(raw, &bundle))
				envelope := bundle["dsseEnvelope"].(map[string]any)
				signature := envelope["signatures"].([]any)[0].(map[string]any)
				bytes, err := base64.StdEncoding.DecodeString(signature["sig"].(string))
				require.NoError(t, err)
				bytes[len(bytes)-1] ^= 1
				signature["sig"] = base64.StdEncoding.EncodeToString(bytes)
				raw, err = json.Marshal(bundle)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0600))
			case "untrusted":
				key = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			result, err := executeNativeAuditVerification(ctx, directory, session, key)
			if mutation == "cancelled" {
				require.Error(t, err)
				require.Nil(t, result)
				return
			}
			require.NoError(t, err)
			require.True(t, result.Session.RecordsVerified)
			require.True(t, result.Ledger.ChainVerified)
			require.Equal(t, mutation != "signature", result.Attestation.SignatureVerified, "exit zero is not signature verification")
			if mutation == "untrusted" {
				require.Nil(t, result.Attestation.ExpectedKeyMatches)
			} else if mutation == "valid" {
				require.NotNil(t, result.Attestation.ExpectedKeyMatches)
				require.True(t, *result.Attestation.ExpectedKeyMatches)
			}
		})
	}
}

func TestNativeVerifierRejectsUnpinnedRuntime(t *testing.T) {
	directory, session, key := nativeVerifierFixture(t, "testdata/nono-audit-081-signed")
	install := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(install, "runtime"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(install, "runtime", "nono-linux-amd64"), []byte("untrusted executable"), 0700))
	t.Chdir(install)
	result, err := executeNativeAuditVerification(t.Context(), directory, session, key)
	require.Error(t, err)
	require.Nil(t, result)
}

func nativeVerifierInstall(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("NONO_ACCEPTANCE_BINARY")
	if binary == "" {
		t.Skip("set NONO_ACCEPTANCE_BINARY to the pinned runtime")
	}
	raw, err := os.ReadFile(binary)
	require.NoError(t, err)
	require.Equal(t, runtimeDigest, streamHash(raw))
	install := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(install, "runtime"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(install, "runtime", "nono-linux-amd64"), raw, 0500))
	return install
}

func nativeVerifierFixture(t *testing.T, fixture string) (string, string, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixture, "provenance.json"))
	require.NoError(t, err)
	var provenance struct {
		Session string `json:"session_id"`
	}
	require.NoError(t, json.Unmarshal(raw, &provenance))
	directory := t.TempDir()
	audit := filepath.Join(directory, "state", "nono", "audit")
	require.NoError(t, os.MkdirAll(filepath.Join(audit, provenance.Session), 0700))
	for _, name := range []string{"audit-events.ndjson", "session.json", "audit-attestation.bundle", "ledger.ndjson"} {
		content, readErr := os.ReadFile(filepath.Join(fixture, name))
		require.NoError(t, readErr)
		target := filepath.Join(audit, provenance.Session, name)
		if name == "ledger.ndjson" {
			target = filepath.Join(audit, name)
		}
		require.NoError(t, os.WriteFile(target, content, 0600))
	}
	key, err := os.ReadFile(filepath.Join(fixture, "signer-public.pem"))
	require.NoError(t, err)
	return directory, provenance.Session, key
}
