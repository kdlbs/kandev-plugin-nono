package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
	"github.com/stretchr/testify/require"
)

func TestExplicitAuditVerificationSeparatesTrustSignatureAndCompleteness(t *testing.T) {
	fixture, err := filepath.Abs("testdata/nono-audit-081-signed")
	require.NoError(t, err)
	install := nativeVerifierInstall(t)
	t.Chdir(install)
	for _, mode := range []string{"trusted", "untrusted", "wrong-key", "unsupported-key", "malformed-key", "wrong-fingerprint", "prefixed-key", "unsigned", "incomplete", "ordinary-read", "redirected-bundle", "duplicate-bundle"} {
		t.Run(mode, func(t *testing.T) {
			_, session, publicKey := nativeVerifierFixture(t, fixture)
			var sources []streamFixtureSource
			for _, entry := range []struct{ schema, name string }{
				{"nono.audit.v1", "audit-events.ndjson"},
				{"nono.session.v1", "session.json"},
				{"nono.attestation.v1", "audit-attestation.bundle"},
				{"nono.ledger.v1", "ledger.ndjson"},
			} {
				if mode == "unsigned" && entry.schema == "nono.attestation.v1" || mode == "incomplete" && entry.schema == "nono.session.v1" {
					continue
				}
				raw, readErr := os.ReadFile(filepath.Join(fixture, entry.name))
				require.NoError(t, readErr)
				if mode == "redirected-bundle" && entry.name == "session.json" {
					var metadata map[string]any
					require.NoError(t, json.Unmarshal(raw, &metadata))
					metadata["audit_attestation"].(map[string]any)["bundle_filename"] = filepath.Join(fixture, "audit-attestation.bundle")
					raw, readErr = json.Marshal(metadata)
					require.NoError(t, readErr)
				}
				if mode == "duplicate-bundle" && entry.name == "audit-attestation.bundle" {
					raw = append([]byte(`{"mediaType":"ambiguous",`), raw[1:]...)
				}
				name := "nono/audit/" + session + "/" + entry.name
				if entry.schema == "nono.ledger.v1" {
					name = "nono/audit/ledger.ndjson"
				}
				sources = append(sources, streamFixtureSource{entry.schema, name, raw})
			}
			requests := streamFixtureRequestsForSession(t, session, sources, 256<<10)
			publicKey = auditSelectedKeyFixture(t, mode, publicKey)
			for _, request := range requests {
				request.VerifyAuditV2 = mode != "ordinary-read"
				if slices.Contains([]string{"trusted", "wrong-key", "unsupported-key", "malformed-key", "wrong-fingerprint", "prefixed-key"}, mode) {
					block, _ := pem.Decode(publicKey)
					request.TrustV2 = &pluginsdk.SandboxAuditTrustV2{ExpectedPublicKeyPem: publicKey, ExpectedKeyFingerprint: streamHash(block.Bytes), TrustRevision: "operator-revision-1"}
					if mode == "wrong-fingerprint" {
						request.TrustV2.ExpectedKeyFingerprint = strings.Repeat("b", 64)
					}
				}
			}
			result, readErr := consumeReportRequests(&nonoPlugin{}, requests)
			if slices.Contains([]string{"redirected-bundle", "duplicate-bundle", "malformed-key", "wrong-fingerprint", "prefixed-key"}, mode) {
				require.Error(t, readErr)
				return
			}
			require.NoError(t, readErr)
			if mode == "ordinary-read" {
				require.Nil(t, result.Verification)
				return
			}
			require.NotNil(t, result.Verification)
			verification := result.Verification
			require.Equal(t, requests[0].ChunkV2.ArtifactSetDigest, verification.ArtifactSetDigest)
			require.Equal(t, session, verification.SessionId)
			if mode == "incomplete" {
				require.Equal(t, "interrupted", verification.Finalization)
				require.Equal(t, "unchecked", verification.SignatureState)
				return
			}
			require.Equal(t, "valid", verification.ChainState)
			require.Equal(t, "valid", verification.LedgerState)
			require.Equal(t, "final", verification.Finalization)
			expected := map[string]string{"trusted": "verified", "untrusted": "untrusted", "wrong-key": "untrusted", "unsigned": "unsigned", "unsupported-key": "unsupported"}[mode]
			require.Equal(t, expected, verification.SignatureState)
			if mode == "trusted" {
				require.Equal(t, requests[0].TrustV2.ExpectedKeyFingerprint, verification.SignerKeyFingerprint)
			}
		})
	}
}

func auditSelectedKeyFixture(t *testing.T, mode string, original []byte) []byte {
	t.Helper()
	var selected any
	switch mode {
	case "wrong-key":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		selected = &key.PublicKey
	case "unsupported-key", "prefixed-key":
		key, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		selected = key
	}
	if selected != nil {
		der, err := x509.MarshalPKIXPublicKey(selected)
		require.NoError(t, err)
		original = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	if mode == "malformed-key" {
		block, _ := pem.Decode(original)
		block.Type = "PRIVATE KEY"
		original = pem.EncodeToMemory(block)
	}
	if mode == "prefixed-key" {
		original = append([]byte("unexpected text\n"), original...)
	}
	return original
}

func TestAuditStreamBindsVerificationActionAndTrustAcrossChunks(t *testing.T) {
	for _, change := range []string{"action", "trust"} {
		t.Run(change, func(t *testing.T) {
			requests := finalReportRequests(t, []byte(finalMetadataFixture))
			plugin := &nonoPlugin{}
			_, err := plugin.ReadSandboxReport(t.Context(), requests[0])
			require.NoError(t, err)
			if change == "action" {
				requests[1].VerifyAuditV2 = true
			} else {
				requests[1].TrustV2 = &pluginsdk.SandboxAuditTrustV2{TrustRevision: "foreign"}
			}
			_, err = plugin.ReadSandboxReport(t.Context(), requests[1])
			require.Error(t, err)
		})
	}
}
