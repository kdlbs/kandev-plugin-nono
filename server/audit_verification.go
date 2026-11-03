package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/kdlbs/kandev/pluginsdk"
)

func (s *auditReportStream) verifyArtifacts(ctx context.Context, report *pluginsdk.SandboxReportV2) error {
	result := &pluginsdk.SandboxAuditVerificationV2{ArtifactSetDigest: s.digest, VerifierVersion: "nono-" + runtimeVersion + "/audit-alpha-1", SessionId: s.session, EventRoot: auditMerkleRoot(s.leaves), EventCount: s.eventCount, ChainState: report.Integrity, Finalization: report.Finalization, SignatureState: "unchecked", LedgerState: "unavailable"}
	if s.trust != nil {
		der := auditPublicKeyDER(s.trust.ExpectedPublicKeyPem)
		if der == nil || !validStreamDigest(s.trust.ExpectedKeyFingerprint) || !boundedIdentity(s.trust.TrustRevision) {
			return invalidAudit()
		}
		if streamHash(der) != s.trust.ExpectedKeyFingerprint {
			return invalidAudit()
		}
		result.ExpectedKeyFingerprint, result.TrustRevision = s.trust.ExpectedKeyFingerprint, s.trust.TrustRevision
	}
	report.Verification = result
	if report.Finalization != "final" {
		report.Finalization, result.Finalization = "interrupted", "interrupted"
		return nil
	}
	if s.metadata.Attestation != nil && s.metadata.Attestation.BundleFilename != "audit-attestation.bundle" {
		return invalidAudit()
	}
	if bundle, present := s.artifacts["nono.attestation.v1"]; present && !uniqueJSONFields(bundle) {
		return invalidAudit()
	}
	directory, err := os.MkdirTemp("", "nono-audit-verify-")
	if err != nil {
		return verifierUnavailable()
	}
	defer func() { _ = os.RemoveAll(directory) }()
	if err = s.writeVerificationInputs(directory); err != nil {
		return err
	}
	native, err := executeNativeAuditVerification(ctx, directory, s.session, nil)
	if err != nil {
		return err
	}
	if !s.nativeSessionMatches(native) {
		return invalidAudit()
	}
	if _, present := s.artifacts["nono.ledger.v1"]; present {
		result.LedgerState = "invalid"
		if native.Ledger.Algorithm == "sha256" && native.Ledger.ChainVerified && native.Ledger.SessionFound && native.Ledger.DigestMatches {
			result.LedgerState = "valid"
		}
	}
	return s.verifyNativeSigner(ctx, directory, native, result)
}

func (s *auditReportStream) writeVerificationInputs(directory string) error {
	root := filepath.Join(directory, "state", "nono", "audit")
	if err := os.MkdirAll(filepath.Join(root, s.session), 0700); err != nil {
		return verifierUnavailable()
	}
	for schema, raw := range s.artifacts {
		path := filepath.Join(root, s.session, auditSourceFilename(schema))
		if schema == "nono.ledger.v1" {
			path = filepath.Join(root, "ledger.ndjson")
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			return verifierUnavailable()
		}
	}
	return nil
}

func (s *auditReportStream) nativeSessionMatches(native *nativeAuditResult) bool {
	value := native.Session
	metadata := s.metadata.Integrity
	return value.Algorithm == "sha256" && value.Scheme == "alpha" && value.RecordsVerified && value.CountMatches && value.EventCount == s.eventCount && value.StoredCount != nil && *value.StoredCount == s.eventCount && value.ComputedChain == metadata.ChainHead && value.StoredChain == metadata.ChainHead && value.ComputedRoot == metadata.MerkleRoot && value.StoredRoot == metadata.MerkleRoot
}

func (s *auditReportStream) verifyNativeSigner(ctx context.Context, directory string, native *nativeAuditResult, result *pluginsdk.SandboxAuditVerificationV2) error {
	value := native.Attestation
	_, bundle := s.artifacts["nono.attestation.v1"]
	result.SignatureState = "unsigned"
	if !bundle || !value.Present {
		return nil
	}
	result.SignatureState = "invalid"
	if !value.SignatureVerified || !value.KeyIDMatches || !value.RootMatches || !value.SessionMatches || value.Error != nil || !validStreamDigest(value.KeyID) || value.Predicate != "https://nono.sh/attestation/audit-session/alpha" {
		return nil
	}
	result.SignerKeyFingerprint = value.KeyID
	result.SignatureState = "untrusted"
	if s.trust == nil {
		return nil
	}
	if !validAuditPublicKey(s.trust.ExpectedPublicKeyPem) {
		result.SignatureState = "unsupported"
		return nil
	}
	keyed, err := executeNativeAuditVerification(ctx, directory, s.session, s.trust.ExpectedPublicKeyPem)
	if err != nil {
		return err
	}
	if !s.nativeSessionMatches(keyed) {
		return invalidAudit()
	}
	expected := keyed.Attestation.ExpectedKeyMatches
	if value.KeyID == s.trust.ExpectedKeyFingerprint && expected != nil && *expected && keyed.Attestation.SignatureVerified && keyed.Attestation.KeyIDMatches && keyed.Attestation.RootMatches && keyed.Attestation.SessionMatches && keyed.Attestation.Error == nil {
		result.SignatureState = "verified"
	}
	return nil
}
