package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type nativeAuditResult struct {
	Session struct {
		RecordsVerified bool    `json:"records_verified"`
		Algorithm       string  `json:"hash_algorithm"`
		Scheme          string  `json:"merkle_scheme"`
		EventCount      uint64  `json:"event_count"`
		StoredCount     *uint64 `json:"stored_event_count"`
		CountMatches    bool    `json:"event_count_matches"`
		ComputedChain   string  `json:"computed_chain_head"`
		StoredChain     string  `json:"stored_chain_head"`
		ComputedRoot    string  `json:"computed_merkle_root"`
		StoredRoot      string  `json:"stored_merkle_root"`
	} `json:"session"`
	Ledger struct {
		ChainVerified bool   `json:"ledger_chain_verified"`
		Algorithm     string `json:"hash_algorithm"`
		SessionFound  bool   `json:"session_found"`
		DigestMatches bool   `json:"session_digest_matches"`
	} `json:"ledger"`
	Attestation struct {
		SignatureVerified  bool    `json:"signature_verified"`
		ExpectedKeyMatches *bool   `json:"expected_public_key_matches"`
		Present            bool    `json:"present"`
		Predicate          string  `json:"predicate_type"`
		KeyID              string  `json:"key_id"`
		KeyIDMatches       bool    `json:"key_id_matches"`
		RootMatches        bool    `json:"merkle_root_matches"`
		SessionMatches     bool    `json:"session_id_matches"`
		Error              *string `json:"verification_error"`
	} `json:"attestation"`
}

func executeNativeAuditVerification(ctx context.Context, directory, session string, expectedKey []byte) (*nativeAuditResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory || !boundedIdentity(session) || strings.ContainsAny(session, "/\\") || len(expectedKey) > 16<<10 {
		return nil, invalidAudit()
	}
	if len(expectedKey) > 0 && !validAuditPublicKey(expectedKey) {
		return nil, invalidAudit()
	}
	executable, err := copyPinnedAuditVerifier(ctx, directory)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(executable) }()
	args := []string{"audit", "verify", "--json"}
	if len(expectedKey) > 0 {
		key := filepath.Join(directory, "expected-public.pem")
		if err = os.WriteFile(key, expectedKey, 0600); err != nil {
			return nil, verifierUnavailable()
		}
		defer func() { _ = os.Remove(key) }()
		args = append(args, "--public-key-file", key)
	}
	args = append(args, "--", session)
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = directory
	command.Env = []string{"HOME=" + directory, "XDG_STATE_HOME=" + filepath.Join(directory, "state"), "XDG_CONFIG_HOME=" + filepath.Join(directory, "config"), "XDG_CACHE_HOME=" + filepath.Join(directory, "cache"), "TMPDIR=" + directory, "NONO_NO_UPDATE_CHECK=1", "LANG=C", "LC_ALL=C"}
	configureAuditVerifierProcess(command)
	output, diagnostic := auditOutputBuffer{limit: 64 << 10}, auditOutputBuffer{limit: 8 << 10}
	command.Stdout, command.Stderr = &output, &diagnostic
	if err = command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, verifierUnavailable()
	}
	var result nativeAuditResult
	if output.exceeded || diagnostic.exceeded || !uniqueJSONFields(output.Bytes()) || json.Unmarshal(output.Bytes(), &result) != nil {
		return nil, invalidAudit()
	}
	return &result, nil
}

func validAuditPublicKey(raw []byte) bool {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) > 0 {
		return false
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := value.(*ecdsa.PublicKey)
	return err == nil && ok && key.Curve == elliptic.P256()
}

func copyPinnedAuditVerifier(ctx context.Context, directory string) (string, error) {
	root, err := os.OpenRoot(".")
	if err != nil {
		return "", verifierUnavailable()
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{"runtime", "runtime/nono-linux-amd64"} {
		info, statErr := root.Lstat(name)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || name == "runtime" && !info.IsDir() || name != "runtime" && !info.Mode().IsRegular() {
			return "", verifierUnavailable()
		}
	}
	file, err := openAuditRuntime(root)
	if err != nil {
		return "", verifierUnavailable()
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", verifierUnavailable()
	}
	raw, err := io.ReadAll(io.LimitReader(file, (128<<20)+1))
	if err != nil || len(raw) > 128<<20 || streamHash(raw) != runtimeDigest {
		return "", verifierUnavailable()
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	copy, err := os.CreateTemp(directory, "nono-verifier-")
	if err != nil {
		return "", verifierUnavailable()
	}
	_, writeErr := copy.Write(raw)
	err = errors.Join(writeErr, copy.Chmod(0500), copy.Close())
	if err != nil {
		_ = os.Remove(copy.Name())
		return "", verifierUnavailable()
	}
	return copy.Name(), nil
}

func verifierUnavailable() error {
	return status.Error(codes.Unavailable, "audit verifier unavailable")
}

type auditOutputBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *auditOutputBuffer) Write(content []byte) (int, error) {
	if len(content) > b.limit-b.Len() {
		b.exceeded = true
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(content)
}
