package main

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type auditSessionSummary struct {
	SessionID  string  `json:"session_id"`
	Ended      *string `json:"ended"`
	EventCount uint64  `json:"audit_event_count"`
	Integrity  *struct {
		Algorithm  string `json:"hash_algorithm"`
		EventCount uint64 `json:"event_count"`
		ChainHead  string `json:"chain_head"`
		MerkleRoot string `json:"merkle_root"`
	} `json:"audit_integrity"`
}

func (s *auditReportStream) verifyFinalMetadata() error {
	metadata := s.metadata
	if metadata.SessionID != s.session || !s.hasAudit {
		return invalidAudit()
	}
	if metadata.Ended == nil {
		return nil
	}
	ended, err := time.Parse(time.RFC3339Nano, *metadata.Ended)
	if err != nil || ended.UnixMilli() <= 0 || ended.After(time.Now().Add(5*time.Second)) || s.tail || metadata.Integrity == nil {
		return invalidAudit()
	}
	summary := metadata.Integrity
	if summary.Algorithm != "sha256" || summary.EventCount != s.eventCount || metadata.EventCount != s.eventCount || summary.MerkleRoot != auditMerkleRoot(s.leaves) {
		return invalidAudit()
	}
	chain := make([]byte, 32)
	if s.previous != nil {
		chain, err = hex.DecodeString(*s.previous)
		if err != nil {
			return invalidAudit()
		}
	}
	if summary.ChainHead != hex.EncodeToString(chain) {
		return invalidAudit()
	}
	return nil
}

func auditMerkleRoot(leaves [][32]byte) string {
	if len(leaves) == 0 {
		return streamHash(nil)
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			if index+1 == len(level) {
				next = append(next, level[index])
				continue
			}
			hash := sha256.New()
			_, _ = hash.Write([]byte("nono.audit.merkle.alpha\n"))
			_, _ = hash.Write(level[index][:])
			_, _ = hash.Write(level[index+1][:])
			next = append(next, [32]byte(hash.Sum(nil)))
		}
		level = next
	}
	return hex.EncodeToString(level[0][:])
}
