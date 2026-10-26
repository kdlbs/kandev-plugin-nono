package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type auditRecord struct {
	Sequence  uint64          `json:"sequence"`
	Previous  *string         `json:"prev_chain"`
	Leaf      string          `json:"leaf_hash"`
	Chain     string          `json:"chain_hash"`
	EventJSON string          `json:"event_json"`
	Event     json.RawMessage `json:"event"`
}

func invalidAudit() error { return status.Error(codes.InvalidArgument, "invalid sandbox audit chain") }

func verifyAuditChain(data []byte) ([]json.RawMessage, error) {
	if len(data) > 1<<20 {
		return nil, invalidAudit()
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	events := make([]json.RawMessage, 0)
	var previous *string
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record auditRecord
		if decodeStrictJSON(line, &record) != nil || record.Sequence != uint64(len(events)) || !sameDigest(record.Previous, previous) {
			return nil, invalidAudit()
		}
		if err := verifyAuditRecord(record, previous); err != nil {
			return nil, err
		}
		value := record.Chain
		previous = &value
		events = append(events, record.Event)
	}
	if scanner.Err() != nil {
		return nil, invalidAudit()
	}
	return events, nil
}

func verifyAuditRecord(record auditRecord, previous *string) error {
	var event, canonical bytes.Buffer
	if record.EventJSON == "" || json.Compact(&event, record.Event) != nil || json.Compact(&canonical, []byte(record.EventJSON)) != nil || !bytes.Equal(event.Bytes(), canonical.Bytes()) {
		return invalidAudit()
	}
	leaf := sha256.Sum256(append([]byte("nono.audit.event.alpha\n"), []byte(record.EventJSON)...))
	if hex.EncodeToString(leaf[:]) != record.Leaf {
		return invalidAudit()
	}
	prior := make([]byte, 32)
	if previous != nil {
		var err error
		prior, err = hex.DecodeString(*previous)
		if err != nil || len(prior) != 32 {
			return invalidAudit()
		}
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("nono.audit.chain.alpha\n"))
	_, _ = hash.Write(prior)
	_, _ = hash.Write(leaf[:])
	if hex.EncodeToString(hash.Sum(nil)) != record.Chain {
		return invalidAudit()
	}
	return nil
}

func sameDigest(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
