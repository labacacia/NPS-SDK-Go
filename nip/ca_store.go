// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// NipCertRecord is a persisted NIP certificate record (NPS-3 §5.1).
type NipCertRecord struct {
	Nid          string
	EntityType   string // "agent" | "node" | "operator"
	Serial       string
	PubKey       string
	Capabilities []string
	ScopeJson    string
	IssuedBy     string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	RevokeReason *string
	MetadataJson *string

	// NidRole — "group", "session", or nil (NPS-CR-0003 §5.1.3).
	NidRole *string
	// ParentNid — set on session records pointing to the group NID.
	ParentNid *string
	// LineageJson — full signed lineage object as canonical JSON.
	LineageJson *string
}

// NipCaStore is the persistence abstraction for NIP CA certificate storage.
type NipCaStore interface {
	Save(record *NipCertRecord) error
	GetByNid(nid string) (*NipCertRecord, error)
	GetBySerial(serial string) (*NipCertRecord, error)
	Revoke(nid, reason string, revokedAt time.Time) (bool, error)
	NextSerial() (string, error)
	List() ([]*NipCertRecord, error)
	GetRevoked() ([]*NipCertRecord, error)
	GetByParentNid(parentNid string) ([]*NipCertRecord, error)
}

// InMemoryNipCaStore is an in-memory NipCaStore for tests, demos, and
// single-process dev stacks. Not durable.
type InMemoryNipCaStore struct {
	mu      sync.Mutex
	records []*NipCertRecord
	serial  int64
}

// NewInMemoryNipCaStore builds an empty in-memory CA store.
func NewInMemoryNipCaStore() *InMemoryNipCaStore { return &InMemoryNipCaStore{} }

func (s *InMemoryNipCaStore) Save(record *NipCertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Serials are the unique invariant. Multiple records may share a NID:
	// renewal appends a new record and GetByNid returns the latest, keeping
	// the prior record for audit (mirrors .NET GetByNid → LastOrDefault). The
	// service-level NID-uniqueness guard runs in Register/RegisterGroup before
	// the initial Save.
	for _, r := range s.records {
		if r.Serial == record.Serial {
			return fmt.Errorf("serial already exists: %s", record.Serial)
		}
	}
	s.records = append(s.records, copyRecord(record))
	return nil
}

func (s *InMemoryNipCaStore) GetByNid(nid string) (*NipCertRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.records) - 1; i >= 0; i-- {
		if s.records[i].Nid == nid {
			return copyRecord(s.records[i]), nil
		}
	}
	return nil, nil
}

func (s *InMemoryNipCaStore) GetBySerial(serial string) (*NipCertRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.records {
		if r.Serial == serial {
			return copyRecord(r), nil
		}
	}
	return nil, nil
}

func (s *InMemoryNipCaStore) Revoke(nid, reason string, revokedAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.records) - 1; i >= 0; i-- {
		r := s.records[i]
		if r.Nid == nid && r.RevokedAt == nil {
			ra := revokedAt
			rs := reason
			r.RevokedAt = &ra
			r.RevokeReason = &rs
			return true, nil
		}
	}
	return false, nil
}

func (s *InMemoryNipCaStore) NextSerial() (string, error) {
	next := atomic.AddInt64(&s.serial, 1)
	return fmt.Sprintf("0x%X", next), nil
}

func (s *InMemoryNipCaStore) List() ([]*NipCertRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyRecords(s.records), nil
}

func (s *InMemoryNipCaStore) GetRevoked() ([]*NipCertRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*NipCertRecord
	for _, r := range s.records {
		if r.RevokedAt != nil {
			out = append(out, copyRecord(r))
		}
	}
	return out, nil
}

func (s *InMemoryNipCaStore) GetByParentNid(parentNid string) ([]*NipCertRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*NipCertRecord
	for _, r := range s.records {
		if r.ParentNid != nil && *r.ParentNid == parentNid {
			out = append(out, copyRecord(r))
		}
	}
	return out, nil
}

func copyRecord(r *NipCertRecord) *NipCertRecord {
	c := *r
	if r.Capabilities != nil {
		c.Capabilities = append([]string(nil), r.Capabilities...)
	}
	return &c
}

func copyRecords(rs []*NipCertRecord) []*NipCertRecord {
	out := make([]*NipCertRecord, 0, len(rs))
	for _, r := range rs {
		out = append(out, copyRecord(r))
	}
	return out
}
