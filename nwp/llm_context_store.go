// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nwp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

var llmContextIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)

// LlmContextOwner is the authenticated principal and deployment security scope.
type LlmContextOwner struct {
	NID           string
	SecurityScope string
}

// LlmContextBinding contains the immutable inputs required for retained-prefix reuse.
type LlmContextBinding struct {
	Model           string
	SystemMessages  []LlmMessageDto
	Tools           []LlmToolDefinitionDto
	RuntimeRevision string
}

// LlmContextMutationRequest is admitted before provider dispatch.
type LlmContextMutationRequest struct {
	Operation      LlmContextOperation
	Owner          LlmContextOwner
	ContextID      *string
	BaseVersion    *uint64
	Binding        LlmContextBinding
	Messages       []LlmMessageDto
	TTLSeconds     *uint32
	IdempotencyKey string
	RequestID      string
}

// LlmContextMutationReservation is an opaque, single-use mutation reservation.
type LlmContextMutationReservation struct {
	reservationID       string
	request             LlmContextMutationRequest
	bindingFingerprint  string
	baseTranscript      []LlmMessageDto
	effectiveTTLSeconds *uint32
	parentContextID     *string
	parentVersion       *uint64
}

func (r *LlmContextMutationReservation) Operation() LlmContextOperation { return r.request.Operation }
func (r *LlmContextMutationReservation) RequestID() string              { return r.request.RequestID }

// LlmContextSnapshot is a defensive copy of committed provider state.
type LlmContextSnapshot struct {
	ContextID  string
	Version    uint64
	State      LlmContextState
	Transcript []LlmMessageDto
	Binding    LlmContextBinding
	ExpiresAt  *time.Time
}

// LlmContextStoreError carries the canonical NWP error and optional CAS version.
type LlmContextStoreError struct {
	ErrorCode      string
	Message        string
	CurrentVersion *uint64
}

func (e *LlmContextStoreError) Error() string { return e.Message }

// LlmContextStoreOptions configures the process-local reference store.
type LlmContextStoreOptions struct {
	MaxContextsPerPrincipal uint32
	DefaultTTLSeconds       uint32
	MaxTTLSeconds           uint32
	TombstoneSeconds        uint32
	IdempotencyTTL          time.Duration
	SupportedOperations     map[LlmContextOperation]bool
	Clock                   func() time.Time
	ContextIDFactory        func() (string, error)
}

// LlmContextStoreDescriptor is the immutable capability surface advertised in NWM.
type LlmContextStoreDescriptor struct {
	Operations              []LlmContextOperation
	Persistence             string
	MaxContextsPerPrincipal uint32
	MaxTTLSeconds           uint32
	TombstoneSeconds        uint32
}

type llmContextEntry struct {
	contextID          string
	owner              LlmContextOwner
	version            uint64
	state              LlmContextState
	binding            LlmContextBinding
	bindingFingerprint string
	transcript         []LlmMessageDto
	ttlSeconds         uint32
	expiresAt          *time.Time
	tombstoneUntil     *time.Time
	reservationID      string
}

type llmIdempotencyEntry struct {
	state         string
	retainUntil   time.Time
	requestID     string
	reservationID string
	errorCode     string
	receipt       *LlmContextReceiptDto
	contextID     string
	baseVersion   *uint64
}

// InMemoryLlmContextStore implements the NWP 0.21 process persistence profile.
type InMemoryLlmContextStore struct {
	mu           sync.Mutex
	options      LlmContextStoreOptions
	contexts     map[string]*llmContextEntry
	idempotency  map[string]*llmIdempotencyEntry
	reservations map[string]*LlmContextMutationReservation
}

// NewInMemoryLlmContextStore returns a ready-to-use context state machine.
func NewInMemoryLlmContextStore(options LlmContextStoreOptions) *InMemoryLlmContextStore {
	if options.MaxContextsPerPrincipal == 0 {
		options.MaxContextsPerPrincipal = 32
	}
	if options.DefaultTTLSeconds == 0 {
		options.DefaultTTLSeconds = 3600
	}
	if options.MaxTTLSeconds == 0 {
		options.MaxTTLSeconds = 3600
	}
	if options.TombstoneSeconds == 0 {
		options.TombstoneSeconds = 86400
	}
	if options.IdempotencyTTL == 0 {
		options.IdempotencyTTL = 24 * time.Hour
	}
	if options.SupportedOperations == nil {
		options.SupportedOperations = map[LlmContextOperation]bool{
			LlmContextCreate: true, LlmContextAppend: true, LlmContextFork: true,
			LlmContextReset: true, LlmContextRelease: true,
		}
	} else {
		retained := make(map[LlmContextOperation]bool, len(options.SupportedOperations))
		for operation, supported := range options.SupportedOperations {
			retained[operation] = supported
		}
		options.SupportedOperations = retained
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.ContextIDFactory == nil {
		options.ContextIDFactory = newLlmContextID
	}
	return &InMemoryLlmContextStore{
		options:      options,
		contexts:     map[string]*llmContextEntry{},
		idempotency:  map[string]*llmIdempotencyEntry{},
		reservations: map[string]*LlmContextMutationReservation{},
	}
}

// Descriptor returns a defensive capability snapshot in canonical operation order.
func (s *InMemoryLlmContextStore) Descriptor() LlmContextStoreDescriptor {
	s.mu.Lock()
	defer s.mu.Unlock()
	order := []LlmContextOperation{
		LlmContextCreate, LlmContextAppend, LlmContextFork, LlmContextReset, LlmContextRelease,
	}
	operations := make([]LlmContextOperation, 0, len(order))
	for _, operation := range order {
		if s.options.SupportedOperations[operation] {
			operations = append(operations, operation)
		}
	}
	return LlmContextStoreDescriptor{
		Operations: operations, Persistence: "process",
		MaxContextsPerPrincipal: s.options.MaxContextsPerPrincipal,
		MaxTTLSeconds:           s.options.MaxTTLSeconds, TombstoneSeconds: s.options.TombstoneSeconds,
	}
}

// Reserve validates and atomically reserves a state transition.
func (s *InMemoryLlmContextStore) Reserve(request LlmContextMutationRequest) (*LlmContextMutationReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	if err := s.validateRequest(request); err != nil {
		return nil, err
	}
	if err := s.ensureSupported(request.Operation); err != nil {
		return nil, err
	}
	key := ownerKey(request.Owner, LlmCompleteActionID, request.IdempotencyKey)
	if _, exists := s.idempotency[key]; exists {
		return nil, storeError(ErrActionIdempotencyConflict, "an outcome already exists for this idempotency key", nil)
	}

	var reservation *LlmContextMutationReservation
	if request.Operation == LlmContextCreate {
		if err := s.ensureAllocationAvailable(request.Owner); err != nil {
			return nil, err
		}
		ttl := s.clampTTL(valueOr(request.TTLSeconds, s.options.DefaultTTLSeconds))
		reservation = s.newReservation(request, nil, &ttl, nil, nil)
	} else {
		entry, err := s.requireMutable(request.Owner, *request.ContextID)
		if err != nil {
			return nil, err
		}
		if entry.reservationID != "" || entry.version != *request.BaseVersion {
			return nil, storeError(ErrLlmContextVersionConflict,
				"the context version is stale or a mutation is running", uint64Ptr(entry.version))
		}
		fingerprint, err := bindingFingerprint(request.Binding)
		if err != nil {
			return nil, err
		}
		if (request.Operation == LlmContextAppend || request.Operation == LlmContextFork) &&
			entry.bindingFingerprint != fingerprint {
			return nil, storeError(ErrLlmContextBindingMismatch,
				"the request binding differs from the retained binding", nil)
		}
		if request.Operation == LlmContextFork {
			if err := s.ensureAllocationAvailable(request.Owner); err != nil {
				return nil, err
			}
		}
		ttl := s.effectiveTTL(request, entry)
		var parentID *string
		var parentVersion *uint64
		if request.Operation == LlmContextFork {
			parentID = stringPtr(entry.contextID)
			parentVersion = uint64Ptr(entry.version)
		}
		reservation = s.newReservation(request, entry.transcript, ttl, parentID, parentVersion)
		if request.Operation != LlmContextFork {
			entry.reservationID = reservation.reservationID
		}
	}

	s.reservations[reservation.reservationID] = reservation
	s.idempotency[key] = &llmIdempotencyEntry{
		state: "busy", requestID: request.RequestID, reservationID: reservation.reservationID,
		retainUntil: s.now().Add(s.options.IdempotencyTTL),
	}
	return reservation, nil
}

// Commit atomically applies a successful terminal provider result.
func (s *InMemoryLlmContextStore) Commit(
	reservation *LlmContextMutationReservation,
	assistantResult LlmMessageDto,
) (LlmContextReceiptDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.requireReservation(reservation)
	if err != nil {
		return LlmContextReceiptDto{}, err
	}
	request := current.request
	var expiry *time.Time
	if current.effectiveTTLSeconds != nil {
		value := s.now().Add(time.Duration(*current.effectiveTTLSeconds) * time.Second)
		expiry = &value
	}

	var entry *llmContextEntry
	var contextID string
	var version uint64
	if request.Operation == LlmContextCreate || request.Operation == LlmContextFork {
		contextID, err = s.nextContextID()
		if err != nil {
			return LlmContextReceiptDto{}, err
		}
		version = 1
		transcript := []LlmMessageDto{}
		if request.Operation == LlmContextFork {
			transcript = cloneMessages(current.baseTranscript)
		}
		transcript = append(transcript, cloneMessages(request.Messages)...)
		transcript = append(transcript, cloneMessage(assistantResult))
		entry = &llmContextEntry{
			contextID: contextID, owner: request.Owner, version: version, state: LlmContextActive,
			binding: cloneBinding(request.Binding), bindingFingerprint: current.bindingFingerprint,
			transcript: transcript, ttlSeconds: valueOr(current.effectiveTTLSeconds, 0), expiresAt: cloneTime(expiry),
		}
		s.contexts[contextID] = entry
	} else {
		entry, err = s.requireEntry(*request.ContextID)
		if err != nil {
			return LlmContextReceiptDto{}, err
		}
		contextID = entry.contextID
		version = entry.version + 1
		entry.version = version
		entry.state = LlmContextActive
		entry.reservationID = ""
		entry.expiresAt = cloneTime(expiry)
		entry.ttlSeconds = valueOr(current.effectiveTTLSeconds, 0)
		if request.Operation == LlmContextReset {
			entry.binding = cloneBinding(request.Binding)
			entry.bindingFingerprint = current.bindingFingerprint
			entry.transcript = append(cloneMessages(request.Messages), cloneMessage(assistantResult))
		} else {
			entry.transcript = append(entry.transcript, cloneMessages(request.Messages)...)
			entry.transcript = append(entry.transcript, cloneMessage(assistantResult))
		}
	}

	receipt := LlmContextReceiptDto{
		ContextID: contextID, Version: version, Operation: request.Operation, State: LlmContextActive,
		ParentContextID: cloneString(current.parentContextID), ParentVersion: cloneUint64(current.parentVersion),
	}
	if expiry != nil {
		formatted := expiry.Format(time.RFC3339Nano)
		receipt.ExpiresAt = &formatted
	}
	s.completeIdempotency(current, receipt)
	delete(s.reservations, current.reservationID)
	return receipt, nil
}

// Abort releases a reservation without changing committed transcript/version.
func (s *InMemoryLlmContextStore) Abort(reservation *LlmContextMutationReservation, errorCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.requireReservation(reservation)
	if err != nil {
		return err
	}
	s.clearReservation(current)
	delete(s.reservations, current.reservationID)
	request := current.request
	s.idempotency[ownerKey(request.Owner, LlmCompleteActionID, request.IdempotencyKey)] = &llmIdempotencyEntry{
		state: "failed", requestID: request.RequestID, errorCode: errorCode,
		retainUntil: s.now().Add(s.options.IdempotencyTTL),
	}
	s.sweepLocked(s.now())
	return nil
}

// Release creates a replay-idempotent released tombstone at vN+1.
func (s *InMemoryLlmContextStore) Release(
	owner LlmContextOwner,
	contextID string,
	baseVersion uint64,
	idempotencyKey string,
) (LlmContextReceiptDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	if err := s.ensureSupported(LlmContextRelease); err != nil {
		return LlmContextReceiptDto{}, err
	}
	if err := validateContextID(contextID); err != nil {
		return LlmContextReceiptDto{}, err
	}
	if idempotencyKey == "" {
		return LlmContextReceiptDto{}, paramsInvalid("release requires idempotency_key")
	}
	key := ownerKey(owner, LlmContextReleaseActionID, idempotencyKey)
	if prior, exists := s.idempotency[key]; exists {
		if prior.state == "completed" && prior.receipt != nil && prior.contextID == contextID &&
			prior.baseVersion != nil && *prior.baseVersion == baseVersion {
			return cloneReceipt(*prior.receipt), nil
		}
		return LlmContextReceiptDto{}, storeError(ErrActionIdempotencyConflict,
			"a release with this idempotency key already exists", nil)
	}
	entry, err := s.requireMutable(owner, contextID)
	if err != nil {
		return LlmContextReceiptDto{}, err
	}
	if entry.reservationID != "" || entry.version != baseVersion {
		return LlmContextReceiptDto{}, storeError(ErrLlmContextVersionConflict,
			"the context version is stale or a mutation is running", uint64Ptr(entry.version))
	}
	entry.version++
	entry.state = LlmContextReleased
	entry.expiresAt = nil
	tombstone := s.now().Add(time.Duration(s.options.TombstoneSeconds) * time.Second)
	entry.tombstoneUntil = &tombstone
	receipt := LlmContextReceiptDto{
		ContextID: contextID, Version: entry.version, Operation: LlmContextRelease, State: LlmContextReleased,
	}
	s.idempotency[key] = &llmIdempotencyEntry{
		state: "completed", receipt: receiptPtr(receipt), contextID: contextID,
		baseVersion: uint64Ptr(baseVersion), retainUntil: s.now().Add(s.options.IdempotencyTTL),
	}
	return receipt, nil
}

// Status resolves exactly one context ID or stateful completion idempotency key.
func (s *InMemoryLlmContextStore) Status(
	owner LlmContextOwner,
	contextID *string,
	idempotencyKey *string,
) (LlmContextStatusDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	if (contextID == nil) == (idempotencyKey == nil) {
		return LlmContextStatusDto{}, paramsInvalid("status requires exactly one locator")
	}
	if idempotencyKey != nil {
		outcome, exists := s.idempotency[ownerKey(owner, LlmCompleteActionID, *idempotencyKey)]
		if !exists {
			return LlmContextStatusDto{}, notFound()
		}
		switch outcome.state {
		case "busy":
			return LlmContextStatusDto{State: LlmContextBusy, RequestID: optionalString(outcome.requestID)}, nil
		case "failed":
			return LlmContextStatusDto{
				State: LlmContextFailed, RequestID: optionalString(outcome.requestID),
				ErrorCode: optionalString(outcome.errorCode),
			}, nil
		default:
			return s.statusFromReceiptLocked(owner, *outcome.receipt)
		}
	}
	return s.statusByContextLocked(owner, *contextID)
}

// Snapshot returns a defensive copy of active committed state.
func (s *InMemoryLlmContextStore) Snapshot(owner LlmContextOwner, contextID string) (LlmContextSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	entry, err := s.requireMutable(owner, contextID)
	if err != nil {
		return LlmContextSnapshot{}, err
	}
	return LlmContextSnapshot{
		ContextID: entry.contextID, Version: entry.version, State: entry.state,
		Transcript: cloneMessages(entry.transcript), Binding: cloneBinding(entry.binding),
		ExpiresAt: cloneTime(entry.expiresAt),
	}, nil
}

// SweepExpired transitions idle contexts and removes elapsed tombstones/outcomes.
func (s *InMemoryLlmContextStore) SweepExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(s.now())
}

func (s *InMemoryLlmContextStore) newReservation(
	request LlmContextMutationRequest,
	transcript []LlmMessageDto,
	ttl *uint32,
	parentID *string,
	parentVersion *uint64,
) *LlmContextMutationReservation {
	retained := cloneMutationRequest(request)
	fingerprint, _ := bindingFingerprint(retained.Binding)
	return &LlmContextMutationReservation{
		reservationID: newReservationID(), request: retained, bindingFingerprint: fingerprint,
		baseTranscript: cloneMessages(transcript), effectiveTTLSeconds: cloneUint32(ttl),
		parentContextID: cloneString(parentID), parentVersion: cloneUint64(parentVersion),
	}
}

func (s *InMemoryLlmContextStore) validateRequest(request LlmContextMutationRequest) error {
	if request.Operation == LlmContextRelease {
		return paramsInvalid("release uses the lifecycle action")
	}
	if request.IdempotencyKey == "" {
		return paramsInvalid("a stateful request requires idempotency_key")
	}
	if request.TTLSeconds != nil && *request.TTLSeconds == 0 {
		return paramsInvalid("ttl_seconds must be greater than zero")
	}
	if request.Operation == LlmContextCreate {
		if request.ContextID != nil || request.BaseVersion != nil {
			return paramsInvalid("create forbids context_id and base_version")
		}
	} else {
		if request.ContextID == nil || request.BaseVersion == nil {
			return paramsInvalid("append/fork/reset require context_id and base_version")
		}
		if err := validateContextID(*request.ContextID); err != nil {
			return err
		}
	}
	if request.Operation != LlmContextFork && len(request.Messages) == 0 {
		return paramsInvalid("only fork may carry an empty message delta")
	}
	if request.Operation == LlmContextAppend || request.Operation == LlmContextFork {
		for _, message := range request.Messages {
			if message.Role == "system" {
				return storeError(ErrLlmContextBindingMismatch,
					"append/fork deltas must not contain system messages", nil)
			}
		}
	}
	return nil
}

func (s *InMemoryLlmContextStore) effectiveTTL(request LlmContextMutationRequest, entry *llmContextEntry) *uint32 {
	if request.TTLSeconds != nil {
		value := s.clampTTL(*request.TTLSeconds)
		return &value
	}
	if request.Operation == LlmContextFork {
		if entry.expiresAt == nil {
			return nil
		}
		remaining := entry.expiresAt.Sub(s.now())
		seconds := uint32(max(int64(1), int64((remaining+time.Second-1)/time.Second)))
		return &seconds
	}
	if entry.ttlSeconds == 0 {
		return nil
	}
	return uint32Ptr(entry.ttlSeconds)
}

func (s *InMemoryLlmContextStore) ensureAllocationAvailable(owner LlmContextOwner) error {
	live := 0
	for _, entry := range s.contexts {
		if entry.owner == owner && entry.state == LlmContextActive {
			live++
		}
	}
	pending := 0
	for _, reservation := range s.reservations {
		if reservation.request.Owner == owner &&
			(reservation.request.Operation == LlmContextCreate || reservation.request.Operation == LlmContextFork) {
			pending++
		}
	}
	if live+pending >= int(s.options.MaxContextsPerPrincipal) {
		return storeError(ErrLlmContextLimitExceeded,
			"the principal's live context limit has been reached", nil)
	}
	return nil
}

func (s *InMemoryLlmContextStore) ensureSupported(operation LlmContextOperation) error {
	if !s.options.SupportedOperations[operation] {
		return storeError(ErrLlmContextOperationUnsupported,
			fmt.Sprintf("context operation %q is not advertised", operation), nil)
	}
	return nil
}

func (s *InMemoryLlmContextStore) requireMutable(owner LlmContextOwner, contextID string) (*llmContextEntry, error) {
	entry, err := s.requireEntry(contextID)
	if err != nil {
		return nil, err
	}
	if entry.owner != owner {
		return nil, storeError(ErrLlmContextForbidden, "the caller does not own this context", nil)
	}
	if entry.state == LlmContextExpired {
		return nil, storeError(ErrLlmContextExpired, "the context expired", uint64Ptr(entry.version))
	}
	if entry.state == LlmContextReleased {
		return nil, notFound()
	}
	return entry, nil
}

func (s *InMemoryLlmContextStore) requireEntry(contextID string) (*llmContextEntry, error) {
	entry, exists := s.contexts[contextID]
	if !exists {
		return nil, notFound()
	}
	return entry, nil
}

func (s *InMemoryLlmContextStore) requireReservation(
	reservation *LlmContextMutationReservation,
) (*LlmContextMutationReservation, error) {
	if reservation == nil {
		return nil, errors.New("context reservation is nil")
	}
	current, exists := s.reservations[reservation.reservationID]
	if !exists || current != reservation {
		return nil, errors.New("context reservation is not active")
	}
	return current, nil
}

func (s *InMemoryLlmContextStore) clearReservation(reservation *LlmContextMutationReservation) {
	if reservation.request.ContextID == nil {
		return
	}
	entry := s.contexts[*reservation.request.ContextID]
	if entry != nil && entry.reservationID == reservation.reservationID {
		entry.reservationID = ""
	}
}

func (s *InMemoryLlmContextStore) completeIdempotency(
	reservation *LlmContextMutationReservation,
	receipt LlmContextReceiptDto,
) {
	request := reservation.request
	s.idempotency[ownerKey(request.Owner, LlmCompleteActionID, request.IdempotencyKey)] = &llmIdempotencyEntry{
		state: "completed", requestID: request.RequestID, receipt: receiptPtr(receipt),
		retainUntil: s.now().Add(s.options.IdempotencyTTL),
	}
}

func (s *InMemoryLlmContextStore) statusFromReceiptLocked(
	owner LlmContextOwner,
	receipt LlmContextReceiptDto,
) (LlmContextStatusDto, error) {
	if _, exists := s.contexts[receipt.ContextID]; exists {
		return s.statusByContextLocked(owner, receipt.ContextID)
	}
	return LlmContextStatusDto{
		State: receipt.State, ContextID: stringPtr(receipt.ContextID), Version: uint64Ptr(receipt.Version),
		ExpiresAt: cloneString(receipt.ExpiresAt),
	}, nil
}

func (s *InMemoryLlmContextStore) statusByContextLocked(
	owner LlmContextOwner,
	contextID string,
) (LlmContextStatusDto, error) {
	if err := validateContextID(contextID); err != nil {
		return LlmContextStatusDto{}, err
	}
	entry, exists := s.contexts[contextID]
	if !exists {
		return LlmContextStatusDto{}, notFound()
	}
	if entry.owner != owner {
		return LlmContextStatusDto{}, storeError(ErrLlmContextForbidden,
			"the caller does not own this context", nil)
	}
	state := entry.state
	var requestID *string
	if entry.reservationID != "" {
		state = LlmContextBusy
		if reservation := s.reservations[entry.reservationID]; reservation != nil {
			requestID = optionalString(reservation.request.RequestID)
		}
	}
	status := LlmContextStatusDto{
		State: state, ContextID: stringPtr(entry.contextID), Version: uint64Ptr(entry.version), RequestID: requestID,
	}
	if entry.expiresAt != nil {
		formatted := entry.expiresAt.Format(time.RFC3339Nano)
		status.ExpiresAt = &formatted
	}
	return status, nil
}

func (s *InMemoryLlmContextStore) nextContextID() (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		value, err := s.options.ContextIDFactory()
		if err != nil {
			return "", err
		}
		if err := validateContextID(value); err != nil {
			return "", err
		}
		if _, exists := s.contexts[value]; !exists {
			return value, nil
		}
	}
	return "", errors.New("context ID factory repeatedly produced collisions")
}

func (s *InMemoryLlmContextStore) sweepLocked(now time.Time) int {
	changed := 0
	for _, entry := range s.contexts {
		if entry.state == LlmContextActive && entry.reservationID == "" && entry.expiresAt != nil &&
			!entry.expiresAt.After(now) {
			entry.state = LlmContextExpired
			entry.expiresAt = nil
			tombstone := now.Add(time.Duration(s.options.TombstoneSeconds) * time.Second)
			entry.tombstoneUntil = &tombstone
			changed++
		}
	}
	for key, entry := range s.contexts {
		if (entry.state == LlmContextExpired || entry.state == LlmContextReleased) &&
			entry.tombstoneUntil != nil && !entry.tombstoneUntil.After(now) {
			delete(s.contexts, key)
			changed++
		}
	}
	for key, entry := range s.idempotency {
		if entry.state != "busy" && !entry.retainUntil.After(now) {
			delete(s.idempotency, key)
			changed++
		}
	}
	return changed
}

func (s *InMemoryLlmContextStore) clampTTL(value uint32) uint32 {
	return min(value, s.options.MaxTTLSeconds)
}

func (s *InMemoryLlmContextStore) now() time.Time { return s.options.Clock() }

func bindingFingerprint(binding LlmContextBinding) (string, error) {
	canonical := struct {
		Model           string                 `json:"model"`
		SystemMessages  []LlmMessageDto        `json:"system_messages"`
		Tools           []LlmToolDefinitionDto `json:"tools"`
		RuntimeRevision string                 `json:"runtime_revision"`
	}{binding.Model, binding.SystemMessages, binding.Tools, binding.RuntimeRevision}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func newLlmContextID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func newReservationID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		panic(fmt.Sprintf("generate context reservation ID: %v", err))
	}
	return hex.EncodeToString(value)
}

func validateContextID(value string) error {
	if !llmContextIDPattern.MatchString(value) {
		return paramsInvalid("context_id must be a 22-128 character unpadded base64url locator")
	}
	return nil
}

func ownerKey(owner LlmContextOwner, action, key string) string {
	return owner.NID + "\x1f" + owner.SecurityScope + "\x1f" + action + "\x1f" + key
}

func storeError(code, message string, currentVersion *uint64) error {
	return &LlmContextStoreError{ErrorCode: code, Message: message, CurrentVersion: currentVersion}
}

func paramsInvalid(message string) error { return storeError(ErrActionParamsInvalid, message, nil) }
func notFound() error {
	return storeError(ErrLlmContextNotFound, "context or retained outcome not found", nil)
}

func cloneMutationRequest(value LlmContextMutationRequest) LlmContextMutationRequest {
	value.ContextID = cloneString(value.ContextID)
	value.BaseVersion = cloneUint64(value.BaseVersion)
	value.TTLSeconds = cloneUint32(value.TTLSeconds)
	value.Binding = cloneBinding(value.Binding)
	value.Messages = cloneMessages(value.Messages)
	return value
}

func cloneBinding(value LlmContextBinding) LlmContextBinding {
	value.SystemMessages = cloneMessages(value.SystemMessages)
	value.Tools = cloneTools(value.Tools)
	return value
}

func cloneMessages(values []LlmMessageDto) []LlmMessageDto {
	if values == nil {
		return nil
	}
	result := make([]LlmMessageDto, len(values))
	for index, value := range values {
		result[index] = cloneMessage(value)
	}
	return result
}

func cloneMessage(value LlmMessageDto) LlmMessageDto {
	value.Content = cloneString(value.Content)
	value.ToolCallID = cloneString(value.ToolCallID)
	value.ToolName = cloneString(value.ToolName)
	value.ToolCalls = append([]LlmToolCallDto(nil), value.ToolCalls...)
	return value
}

func cloneTools(values []LlmToolDefinitionDto) []LlmToolDefinitionDto {
	if values == nil {
		return nil
	}
	result := make([]LlmToolDefinitionDto, len(values))
	for index, value := range values {
		value.Description = cloneString(value.Description)
		value.Parameters = append([]ToolParameterDto(nil), value.Parameters...)
		for parameterIndex := range value.Parameters {
			value.Parameters[parameterIndex].Description = cloneString(value.Parameters[parameterIndex].Description)
		}
		result[index] = value
	}
	return result
}

func cloneReceipt(value LlmContextReceiptDto) LlmContextReceiptDto {
	value.ExpiresAt = cloneString(value.ExpiresAt)
	value.ParentContextID = cloneString(value.ParentContextID)
	value.ParentVersion = cloneUint64(value.ParentVersion)
	return value
}

func receiptPtr(value LlmContextReceiptDto) *LlmContextReceiptDto {
	result := cloneReceipt(value)
	return &result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func stringPtr(value string) *string { return &value }
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func uint32Ptr(value uint32) *uint32 { return &value }
func uint64Ptr(value uint64) *uint64 { return &value }
func valueOr[T any](value *T, fallback T) T {
	if value == nil {
		return fallback
	}
	return *value
}
