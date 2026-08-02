// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package ndp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"
)

type NdpRegistryDecision string

const (
	NdpAccepted  NdpRegistryDecision = "accepted"
	NdpDuplicate NdpRegistryDecision = "duplicate"
	NdpRefreshed NdpRegistryDecision = "refreshed"
	NdpRemoved   NdpRegistryDecision = "removed"
	NdpRejected  NdpRegistryDecision = "rejected"
)

type NdpRegistryAdmission struct {
	Decision  NdpRegistryDecision
	ErrorCode string
}

type NdpClusterSelection struct {
	NID       string
	Epoch     uint64
	ErrorCode string
}

type profileEntry struct {
	frame        map[string]any
	signedDigest string
	expiresAt    time.Time
}

// CanonicalAnnounceJSON returns the NDP 0.12 signed body.
func CanonicalAnnounceJSON(frame map[string]any) (string, error) {
	root := make(map[string]any, len(frame)+1)
	for key, value := range frame {
		if key == "frame" || key == "signature" || key == "health" || key == "last_seen" || value == nil {
			continue
		}
		root[key] = withoutNulls(value)
	}
	if _, ok := root["heartbeat_interval_ms"]; !ok {
		root["heartbeat_interval_ms"] = 60_000
	}
	encoded, err := json.Marshal(root)
	return string(encoded), err
}

// VerifyAnnounceSignature verifies an ed25519:<base64url> Announce signature.
func VerifyAnnounceSignature(frame map[string]any, encodedPublicKey, encodedSignature string) bool {
	const prefix = "ed25519:"
	if !strings.HasPrefix(encodedPublicKey, prefix) || !strings.HasPrefix(encodedSignature, prefix) {
		return false
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encodedPublicKey, prefix))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encodedSignature, prefix))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	canonical, err := CanonicalAnnounceJSON(frame)
	return err == nil && ed25519.Verify(publicKey, []byte(canonical), signature)
}

// NdpRegistryProfile is the transport-independent NDP 0.12 registry state machine.
type NdpRegistryProfile struct {
	SecurityProfile string
	entries         map[string]profileEntry
	sequences       map[string]uint64
}

func NewNdpRegistryProfile(securityProfile string) *NdpRegistryProfile {
	if securityProfile == "" {
		securityProfile = "local-dev"
	}
	return &NdpRegistryProfile{
		SecurityProfile: securityProfile,
		entries:         make(map[string]profileEntry),
		sequences:       make(map[string]uint64),
	}
}

func (r *NdpRegistryProfile) ApplyAnnounce(
	frame map[string]any,
	signatureValid bool,
	receivedAt time.Time,
) NdpRegistryAdmission {
	if !signatureValid {
		return rejectAdmission(ErrAnnounceSignatureInvalid)
	}
	nid, _ := frame["nid"].(string)
	timestamp, ok := timeValue(frame, "timestamp")
	if nid == "" || !ok {
		return rejectAdmission(ErrAnnounceProfileViolation)
	}
	sequenceValue, sequencePresent := frame["graph_seq"]
	sequence, hasSequence := uintValue(sequenceValue)
	ttl, hasTtl := uintValue(frame["ttl"])
	if (sequencePresent && !hasSequence) ||
		(!sequencePresent && r.SecurityProfile != "local-dev") ||
		!hasTtl || ttl > uint64(1<<32-1) {
		return rejectAdmission(ErrAnnounceProfileViolation)
	}
	if !bridgeShapeIsValid(frame) {
		return rejectAdmission(ErrAnnounceProfileViolation)
	}
	if r.SecurityProfile != "local-dev" && receivedAt.Sub(timestamp).Abs() > 5*time.Minute {
		return rejectAdmission(ErrAnnounceSignatureInvalid)
	}

	canonical, err := CanonicalAnnounceJSON(frame)
	if err != nil {
		return rejectAdmission(ErrAnnounceProfileViolation)
	}
	sum := sha256.Sum256([]byte(canonical))
	digest := hex.EncodeToString(sum[:])
	if highest, exists := r.sequences[nid]; exists {
		if sequence < highest {
			return rejectAdmission(ErrGraphSeqRollback)
		}
		if sequence == highest {
			current, live := r.entries[nid]
			if !live {
				return NdpRegistryAdmission{Decision: NdpDuplicate}
			}
			if current.signedDigest != digest {
				return rejectAdmission(ErrAnnounceConflict)
			}
			if sameLiveness(current.frame, frame) {
				return NdpRegistryAdmission{Decision: NdpDuplicate}
			}
			expiresAt, ok := freshnessDeadline(frame)
			if !ok || !expiresAt.After(receivedAt) {
				return rejectAdmission(ErrAnnounceStale)
			}
			r.entries[nid] = profileEntry{cloneMap(frame), digest, expiresAt}
			return NdpRegistryAdmission{Decision: NdpRefreshed}
		}
	}

	if ttl == 0 {
		r.sequences[nid] = sequence
		delete(r.entries, nid)
		return NdpRegistryAdmission{Decision: NdpRemoved}
	}
	expiresAt, ok := freshnessDeadline(frame)
	if !ok || !expiresAt.After(receivedAt) {
		return rejectAdmission(ErrAnnounceStale)
	}
	r.sequences[nid] = sequence
	r.entries[nid] = profileEntry{cloneMap(frame), digest, expiresAt}
	return NdpRegistryAdmission{Decision: NdpAccepted}
}

func (r *NdpRegistryProfile) LiveNIDs(now time.Time) []string {
	result := make([]string, 0)
	for nid, entry := range r.entries {
		if entry.expiresAt.After(now) {
			result = append(result, nid)
		}
	}
	sort.Strings(result)
	return result
}

func (r *NdpRegistryProfile) HighestSequences() map[string]uint64 {
	result := make(map[string]uint64, len(r.sequences))
	for nid, sequence := range r.sequences {
		result[nid] = sequence
	}
	return result
}

func (r *NdpRegistryProfile) HasStaleEntry(now time.Time) bool {
	for _, entry := range r.entries {
		if !entry.expiresAt.After(now) {
			return true
		}
	}
	return false
}

func (r *NdpRegistryProfile) ResolveCluster(clusterAnchor string, now time.Time) NdpClusterSelection {
	type member struct {
		nid   string
		epoch uint64
	}
	members := make([]member, 0)
	for nid, entry := range r.entries {
		if !entry.expiresAt.After(now) || stringField(entry.frame, "cluster_anchor") != clusterAnchor ||
			!contains(stringsField(entry.frame, "node_roles"), "anchor") {
			continue
		}
		epoch, ok := uintValue(entry.frame["cluster_epoch"])
		if !ok {
			epoch = 1
		}
		members = append(members, member{nid, epoch})
	}
	if len(members) == 0 {
		return NdpClusterSelection{}
	}
	var top uint64
	for _, candidate := range members {
		if candidate.epoch > top {
			top = candidate.epoch
		}
	}
	leaders := make([]string, 0)
	for _, candidate := range members {
		if candidate.epoch == top {
			leaders = append(leaders, candidate.nid)
		}
	}
	sort.Strings(leaders)
	if len(leaders) != 1 {
		return NdpClusterSelection{ErrorCode: ErrClusterSplit}
	}
	return NdpClusterSelection{NID: leaders[0], Epoch: top}
}

func (r *NdpRegistryProfile) DiscoverBridges(direction, protocol string, now time.Time) ([]string, error) {
	field := ""
	switch direction {
	case "inbound":
		field = "bridge_inbound_protocols"
	case "outbound":
		field = "bridge_protocols"
	default:
		return nil, errors.New("bridge direction must be inbound or outbound")
	}
	result := make([]string, 0)
	for nid, entry := range r.entries {
		if entry.expiresAt.After(now) && stringField(entry.frame, "health") != "draining" &&
			isBridge(entry.frame) && contains(stringsField(entry.frame, field), protocol) {
			result = append(result, nid)
		}
	}
	sort.Strings(result)
	return result, nil
}

func rejectAdmission(errorCode string) NdpRegistryAdmission {
	return NdpRegistryAdmission{Decision: NdpRejected, ErrorCode: errorCode}
}

func bridgeShapeIsValid(frame map[string]any) bool {
	outboundPresent, outbound, outboundValid := protocolList(frame, "bridge_protocols")
	inboundPresent, inbound, inboundValid := protocolList(frame, "bridge_inbound_protocols")
	if !outboundValid || !inboundValid {
		return false
	}
	if isBridge(frame) {
		return len(outbound)+len(inbound) > 0
	}
	return !outboundPresent && !inboundPresent
}

func protocolList(frame map[string]any, field string) (bool, []string, bool) {
	value, present := frame[field]
	if !present {
		return false, nil, true
	}
	values, ok := value.([]any)
	if !ok {
		if typed, typedOK := value.([]string); typedOK {
			values := make([]string, len(typed))
			copy(values, typed)
			for _, item := range values {
				if strings.TrimSpace(item) == "" {
					return true, nil, false
				}
			}
			return true, values, true
		}
		return true, nil, false
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return true, nil, false
		}
		result = append(result, text)
	}
	return true, result, true
}

func isBridge(frame map[string]any) bool {
	return contains(stringsField(frame, "node_roles"), "bridge") || stringField(frame, "node_type") == "bridge"
}

func sameLiveness(left, right map[string]any) bool {
	return stringField(left, "health") == stringField(right, "health") &&
		stringField(left, "last_seen") == stringField(right, "last_seen")
}

func freshnessDeadline(frame map[string]any) (time.Time, bool) {
	source, ok := timeValue(frame, "last_seen")
	if !ok {
		source, ok = timeValue(frame, "timestamp")
	}
	if !ok {
		return time.Time{}, false
	}
	ttl, _ := uintValue(frame["ttl"])
	return source.Add(time.Duration(ttl) * time.Second), true
}

func timeValue(frame map[string]any, field string) (time.Time, bool) {
	value := stringField(frame, field)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

func uintValue(value any) (uint64, bool) {
	switch number := value.(type) {
	case uint64:
		return number, true
	case int:
		return uint64(number), number >= 0
	case int64:
		return uint64(number), number >= 0
	case float64:
		return uint64(number), number >= 0 && !math.IsInf(number, 0) &&
			math.Trunc(number) == number
	case json.Number:
		parsed, err := number.Int64()
		return uint64(parsed), err == nil && parsed >= 0
	default:
		return 0, false
	}
}

func stringField(frame map[string]any, field string) string {
	value, _ := frame[field].(string)
	return value
}

func stringsField(frame map[string]any, field string) []string {
	switch values := frame[field].(type) {
	case []string:
		return values
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func cloneMap(value map[string]any) map[string]any {
	cloned, _ := withoutNulls(value).(map[string]any)
	return cloned
}

func withoutNulls(value any) any {
	switch item := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(item))
		for key, nested := range item {
			if nested != nil {
				result[key] = withoutNulls(nested)
			}
		}
		return result
	case []any:
		result := make([]any, len(item))
		for index, nested := range item {
			result[index] = withoutNulls(nested)
		}
		return result
	default:
		return value
	}
}
