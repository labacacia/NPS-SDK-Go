// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	"crypto/ed25519"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/labacacia/NPS-sdk-go/core"
)

// NPS X.509 OIDs (NPS-RFC-0002 §4) — kept in-package to avoid an import cycle
// with nip/x509 (which imports nip for AssuranceLevel).
var (
	oidEkuAgentIdentity          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 1, 1}
	oidEkuNodeIdentity           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 1, 2}
	oidNidAssuranceLevel         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65715, 2, 1}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// Lineage role constants (NPS-CR-0003 §5.1.3).
const (
	IdentLineageRoleGroup   = "group"
	IdentLineageRoleSession = "session"
)

// NipCaError is raised when a NIP CA operation cannot be completed (NPS-3 §9).
type NipCaError struct {
	Message   string
	ErrorCode string
}

func (e *NipCaError) Error() string { return e.Message }

func newCaErr(errorCode, format string, args ...any) *NipCaError {
	return &NipCaError{Message: fmt.Sprintf(format, args...), ErrorCode: errorCode}
}

// NipCaOptions configures the NIP CA service (NPS-3 §8).
type NipCaOptions struct {
	// CaNid, e.g. "urn:nps:org:ca.example.com". Used as issued_by in all frames.
	CaNid       string
	DisplayName string
	BaseUrl     string
	// RoutePrefix — HTTP route prefix for CA endpoints. Default "".
	RoutePrefix string

	AgentCertValidityDays int
	NodeCertValidityDays  int
	RenewalWindowDays     int
	GroupCertValidityDays int

	SessionDefaultValidity time.Duration
	SessionMaxValidity     time.Duration
	SessionMinValidity     time.Duration
	SessionJwsClockSkew    time.Duration

	NormalizeOcspResponseTime bool
	Algorithms                []string

	// OperatorApiKey — Bearer token required on operator endpoints. When "",
	// operator auth is skipped (development only).
	OperatorApiKey string
	// AllowedCapabilities — when non-nil, only these caps may be requested.
	AllowedCapabilities map[string]bool

	EnrollmentTier              EnrollmentTier
	EnrollmentAllowlistPatterns []string
	BootstrapTokenMaxTtl        time.Duration
	PendingQueueMaxSize         int
	PendingQueueMaxAge          time.Duration
}

// DefaultNipCaOptions returns options with the .NET reference defaults applied.
func DefaultNipCaOptions(caNid, baseUrl string) NipCaOptions {
	return NipCaOptions{
		CaNid:                       caNid,
		BaseUrl:                     baseUrl,
		AgentCertValidityDays:       30,
		NodeCertValidityDays:        90,
		RenewalWindowDays:           7,
		GroupCertValidityDays:       365,
		SessionDefaultValidity:      time.Hour,
		SessionMaxValidity:          24 * time.Hour,
		SessionMinValidity:          time.Minute,
		SessionJwsClockSkew:         5 * time.Minute,
		NormalizeOcspResponseTime:   true,
		Algorithms:                  []string{"ed25519"},
		EnrollmentTier:              EnrollmentTierAllowlist,
		EnrollmentAllowlistPatterns: []string{"*"},
		BootstrapTokenMaxTtl:        24 * time.Hour,
		PendingQueueMaxSize:         1000,
		PendingQueueMaxAge:          7 * 24 * time.Hour,
	}
}

func (o *NipCaOptions) applyDefaults() {
	if o.AgentCertValidityDays == 0 {
		o.AgentCertValidityDays = 30
	}
	if o.NodeCertValidityDays == 0 {
		o.NodeCertValidityDays = 90
	}
	if o.RenewalWindowDays == 0 {
		o.RenewalWindowDays = 7
	}
	if o.GroupCertValidityDays == 0 {
		o.GroupCertValidityDays = 365
	}
	if o.SessionDefaultValidity == 0 {
		o.SessionDefaultValidity = time.Hour
	}
	if o.SessionMaxValidity == 0 {
		o.SessionMaxValidity = 24 * time.Hour
	}
	if o.SessionMinValidity == 0 {
		o.SessionMinValidity = time.Minute
	}
	if o.SessionJwsClockSkew == 0 {
		o.SessionJwsClockSkew = 5 * time.Minute
	}
	if o.Algorithms == nil {
		o.Algorithms = []string{"ed25519"}
	}
	if o.EnrollmentTier == 0 {
		o.EnrollmentTier = EnrollmentTierAllowlist
	}
	if o.EnrollmentAllowlistPatterns == nil {
		o.EnrollmentAllowlistPatterns = []string{"*"}
	}
	if o.BootstrapTokenMaxTtl == 0 {
		o.BootstrapTokenMaxTtl = 24 * time.Hour
	}
	if o.PendingQueueMaxSize == 0 {
		o.PendingQueueMaxSize = 1000
	}
	if o.PendingQueueMaxAge == 0 {
		o.PendingQueueMaxAge = 7 * 24 * time.Hour
	}
}

// NipVerifyResult describes the outcome of a NID verification.
type NipVerifyResult struct {
	Valid     bool
	ErrorCode string
	Message   string
	Record    *NipCertRecord
}

func verifyOk(r *NipCertRecord) NipVerifyResult { return NipVerifyResult{Valid: true, Record: r} }
func verifyFail(code, msg string) NipVerifyResult {
	return NipVerifyResult{Valid: false, ErrorCode: code, Message: msg}
}

// NipCaService is the core CA business logic (NPS-3 §6–8).
type NipCaService struct {
	opts  NipCaOptions
	store NipCaStore
	keys  *NipIdentity
}

// NewNipCaService builds a CA service over the given store + CA key.
func NewNipCaService(opts NipCaOptions, store NipCaStore, keys *NipIdentity) *NipCaService {
	opts.applyDefaults()
	return &NipCaService{opts: opts, store: store, keys: keys}
}

// Options returns a copy of the effective options.
func (s *NipCaService) Options() NipCaOptions { return s.opts }

const rfc3339Nano = "2006-01-02T15:04:05.0000000Z07:00"

func isoTime(t time.Time) string { return t.UTC().Format(rfc3339Nano) }

// GetCaPublicKey returns the CA public key in "ed25519:{base64url}" form.
func (s *NipCaService) GetCaPublicKey() string { return s.keys.PubKeyString() }

// SignArtifact signs an arbitrary CA-owned JSON artifact with the CA key.
func (s *NipCaService) SignArtifact(artifact core.FrameDict) string { return s.keys.Sign(artifact) }

// BuildNid builds a NID from the CA issuer domain + an entity identifier.
//
//	"urn:nps:org:ca.example.com" + ("agent","x") → "urn:nps:agent:ca.example.com:x"
func (s *NipCaService) BuildNid(entityType, identifier string) string {
	parts := strings.Split(s.opts.CaNid, ":")
	domain := s.opts.CaNid
	if len(parts) >= 4 {
		domain = parts[3]
	}
	return fmt.Sprintf("urn:nps:%s:%s:%s", entityType, domain, identifier)
}

// buildSignedPayload builds the canonical signed IdentFrame payload. Field
// order is irrelevant (canonicalJSON sorts); assurance_level / lineage are
// omitted when absent to stay bit-compatible with pre-CR-0003 verifiers.
func (s *NipCaService) buildSignedPayload(
	nid, pubKey string, capabilities []string, scope map[string]any,
	issuedAt, expiresAt, serial string,
	assurance *AssuranceLevel, lineage map[string]any,
) core.FrameDict {
	caps := capabilities
	if caps == nil {
		caps = []string{}
	}
	if scope == nil {
		scope = map[string]any{}
	}
	d := core.FrameDict{
		"capabilities": caps,
		"expires_at":   expiresAt,
		"frame":        "0x20",
		"issued_at":    issuedAt,
		"issued_by":    s.opts.CaNid,
		"nid":          nid,
		"pub_key":      pubKey,
		"scope":        scope,
		"serial":       serial,
	}
	if assurance != nil {
		d["assurance_level"] = assurance.Wire
	}
	if lineage != nil {
		d["lineage"] = lineage
	}
	return d
}

func (s *NipCaService) issueFrame(
	nid, pubKey string, capabilities []string, scopeJSON string,
	issuedAt, expiresAt time.Time, serial string, metadataJSON string,
	assurance *AssuranceLevel, lineage map[string]any,
) (*IdentFrame, error) {
	scope := map[string]any{}
	if scopeJSON != "" {
		if err := json.Unmarshal([]byte(scopeJSON), &scope); err != nil {
			return nil, newCaErr(ErrCertFormatInvalid, "invalid scope JSON: %v", err)
		}
	}
	issuedStr := isoTime(issuedAt)
	expiresStr := isoTime(expiresAt)

	payload := s.buildSignedPayload(nid, pubKey, capabilities, scope, issuedStr, expiresStr, serial, assurance, lineage)
	sig := s.keys.Sign(payload)

	var meta map[string]any
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &meta); err != nil {
			return nil, newCaErr(ErrCertFormatInvalid, "invalid metadata JSON: %v", err)
		}
	}
	caps := capabilities
	if caps == nil {
		caps = []string{}
	}
	f := &IdentFrame{
		NID:            nid,
		PubKey:         pubKey,
		Meta:           meta,
		Signature:      &sig,
		IssuedBy:       s.opts.CaNid,
		IssuedAt:       issuedStr,
		ExpiresAt:      expiresStr,
		Serial:         serial,
		Capabilities:   caps,
		Scope:          scope,
		AssuranceLevel: assurance,
	}
	f.lineage = lineage
	return f, nil
}

// frameLineage returns the lineage object attached to an issued frame, or nil.
func frameLineage(f *IdentFrame) map[string]any { return f.lineage }

func (s *NipCaService) checkAllowedCaps(capabilities []string) error {
	if s.opts.AllowedCapabilities == nil {
		return nil
	}
	var disallowed []string
	for _, c := range capabilities {
		if !s.opts.AllowedCapabilities[c] {
			disallowed = append(disallowed, c)
		}
	}
	if len(disallowed) > 0 {
		return newCaErr(ErrCertCapabilityMissing,
			"Capabilities not permitted by this CA: %s", strings.Join(disallowed, ", "))
	}
	return nil
}

// Register registers a new Agent or Node and issues an IdentFrame.
func (s *NipCaService) Register(
	entityType, identifier, pubKey string,
	capabilities []string, scopeJSON, metadataJSON string,
) (*IdentFrame, error) {
	nid := s.BuildNid(entityType, identifier)
	if existing, _ := s.store.GetByNid(nid); existing != nil {
		return nil, newCaErr(ErrCaNidAlreadyExists, "NID already exists: %s", nid)
	}
	if err := s.checkAllowedCaps(capabilities); err != nil {
		return nil, err
	}

	validDays := s.opts.AgentCertValidityDays
	if entityType == "node" {
		validDays = s.opts.NodeCertValidityDays
	}
	now := time.Now().UTC()
	expiresAt := now.AddDate(0, 0, validDays)
	serial, err := s.store.NextSerial()
	if err != nil {
		return nil, err
	}

	frame, err := s.issueFrame(nid, pubKey, capabilities, scopeJSON, now, expiresAt, serial, metadataJSON, nil, nil)
	if err != nil {
		return nil, err
	}
	rec := &NipCertRecord{
		Nid: nid, EntityType: entityType, Serial: serial, PubKey: pubKey,
		Capabilities: capabilities, ScopeJson: scopeJSON, IssuedBy: s.opts.CaNid,
		IssuedAt: now, ExpiresAt: expiresAt, MetadataJson: nilStr(metadataJSON),
	}
	if err := s.store.Save(rec); err != nil {
		return nil, err
	}
	return frame, nil
}

// RegisterWithRa runs the active EnrollmentPolicy before delegating to Register.
// Tier-3 policies raise *NipRaPendingError (caller returns 202).
func (s *NipCaService) RegisterWithRa(
	entityType, identifier, pubKey string,
	capabilities []string, scopeJSON, metadataJSON, enrollmentToken string,
	policy EnrollmentPolicy,
) (*IdentFrame, error) {
	if policy != nil {
		if err := policy.Check(entityType, identifier, pubKey, capabilities, scopeJSON, metadataJSON, enrollmentToken); err != nil {
			return nil, err
		}
	}
	return s.Register(entityType, identifier, pubKey, capabilities, scopeJSON, metadataJSON)
}

// CreateEnrollmentPolicy builds the policy selected by opts.EnrollmentTier.
func CreateEnrollmentPolicy(opts NipCaOptions, bootstrapStore BootstrapTokenStore, pendingStore PendingStore) (EnrollmentPolicy, error) {
	opts.applyDefaults()
	switch opts.EnrollmentTier {
	case EnrollmentTierAllowlist:
		return NewAllowlistPolicy(opts.EnrollmentAllowlistPatterns), nil
	case EnrollmentTierBootstrapToken:
		if bootstrapStore == nil {
			return nil, fmt.Errorf("EnrollmentTierBootstrapToken requires a BootstrapTokenStore")
		}
		return NewBootstrapTokenPolicy(bootstrapStore), nil
	case EnrollmentTierPendingQueue:
		if pendingStore == nil {
			return nil, fmt.Errorf("EnrollmentTierPendingQueue requires a PendingStore")
		}
		return NewPendingQueuePolicy(pendingStore, opts.PendingQueueMaxSize), nil
	default:
		return nil, fmt.Errorf("unknown EnrollmentTier: %d", opts.EnrollmentTier)
	}
}

// RegisterX509 registers an entity and issues an IdentFrame carrying both the
// v1 CA-signed proof and a DER X.509 chain (NPS-RFC-0002 §4.1).
func (s *NipCaService) RegisterX509(
	entityType, identifier, pubKey string,
	capabilities []string, scopeJSON string,
	assurance AssuranceLevel, metadataJSON string,
	rootCert []byte,
) (*IdentFrame, error) {
	nid := s.BuildNid(entityType, identifier)
	if existing, _ := s.store.GetByNid(nid); existing != nil {
		return nil, newCaErr(ErrCaNidAlreadyExists, "NID already exists: %s", nid)
	}
	if err := s.checkAllowedCaps(capabilities); err != nil {
		return nil, err
	}

	validDays := s.opts.AgentCertValidityDays
	if entityType == "node" {
		validDays = s.opts.NodeCertValidityDays
	}
	now := time.Now().UTC()
	expiresAt := now.AddDate(0, 0, validDays)
	serial, err := s.store.NextSerial()
	if err != nil {
		return nil, err
	}

	frame, err := s.issueFrame(nid, pubKey, capabilities, scopeJSON, now, expiresAt, serial, metadataJSON, &assurance, nil)
	if err != nil {
		return nil, err
	}

	subjectRaw, err := extractEd25519Raw(pubKey)
	if err != nil {
		return nil, err
	}
	leafSerial := parseSerialBytes(serial)
	leaf, err := s.issueLeafCert(nid, subjectRaw, entityType, assurance, now, expiresAt, leafSerial)
	if err != nil {
		return nil, newCaErr(ErrCertFormatInvalid, "X.509 leaf issuance failed: %v", err)
	}

	if rootCert == nil {
		rc, err := s.caRootCert(now)
		if err != nil {
			return nil, err
		}
		rootCert = rc
	}

	certFormat := CertFormatV2X509
	frame.CertFormat = &certFormat
	frame.CertChain = []string{base64Url(leaf), base64Url(rootCert)}

	rec := &NipCertRecord{
		Nid: nid, EntityType: entityType, Serial: serial, PubKey: pubKey,
		Capabilities: capabilities, ScopeJson: scopeJSON, IssuedBy: s.opts.CaNid,
		IssuedAt: now, ExpiresAt: expiresAt, MetadataJson: nilStr(metadataJSON),
	}
	if err := s.store.Save(rec); err != nil {
		return nil, err
	}
	return frame, nil
}

// issueLeafCert issues a DER-encoded NPS NID leaf certificate (NPS-RFC-0002 §4.1),
// inlined to avoid an import cycle with nip/x509.
func (s *NipCaService) issueLeafCert(
	nid string, subjectPub ed25519.PublicKey, entityType string,
	assurance AssuranceLevel, notBefore, notAfter time.Time, serial *big.Int,
) ([]byte, error) {
	ekuOid := oidEkuAgentIdentity
	if entityType == "node" {
		ekuOid = oidEkuNodeIdentity
	}
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{ekuOid})
	if err != nil {
		return nil, err
	}
	// ASN.1 ENUMERATED encoding of the assurance level rank.
	assuranceDer := []byte{0x0A, 0x01, byte(assurance.Rank)}

	uri, err := url.Parse(nid)
	if err != nil {
		return nil, err
	}
	tmpl := &cryptox509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nid},
		Issuer:                pkix.Name{CommonName: s.opts.CaNid},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              cryptox509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{uri},
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionExtendedKeyUsage, Critical: true, Value: ekuValue},
			{Id: oidNidAssuranceLevel, Critical: false, Value: assuranceDer},
		},
	}
	parent := &cryptox509.Certificate{Subject: pkix.Name{CommonName: s.opts.CaNid}}
	return cryptox509.CreateCertificate(rand.Reader, tmpl, parent, subjectPub, s.keys.privKey)
}

func (s *NipCaService) caRootCert(now time.Time) ([]byte, error) {
	serial := make([]byte, 16)
	_, _ = rand.Read(serial)
	serial[0] &= 0x7F
	if serial[0] == 0 {
		serial[0] = 0x01
	}
	tmpl := &cryptox509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial),
		Subject:               pkix.Name{CommonName: s.opts.CaNid},
		Issuer:                pkix.Name{CommonName: s.opts.CaNid},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	pub := s.keys.privKey.Public().(ed25519.PublicKey)
	der, err := cryptox509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, s.keys.privKey)
	if err != nil {
		return nil, newCaErr(ErrCertFormatInvalid, "CA root cert generation failed: %v", err)
	}
	return der, nil
}

// RegisterGroup registers an orchestrator group NID with lineage.role="group"
// (NPS-CR-0003 §5.1.3). identifier MUST start with "group-" or be empty (auto).
func (s *NipCaService) RegisterGroup(
	identifier, pubKey string, capabilities []string, scopeJSON,
	ownerUserId, ownerKeyId, metadataJSON string,
) (*IdentFrame, error) {
	if identifier == "" {
		identifier = "group-" + randHexN(16)
	} else if !strings.HasPrefix(identifier, "group-") {
		return nil, newCaErr(ErrCaNidAlreadyExists,
			"Group identifier MUST start with reserved prefix 'group-' (got '%s'). NPS-3 §3.1.", identifier)
	}

	nid := s.BuildNid("agent", identifier)
	if existing, _ := s.store.GetByNid(nid); existing != nil {
		return nil, newCaErr(ErrCaNidAlreadyExists, "NID already exists: %s", nid)
	}
	if err := s.checkAllowedCaps(capabilities); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.AddDate(0, 0, s.opts.GroupCertValidityDays)
	serial, err := s.store.NextSerial()
	if err != nil {
		return nil, err
	}

	lineage := lineageMap(map[string]string{
		"role":          IdentLineageRoleGroup,
		"owner_user_id": ownerUserId,
		"owner_key_id":  ownerKeyId,
	})
	lineageJSON, _ := json.Marshal(lineage)

	frame, err := s.issueFrame(nid, pubKey, capabilities, scopeJSON, now, expiresAt, serial, metadataJSON, nil, lineage)
	if err != nil {
		return nil, err
	}
	rec := &NipCertRecord{
		Nid: nid, EntityType: "agent", Serial: serial, PubKey: pubKey,
		Capabilities: capabilities, ScopeJson: scopeJSON, IssuedBy: s.opts.CaNid,
		IssuedAt: now, ExpiresAt: expiresAt, MetadataJson: nilStr(metadataJSON),
		NidRole: strPtr(IdentLineageRoleGroup), LineageJson: strPtr(string(lineageJSON)),
	}
	if err := s.store.Save(rec); err != nil {
		return nil, err
	}
	return frame, nil
}

// IssueSessionParams carries the optional inputs for IssueSession.
type IssueSessionParams struct {
	Validity     time.Duration // 0 → default
	Purpose      string
	Capabilities []string // nil → inherit group
	ScopeJSON    string   // "" → inherit group
	MetadataJSON string
}

// IssueSession issues a short-lived session NID under groupNid (NPS-CR-0003
// §5.1.3). Validity is clamped to [SessionMinValidity, SessionMaxValidity];
// capabilities MUST be a subset of the group's.
func (s *NipCaService) IssueSession(groupNid, sessionPubKey string, p IssueSessionParams) (*IdentFrame, error) {
	group, _ := s.store.GetByNid(groupNid)
	if group == nil {
		return nil, newCaErr(ErrCaParentNotFound, "Group NID not found: %s.", groupNid)
	}
	if group.NidRole == nil || *group.NidRole != IdentLineageRoleGroup {
		role := "<null>"
		if group.NidRole != nil {
			role = *group.NidRole
		}
		return nil, newCaErr(ErrCaParentNotGroup, "NID '%s' is not registered as a group (role='%s').", groupNid, role)
	}
	if group.RevokedAt != nil {
		return nil, newCaErr(ErrCaGroupRevoked, "Group %s was revoked at %s; cannot issue new sessions.", groupNid, isoTime(*group.RevokedAt))
	}
	if time.Now().UTC().After(group.ExpiresAt) {
		return nil, newCaErr(ErrCertExpired, "Group %s expired at %s; cannot issue new sessions.", groupNid, isoTime(group.ExpiresAt))
	}

	v := p.Validity
	if v == 0 {
		v = s.opts.SessionDefaultValidity
	}
	if v < s.opts.SessionMinValidity || v > s.opts.SessionMaxValidity {
		return nil, newCaErr(ErrCaSessionValidityInvalid,
			"Session validity must be in [%s, %s]; got %s.", s.opts.SessionMinValidity, s.opts.SessionMaxValidity, v)
	}

	sessionCaps := p.Capabilities
	if p.Capabilities != nil {
		groupSet := map[string]bool{}
		for _, c := range group.Capabilities {
			groupSet[c] = true
		}
		var expansion []string
		for _, c := range p.Capabilities {
			if !groupSet[c] {
				expansion = append(expansion, c)
			}
		}
		if len(expansion) > 0 {
			return nil, newCaErr(ErrCaScopeExpansionDenied,
				"Session capabilities not in parent group: %s.", strings.Join(expansion, ", "))
		}
	} else {
		sessionCaps = group.Capabilities
	}
	sessionScopeJSON := p.ScopeJSON
	if sessionScopeJSON == "" {
		sessionScopeJSON = group.ScopeJson
	}

	unixSeconds := time.Now().UTC().Unix()
	sessionID := fmt.Sprintf("session-%d-%s", unixSeconds, randHexN(8))
	sessionNid := s.BuildNid("agent", sessionID)

	now := time.Now().UTC()
	expiresAt := now.Add(v)
	serial, err := s.store.NextSerial()
	if err != nil {
		return nil, err
	}

	lineage := lineageMap(map[string]string{
		"role":          IdentLineageRoleSession,
		"parent_nid":    groupNid,
		"group_nid":     groupNid,
		"session_id":    sessionID,
		"purpose":       p.Purpose,
		"owner_user_id": extractLineageString(group.LineageJson, "owner_user_id"),
		"owner_key_id":  extractLineageString(group.LineageJson, "owner_key_id"),
	})
	lineageJSON, _ := json.Marshal(lineage)

	frame, err := s.issueFrame(sessionNid, sessionPubKey, sessionCaps, sessionScopeJSON, now, expiresAt, serial, p.MetadataJSON, nil, lineage)
	if err != nil {
		return nil, err
	}
	rec := &NipCertRecord{
		Nid: sessionNid, EntityType: "agent", Serial: serial, PubKey: sessionPubKey,
		Capabilities: sessionCaps, ScopeJson: sessionScopeJSON, IssuedBy: s.opts.CaNid,
		IssuedAt: now, ExpiresAt: expiresAt, MetadataJson: nilStr(p.MetadataJSON),
		NidRole: strPtr(IdentLineageRoleSession), ParentNid: strPtr(groupNid), LineageJson: strPtr(string(lineageJSON)),
	}
	if err := s.store.Save(rec); err != nil {
		return nil, err
	}
	return frame, nil
}

// ListSessions returns every session NID issued under groupNid (live + revoked).
func (s *NipCaService) ListSessions(groupNid string) ([]*NipCertRecord, error) {
	return s.store.GetByParentNid(groupNid)
}

// GetCert returns the persisted record for nid, or nil.
func (s *NipCaService) GetCert(nid string) (*NipCertRecord, error) { return s.store.GetByNid(nid) }

// Renew renews a certificate within the renewal window.
func (s *NipCaService) Renew(nid string) (*IdentFrame, error) {
	rec, _ := s.store.GetByNid(nid)
	if rec == nil {
		return nil, newCaErr(ErrCaNidNotFound, "NID not found: %s", nid)
	}
	if rec.RevokedAt != nil {
		return nil, newCaErr(ErrCertRevoked, "NID is revoked: %s", nid)
	}
	now := time.Now().UTC()
	windowStart := rec.ExpiresAt.AddDate(0, 0, -s.opts.RenewalWindowDays)
	if now.Before(windowStart) {
		return nil, newCaErr(ErrCaRenewalTooEarly, "Renewal window opens %s. Too early to renew.", isoTime(windowStart))
	}

	validDays := s.opts.AgentCertValidityDays
	if rec.EntityType == "node" {
		validDays = s.opts.NodeCertValidityDays
	}
	expiresAt := now.AddDate(0, 0, validDays)
	serial, err := s.store.NextSerial()
	if err != nil {
		return nil, err
	}
	frame, err := s.issueFrame(nid, rec.PubKey, rec.Capabilities, rec.ScopeJson, now, expiresAt, serial, ptrStr(rec.MetadataJson), nil, nil)
	if err != nil {
		return nil, err
	}
	newRec := &NipCertRecord{
		Nid: nid, EntityType: rec.EntityType, Serial: serial, PubKey: rec.PubKey,
		Capabilities: rec.Capabilities, ScopeJson: rec.ScopeJson, IssuedBy: s.opts.CaNid,
		IssuedAt: now, ExpiresAt: expiresAt, MetadataJson: rec.MetadataJson,
	}
	if err := s.store.Save(newRec); err != nil {
		return nil, err
	}
	return frame, nil
}

// Revoke revokes a certificate. When the target is a group, live sessions
// under it are cascade-revoked with reason "parent_revoked".
func (s *NipCaService) Revoke(nid, reason string) (*RevokeFrame, error) {
	rec, _ := s.store.GetByNid(nid)
	if rec == nil {
		return nil, newCaErr(ErrCaNidNotFound, "NID not found: %s", nid)
	}
	now := time.Now().UTC()
	revoked, err := s.store.Revoke(nid, reason, now)
	if err != nil {
		return nil, err
	}
	if !revoked {
		return nil, newCaErr(ErrCaNidNotFound, "Failed to revoke %s.", nid)
	}

	if rec.NidRole != nil && *rec.NidRole == IdentLineageRoleGroup {
		children, _ := s.store.GetByParentNid(nid)
		for _, child := range children {
			if child.RevokedAt != nil {
				continue
			}
			_, _ = s.store.Revoke(child.Nid, "parent_revoked", now)
		}
	}

	payload := core.FrameDict{
		"frame":      "0x22",
		"target_nid": nid,
		"serial":     rec.Serial,
		"reason":     reason,
		"revoked_at": isoTime(now),
		"signer_nid": s.opts.CaNid,
	}
	sig := s.keys.Sign(payload)
	serial := rec.Serial
	return &RevokeFrame{
		TargetNID: nid,
		Serial:    &serial,
		Reason:    reason,
		RevokedAt: isoTime(now),
		SignerNID: s.opts.CaNid,
		Signature: sig,
	}, nil
}

// Verify checks existence, expiry, revocation, and (for sessions) the parent
// chain (NPS-3 §7 step 3a).
func (s *NipCaService) Verify(nid string) NipVerifyResult {
	rec, _ := s.store.GetByNid(nid)
	if rec == nil {
		return verifyFail(ErrCaNidNotFound, "NID not found.")
	}
	if rec.RevokedAt != nil {
		return verifyFail(ErrCertRevoked, fmt.Sprintf("Revoked at %s: %s", isoTime(*rec.RevokedAt), ptrStr(rec.RevokeReason)))
	}
	if time.Now().UTC().After(rec.ExpiresAt) {
		return verifyFail(ErrCertExpired, fmt.Sprintf("Expired at %s.", isoTime(rec.ExpiresAt)))
	}
	if rec.ParentNid != nil && *rec.ParentNid != "" {
		parent, _ := s.store.GetByNid(*rec.ParentNid)
		if parent == nil {
			return verifyFail(ErrCertParentRevoked, fmt.Sprintf("Parent NID %s not found.", *rec.ParentNid))
		}
		if parent.RevokedAt != nil {
			return verifyFail(ErrCertParentRevoked, fmt.Sprintf("Parent %s revoked at %s: %s", *rec.ParentNid, isoTime(*parent.RevokedAt), ptrStr(parent.RevokeReason)))
		}
		if time.Now().UTC().After(parent.ExpiresAt) {
			return verifyFail(ErrCertParentRevoked, fmt.Sprintf("Parent %s expired at %s.", *rec.ParentNid, isoTime(parent.ExpiresAt)))
		}
	}
	return verifyOk(rec)
}

// GetCrl returns the current Certificate Revocation List (NPS-3 §8).
func (s *NipCaService) GetCrl() ([]*NipCertRecord, error) { return s.store.GetRevoked() }

// ListCertificates returns all records from the store.
func (s *NipCaService) ListCertificates() ([]*NipCertRecord, error) { return s.store.List() }

// ── helpers ──────────────────────────────────────────────────────────────────

func extractEd25519Raw(encoded string) ([]byte, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(encoded, prefix) {
		return nil, newCaErr(ErrCertFormatInvalid, "X.509 issuance requires an ed25519:* pubkey; got '%s'.", encoded)
	}
	raw, err := decodeBase64Url(encoded[len(prefix):])
	if err != nil {
		return nil, newCaErr(ErrCertFormatInvalid, "invalid ed25519 pubkey base64url: %v", err)
	}
	if len(raw) != 32 {
		return nil, newCaErr(ErrCertFormatInvalid, "Ed25519 pubkey must be 32 bytes; got %d.", len(raw))
	}
	return raw, nil
}

func parseSerialBytes(serial string) *big.Int {
	hexStr := serial
	if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
		hexStr = hexStr[2:]
	}
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) == 0 {
		b = []byte{0x01}
	}
	return new(big.Int).SetBytes(b)
}

// lineageMap builds a lineage object dropping empty-valued fields, matching the
// .NET snake_case omit-null canonical form.
func lineageMap(fields map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range fields {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

func extractLineageString(lineageJSON *string, field string) string {
	if lineageJSON == nil || *lineageJSON == "" {
		return ""
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(*lineageJSON), &doc); err != nil {
		return ""
	}
	if v, ok := doc[field].(string); ok {
		return v
	}
	return ""
}

func randHexN(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func strPtr(s string) *string { return &s }
func nilStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
