// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package nip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/labacacia/NPS-sdk-go/core"
)

// NipCaClient is a typed HTTP client for remote NIP CA routes.
type NipCaClient struct {
	baseURL string
	prefix  string
	http    *http.Client
}

func NewNipCaClient(baseURL string) *NipCaClient {
	return NewNipCaClientFull(baseURL, "", nil)
}

func NewNipCaClientFull(baseURL, routePrefix string, httpClient *http.Client) *NipCaClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &NipCaClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		prefix:  strings.TrimRight(routePrefix, "/"),
		http:    httpClient,
	}
}

type NipCaRegisterRequest struct {
	Identifier   string   `json:"identifier"`
	PubKey       string   `json:"pub_key"`
	Capabilities []string `json:"capabilities,omitempty"`
	ScopeJSON    string   `json:"scope_json,omitempty"`
	MetadataJSON string   `json:"metadata_json,omitempty"`
}

type NipCaRegisterX509Request struct {
	NipCaRegisterRequest
	AssuranceLevel string `json:"assurance_level,omitempty"`
}

type NipCaIdentFrame struct {
	Frame        string         `json:"frame,omitempty"`
	NID          string         `json:"nid"`
	PubKey       string         `json:"pub_key"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Scope        map[string]any `json:"scope,omitempty"`
	IssuedBy     string         `json:"issued_by,omitempty"`
	IssuedAt     string         `json:"issued_at,omitempty"`
	ExpiresAt    string         `json:"expires_at,omitempty"`
	Serial       string         `json:"serial,omitempty"`
	Signature    string         `json:"signature,omitempty"`
	CertFormat   string         `json:"cert_format,omitempty"`
	CertChain    []string       `json:"cert_chain,omitempty"`
	OCSPStaple   string         `json:"ocsp_staple,omitempty"`
}

type NipCaCrlEntry struct {
	NID       string `json:"nid"`
	Serial    string `json:"serial"`
	RevokedAt string `json:"revoked_at,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type NipCaCrl struct {
	IssuedBy  string          `json:"issued_by"`
	IssuedAt  string          `json:"issued_at"`
	Entries   []NipCaCrlEntry `json:"entries"`
	Signature string          `json:"signature"`
}

type NipCaCertificateRecord struct {
	NID          string   `json:"nid"`
	EntityType   string   `json:"entity_type"`
	Serial       string   `json:"serial"`
	PubKey       string   `json:"pub_key"`
	Capabilities []string `json:"capabilities"`
	Scope        any      `json:"scope"`
	IssuedBy     string   `json:"issued_by"`
	IssuedAt     string   `json:"issued_at"`
	ExpiresAt    string   `json:"expires_at"`
	RevokedAt    *string  `json:"revoked_at,omitempty"`
	RevokeReason *string  `json:"revoke_reason,omitempty"`
	NidRole      *string  `json:"nid_role,omitempty"`
	ParentNID    *string  `json:"parent_nid,omitempty"`
}

type NipCaCertificateList struct {
	Entries []NipCaCertificateRecord `json:"entries"`
}

type NipCaRevokeFrame struct {
	Frame     string `json:"frame,omitempty"`
	TargetNID string `json:"target_nid,omitempty"`
	NID       string `json:"nid,omitempty"`
	Serial    string `json:"serial,omitempty"`
	Reason    string `json:"reason,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type NipCaDiscoveryDocument struct {
	NpsCa               string         `json:"nps_ca"`
	Issuer              string         `json:"issuer"`
	DisplayName         string         `json:"display_name,omitempty"`
	PublicKey           string         `json:"public_key"`
	Algorithms          []string       `json:"algorithms,omitempty"`
	Endpoints           map[string]any `json:"endpoints,omitempty"`
	Capabilities        []string       `json:"capabilities,omitempty"`
	MaxCertValidityDays int            `json:"max_cert_validity_days,omitempty"`
}

type NipCaVerifyResponse struct {
	Valid     bool   `json:"valid"`
	NID       string `json:"nid,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Serial    string `json:"serial,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
}

type NipCaClientError struct {
	ErrorCode  string
	Message    string
	StatusCode int
}

func (e *NipCaClientError) Error() string { return e.Message }

func (c *NipCaClient) GetDiscovery(ctx context.Context) (*NipCaDiscoveryDocument, error) {
	var out NipCaDiscoveryDocument
	if err := c.getJSON(ctx, "/.well-known/nps-ca", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *NipCaClient) GetCrl(ctx context.Context) (*NipCaCrl, error) {
	var out NipCaCrl
	if err := c.getJSON(ctx, c.prefix+"/v1/crl", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *NipCaClient) GetCertificates(ctx context.Context, bearerToken string) (*NipCaCertificateList, error) {
	var out NipCaCertificateList
	if err := c.sendJSON(ctx, http.MethodGet, c.prefix+"/v1/certificates", nil, bearerToken, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyCrlSignature verifies a signed CRL using the CA public key.
func VerifyCrlSignature(crl *NipCaCrl, caPublicKey string) bool {
	entries := make([]any, 0, len(crl.Entries))
	for _, entry := range crl.Entries {
		item := map[string]any{
			"nid":    entry.NID,
			"serial": entry.Serial,
		}
		if entry.RevokedAt != "" {
			item["revoked_at"] = entry.RevokedAt
		}
		if entry.Reason != "" {
			item["reason"] = entry.Reason
		}
		entries = append(entries, item)
	}
	body := core.FrameDict{
		"issued_by": crl.IssuedBy,
		"issued_at": crl.IssuedAt,
		"entries":   entries,
	}
	return VerifyWithPubKeyStr(body, caPublicKey, crl.Signature)
}

func (c *NipCaClient) RegisterAgent(ctx context.Context, req NipCaRegisterRequest, bearerToken string) (*NipCaIdentFrame, error) {
	return c.sendIdent(ctx, http.MethodPost, c.prefix+"/v1/agents/register", req, bearerToken)
}

func (c *NipCaClient) RegisterNode(ctx context.Context, req NipCaRegisterRequest, bearerToken string) (*NipCaIdentFrame, error) {
	return c.sendIdent(ctx, http.MethodPost, c.prefix+"/v1/nodes/register", req, bearerToken)
}

func (c *NipCaClient) RegisterAgentX509(ctx context.Context, req NipCaRegisterX509Request, bearerToken string) (*NipCaIdentFrame, error) {
	return c.sendIdent(ctx, http.MethodPost, c.prefix+"/v1/agents/register-x509", req, bearerToken)
}

func (c *NipCaClient) RegisterNodeX509(ctx context.Context, req NipCaRegisterX509Request, bearerToken string) (*NipCaIdentFrame, error) {
	return c.sendIdent(ctx, http.MethodPost, c.prefix+"/v1/nodes/register-x509", req, bearerToken)
}

func (c *NipCaClient) RenewAgent(ctx context.Context, nid, bearerToken string) (*NipCaIdentFrame, error) {
	return c.sendIdent(ctx, http.MethodPost, c.prefix+"/v1/agents/"+url.PathEscape(nid)+"/renew", nil, bearerToken)
}

func (c *NipCaClient) RenewNode(ctx context.Context, nid, bearerToken string) (*NipCaIdentFrame, error) {
	return c.sendIdent(ctx, http.MethodPost, c.prefix+"/v1/nodes/"+url.PathEscape(nid)+"/renew", nil, bearerToken)
}

func (c *NipCaClient) RevokeAgent(ctx context.Context, nid, reason, bearerToken string) (*NipCaRevokeFrame, error) {
	if reason == "" {
		reason = "cessation_of_operation"
	}
	var out NipCaRevokeFrame
	err := c.sendJSON(ctx, http.MethodPost, c.prefix+"/v1/agents/"+url.PathEscape(nid)+"/revoke", map[string]string{"reason": reason}, bearerToken, &out)
	return &out, err
}

func (c *NipCaClient) RevokeNode(ctx context.Context, nid, reason, bearerToken string) (*NipCaRevokeFrame, error) {
	if reason == "" {
		reason = "cessation_of_operation"
	}
	var out NipCaRevokeFrame
	err := c.sendJSON(ctx, http.MethodPost, c.prefix+"/v1/nodes/"+url.PathEscape(nid)+"/revoke", map[string]string{"reason": reason}, bearerToken, &out)
	return &out, err
}

func (c *NipCaClient) VerifyAgent(ctx context.Context, nid string) (*NipCaVerifyResponse, error) {
	var out NipCaVerifyResponse
	if err := c.getJSON(ctx, c.prefix+"/v1/agents/"+url.PathEscape(nid)+"/verify", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *NipCaClient) VerifyNode(ctx context.Context, nid string) (*NipCaVerifyResponse, error) {
	var out NipCaVerifyResponse
	if err := c.getJSON(ctx, c.prefix+"/v1/nodes/"+url.PathEscape(nid)+"/verify", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *NipCaClient) sendIdent(ctx context.Context, method, path string, body any, bearerToken string) (*NipCaIdentFrame, error) {
	var out NipCaIdentFrame
	if err := c.sendJSON(ctx, method, path, body, bearerToken, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *NipCaClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return readCaResponse(resp, out)
}

func (c *NipCaClient) sendJSON(ctx context.Context, method, path string, body any, bearerToken string, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return readCaResponse(resp, out)
}

func readCaResponse(resp *http.Response, out any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if len(body) == 0 {
			return &NipCaClientError{ErrorCode: "NIP-CA-EMPTY-RESPONSE", Message: "NIP CA returned an empty response.", StatusCode: resp.StatusCode}
		}
		return json.Unmarshal(body, out)
	}
	var errBody struct {
		ErrorCode string `json:"error_code"`
		Error     string `json:"error"`
		Message   string `json:"message"`
	}
	_ = json.Unmarshal(body, &errBody)
	code := errBody.ErrorCode
	if code == "" {
		code = errBody.Error
	}
	if code == "" {
		code = "NIP-CA-HTTP-ERROR"
	}
	msg := errBody.Message
	if msg == "" {
		msg = fmt.Sprintf("NIP CA returned HTTP %d.", resp.StatusCode)
	}
	return &NipCaClientError{ErrorCode: code, Message: msg, StatusCode: resp.StatusCode}
}
