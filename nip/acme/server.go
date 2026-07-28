// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package acme

import (
	"crypto/ed25519"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	npsnip "github.com/labacacia/NPS-sdk-go/nip"
	npsx509 "github.com/labacacia/NPS-sdk-go/nip/x509"
)

// ServerOptions — bootstrap options for an in-process AcmeServer.
type ServerOptions struct {
	CaNid        string
	CaKey        ed25519.PrivateKey
	CaRootCert   *cryptox509.Certificate
	CertValidity time.Duration
}

type orderState struct {
	id, authzId, finalizeUrl, accountUrl string
	identifier                           Identifier
	status                               string
	certificateUrl                       string
}

type authzState struct {
	id           string
	identifier   Identifier
	status       string
	challengeIds []string
	accountUrl   string
}

type challengeState struct {
	id, typ, status, token, authzId, accountUrl string
}

// Server — in-process ACME server suitable for tests.
type Server struct {
	opts    ServerOptions
	mu      sync.Mutex
	listen  net.Listener
	httpSrv *http.Server
	baseURL string

	nonces      map[string]struct{}
	accountJwks map[string]*JWK // accountUrl → jwk
	orders      map[string]*orderState
	authzs      map[string]*authzState
	challenges  map[string]*challengeState
	certs       map[string]string
}

// NewServer constructs an unstarted server. Call Start to bind a port.
func NewServer(opts ServerOptions) *Server {
	return &Server{
		opts:        opts,
		nonces:      make(map[string]struct{}),
		accountJwks: make(map[string]*JWK),
		orders:      make(map[string]*orderState),
		authzs:      make(map[string]*authzState),
		challenges:  make(map[string]*challengeState),
		certs:       make(map[string]string),
	}
}

// Start binds 127.0.0.1:0 (random port) and starts serving in a goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.listen = ln
	s.baseURL = fmt.Sprintf("http://%s", ln.Addr().String())

	mux := http.NewServeMux()
	mux.HandleFunc("/directory", s.handleDirectory)
	mux.HandleFunc("/new-nonce", s.handleNewNonce)
	mux.HandleFunc("/new-account", s.handleNewAccount)
	mux.HandleFunc("/new-order", s.handleNewOrder)
	mux.HandleFunc("/authz/", s.handleAuthz)
	mux.HandleFunc("/chall/", s.handleChallenge)
	mux.HandleFunc("/finalize/", s.handleFinalize)
	mux.HandleFunc("/cert/", s.handleCert)
	mux.HandleFunc("/order/", s.handleOrder)

	s.httpSrv = &http.Server{Handler: mux}
	go func() { _ = s.httpSrv.Serve(ln) }()
	return nil
}

// Close stops the server.
func (s *Server) Close() error {
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

func (s *Server) BaseURL() string      { return s.baseURL }
func (s *Server) DirectoryURL() string { return s.baseURL + "/directory" }

// ── Handlers ───────────────────────────────────────────────────────────────

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.problem(w, 405, "urn:ietf:params:acme:error:malformed", "method not allowed")
		return
	}
	s.json(w, 200, Directory{
		NewNonce:   s.baseURL + "/new-nonce",
		NewAccount: s.baseURL + "/new-account",
		NewOrder:   s.baseURL + "/new-order",
	})
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", s.mintNonce())
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(200)
	} else {
		w.WriteHeader(204)
	}
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	env, header, ok := s.readJoseRequest(w, r)
	if !ok {
		return
	}
	if header.JWK == nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed", "newAccount must include a 'jwk' member")
		return
	}
	if !s.consumeNonce(header.Nonce) {
		s.problem(w, 400, "urn:ietf:params:acme:error:badNonce", "invalid nonce")
		return
	}
	pub, err := PublicKeyFromJWK(header.JWK)
	if err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed", err.Error())
		return
	}
	if _, err := Verify(env, pub); err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed", "JWS signature verify failed")
		return
	}
	accountId := "acc-" + shortId()
	accountUrl := s.baseURL + "/account/" + accountId
	s.mu.Lock()
	s.accountJwks[accountUrl] = header.JWK
	s.mu.Unlock()
	w.Header().Set("Location", accountUrl)
	w.Header().Set("Replay-Nonce", s.mintNonce())
	s.json(w, 201, map[string]string{"status": StatusValid})
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	env, header, ok := s.readJoseRequest(w, r)
	if !ok {
		return
	}
	if !s.consumeNonce(header.Nonce) {
		s.problem(w, 400, "urn:ietf:params:acme:error:badNonce", "invalid nonce")
		return
	}
	if !s.verifyAccount(env, header) {
		s.problem(w, 401, "urn:ietf:params:acme:error:accountDoesNotExist",
			fmt.Sprintf("unknown kid: %s", header.Kid))
		return
	}
	var payload NewOrderPayload
	if err := DecodePayload(env, &payload); err != nil || len(payload.Identifiers) == 0 {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed", "missing identifiers")
		return
	}
	ident := payload.Identifiers[0]
	orderId := "ord-" + shortId()
	authzId := "az-" + shortId()
	challId := "ch-" + shortId()
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	token := B64uEncode(tokenBytes)

	orderUrl := s.baseURL + "/order/" + orderId
	authzUrl := s.baseURL + "/authz/" + authzId
	challUrl := s.baseURL + "/chall/" + challId
	finalizeUrl := s.baseURL + "/finalize/" + orderId

	s.mu.Lock()
	s.challenges[challId] = &challengeState{
		id: challId, typ: ChallengeAgent01, status: StatusPending,
		token: token, authzId: authzId, accountUrl: header.Kid,
	}
	s.authzs[authzId] = &authzState{
		id: authzId, identifier: ident, status: StatusPending,
		challengeIds: []string{challId}, accountUrl: header.Kid,
	}
	s.orders[orderId] = &orderState{
		id: orderId, identifier: ident, status: StatusPending,
		authzId: authzId, finalizeUrl: finalizeUrl, accountUrl: header.Kid,
	}
	s.mu.Unlock()

	w.Header().Set("Location", orderUrl)
	w.Header().Set("Replay-Nonce", s.mintNonce())
	s.json(w, 201, Order{
		Status: StatusPending, Identifiers: []Identifier{ident},
		Authorizations: []string{authzUrl}, Finalize: finalizeUrl,
	})
	_ = challUrl
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	env, header, ok := s.readJoseRequest(w, r)
	if !ok {
		return
	}
	if !s.consumeNonce(header.Nonce) {
		s.problem(w, 400, "urn:ietf:params:acme:error:badNonce", "invalid nonce")
		return
	}
	if !s.verifyAccount(env, header) {
		s.problem(w, 401, "urn:ietf:params:acme:error:unauthorized", "bad sig")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	s.mu.Lock()
	az, ok := s.authzs[id]
	s.mu.Unlock()
	if !ok {
		s.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no authz")
		return
	}
	challenges := make([]Challenge, 0, len(az.challengeIds))
	s.mu.Lock()
	for _, cid := range az.challengeIds {
		cs := s.challenges[cid]
		challenges = append(challenges, Challenge{
			Type: cs.typ, URL: s.baseURL + "/chall/" + cs.id,
			Status: cs.status, Token: cs.token,
		})
	}
	s.mu.Unlock()
	w.Header().Set("Replay-Nonce", s.mintNonce())
	s.json(w, 200, Authorization{
		Status: az.status, Identifier: az.identifier, Challenges: challenges,
	})
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	env, header, ok := s.readJoseRequest(w, r)
	if !ok {
		return
	}
	if !s.consumeNonce(header.Nonce) {
		s.problem(w, 400, "urn:ietf:params:acme:error:badNonce", "invalid nonce")
		return
	}
	s.mu.Lock()
	jwk, ok := s.accountJwks[header.Kid]
	s.mu.Unlock()
	if !ok {
		s.problem(w, 401, "urn:ietf:params:acme:error:accountDoesNotExist", "unknown kid")
		return
	}
	accountPub, err := PublicKeyFromJWK(jwk)
	if err != nil {
		s.problem(w, 401, "urn:ietf:params:acme:error:accountDoesNotExist", err.Error())
		return
	}
	if _, err := Verify(env, accountPub); err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed", "JWS sig fail")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/chall/")
	s.mu.Lock()
	ch, ok := s.challenges[id]
	s.mu.Unlock()
	if !ok {
		s.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no chall")
		return
	}
	var payload ChallengeRespondPayload
	if err := DecodePayload(env, &payload); err != nil || payload.AgentSignature == "" {
		s.mu.Lock()
		ch.status = StatusInvalid
		s.mu.Unlock()
		s.problem(w, 400, npsnip.ErrAcmeChallengeFailed,
			"missing agent_signature in challenge response")
		return
	}
	sig, err := B64uDecode(payload.AgentSignature)
	if err != nil {
		s.mu.Lock()
		ch.status = StatusInvalid
		s.mu.Unlock()
		s.problem(w, 400, npsnip.ErrAcmeChallengeFailed,
			fmt.Sprintf("agent-01 verification error: %v", err))
		return
	}
	if !ed25519.Verify(accountPub, []byte(ch.token), sig) {
		s.mu.Lock()
		ch.status = StatusInvalid
		s.mu.Unlock()
		s.problem(w, 400, npsnip.ErrAcmeChallengeFailed,
			"agent-01 signature did not verify")
		return
	}
	s.mu.Lock()
	ch.status = StatusValid
	if az, ok := s.authzs[ch.authzId]; ok {
		az.status = StatusValid
	}
	for _, o := range s.orders {
		if o.authzId == ch.authzId {
			o.status = StatusReady
		}
	}
	s.mu.Unlock()
	w.Header().Set("Replay-Nonce", s.mintNonce())
	s.json(w, 200, Challenge{
		Type: ch.typ, URL: s.baseURL + "/chall/" + ch.id,
		Status: ch.status, Token: ch.token,
	})
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	env, header, ok := s.readJoseRequest(w, r)
	if !ok {
		return
	}
	if !s.consumeNonce(header.Nonce) {
		s.problem(w, 400, "urn:ietf:params:acme:error:badNonce", "invalid nonce")
		return
	}
	if !s.verifyAccount(env, header) {
		s.problem(w, 401, "urn:ietf:params:acme:error:unauthorized", "bad sig")
		return
	}
	orderId := strings.TrimPrefix(r.URL.Path, "/finalize/")
	s.mu.Lock()
	os, ok := s.orders[orderId]
	s.mu.Unlock()
	if !ok {
		s.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no order")
		return
	}
	if os.status != StatusReady {
		s.problem(w, 403, "urn:ietf:params:acme:error:orderNotReady",
			fmt.Sprintf("order is in state %q, not 'ready'", os.status))
		return
	}
	var fp FinalizePayload
	if err := DecodePayload(env, &fp); err != nil || fp.CSR == "" {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed", "missing csr")
		return
	}
	csrDer, err := B64uDecode(fp.CSR)
	if err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:badCSR",
			fmt.Sprintf("CSR base64url: %v", err))
		return
	}
	csr, err := cryptox509.ParseCertificateRequest(csrDer)
	if err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:badCSR",
			fmt.Sprintf("CSR parse: %v", err))
		return
	}
	if subjectCn := csr.Subject.CommonName; subjectCn != os.identifier.Value {
		s.problem(w, 400, npsnip.ErrCertSubjectNidMismatch,
			fmt.Sprintf("CSR subject CN %q does not match order identifier %q", subjectCn, os.identifier.Value))
		return
	}
	subjectPub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		s.problem(w, 400, "urn:ietf:params:acme:error:badCSR", "CSR public key is not Ed25519")
		return
	}
	now := time.Now()
	leaf, err := npsx509.IssueLeaf(npsx509.IssueLeafOptions{
		SubjectNID:       os.identifier.Value,
		SubjectPublicKey: subjectPub,
		CAPrivateKey:     s.opts.CaKey,
		IssuerNID:        s.opts.CaNid,
		Role:             npsx509.LeafRoleAgent,
		AssuranceLevel:   npsnip.AssuranceAnonymous,
		NotBefore:        now.Add(-time.Minute),
		NotAfter:         now.Add(s.opts.CertValidity),
		SerialNumber:     randomSerial(),
	})
	if err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:badCSR",
			fmt.Sprintf("issue leaf: %v", err))
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	pemBytes = append(pemBytes,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.opts.CaRootCert.Raw})...)

	certId := "crt-" + shortId()
	certUrl := s.baseURL + "/cert/" + certId
	s.mu.Lock()
	s.certs[certId] = string(pemBytes)
	os.status = StatusValid
	os.certificateUrl = certUrl
	s.mu.Unlock()

	authzUrl := s.baseURL + "/authz/" + os.authzId
	w.Header().Set("Replay-Nonce", s.mintNonce())
	s.json(w, 200, Order{
		Status: os.status, Identifiers: []Identifier{os.identifier},
		Authorizations: []string{authzUrl}, Finalize: os.finalizeUrl,
		Certificate: os.certificateUrl,
	})
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	env, header, ok := s.readJoseRequest(w, r)
	if !ok {
		return
	}
	if !s.consumeNonce(header.Nonce) {
		s.problem(w, 400, "urn:ietf:params:acme:error:badNonce", "invalid nonce")
		return
	}
	if !s.verifyAccount(env, header) {
		s.problem(w, 401, "urn:ietf:params:acme:error:unauthorized", "bad sig")
		return
	}
	certId := strings.TrimPrefix(r.URL.Path, "/cert/")
	s.mu.Lock()
	pem, ok := s.certs[certId]
	s.mu.Unlock()
	if !ok {
		s.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no cert")
		return
	}
	w.Header().Set("Content-Type", ContentTypePemCert)
	w.Header().Set("Replay-Nonce", s.mintNonce())
	w.WriteHeader(200)
	_, _ = w.Write([]byte(pem))
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	env, header, ok := s.readJoseRequest(w, r)
	if !ok {
		return
	}
	if !s.consumeNonce(header.Nonce) {
		s.problem(w, 400, "urn:ietf:params:acme:error:badNonce", "invalid nonce")
		return
	}
	if !s.verifyAccount(env, header) {
		s.problem(w, 401, "urn:ietf:params:acme:error:unauthorized", "bad sig")
		return
	}
	orderId := strings.TrimPrefix(r.URL.Path, "/order/")
	s.mu.Lock()
	os, ok := s.orders[orderId]
	s.mu.Unlock()
	if !ok {
		s.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no order")
		return
	}
	authzUrl := s.baseURL + "/authz/" + os.authzId
	w.Header().Set("Replay-Nonce", s.mintNonce())
	s.json(w, 200, Order{
		Status: os.status, Identifiers: []Identifier{os.identifier},
		Authorizations: []string{authzUrl}, Finalize: os.finalizeUrl,
		Certificate: os.certificateUrl,
	})
}

// ── Helpers ────────────────────────────────────────────────────────────────

func (s *Server) readJoseRequest(w http.ResponseWriter, r *http.Request) (*Envelope, *ProtectedHeader, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed",
			fmt.Sprintf("body read: %v", err))
		return nil, nil, false
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed",
			fmt.Sprintf("body parse: %v", err))
		return nil, nil, false
	}
	headerBytes, err := B64uDecode(env.Protected)
	if err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed",
			fmt.Sprintf("malformed protected header: %v", err))
		return nil, nil, false
	}
	var header ProtectedHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		s.problem(w, 400, "urn:ietf:params:acme:error:malformed",
			fmt.Sprintf("protected header parse: %v", err))
		return nil, nil, false
	}
	return &env, &header, true
}

func (s *Server) verifyAccount(env *Envelope, header *ProtectedHeader) bool {
	if header.Kid == "" {
		return false
	}
	s.mu.Lock()
	jwk, ok := s.accountJwks[header.Kid]
	s.mu.Unlock()
	if !ok {
		return false
	}
	pub, err := PublicKeyFromJWK(jwk)
	if err != nil {
		return false
	}
	_, err = Verify(env, pub)
	return err == nil
}

func (s *Server) mintNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	n := B64uEncode(b)
	s.mu.Lock()
	s.nonces[n] = struct{}{}
	s.mu.Unlock()
	return n
}

func (s *Server) consumeNonce(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nonces[nonce]; !ok {
		return false
	}
	delete(s.nonces, nonce)
	return true
}

func (s *Server) json(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", ContentTypeProblem)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ProblemDetail{Type: typ, Detail: detail, Status: status})
}

func shortId() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomSerial() *big.Int {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	n := new(big.Int).SetBytes(b)
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n
}
