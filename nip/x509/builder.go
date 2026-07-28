// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
package x509

import (
	"crypto/ed25519"
	"crypto/rand"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/url"
	"time"

	npsnip "github.com/labacacia/NPS-sdk-go/nip"
)

// LeafRole — agent or node identity.
type LeafRole string

const (
	LeafRoleAgent LeafRole = "agent"
	LeafRoleNode  LeafRole = "node"
)

// Standard X.509 OID for the ExtendedKeyUsage extension (id-ce-extKeyUsage).
var oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// IssueLeafOptions — inputs for IssueLeaf (NPS-RFC-0002 §4.1).
type IssueLeafOptions struct {
	SubjectNID       string
	SubjectPublicKey ed25519.PublicKey
	CAPrivateKey     ed25519.PrivateKey
	IssuerNID        string
	Role             LeafRole
	AssuranceLevel   npsnip.AssuranceLevel
	NotBefore        time.Time
	NotAfter         time.Time
	SerialNumber     *big.Int
}

// IssueRootOptions — inputs for IssueRoot.
type IssueRootOptions struct {
	CANID        string
	CAPrivateKey ed25519.PrivateKey
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber *big.Int
}

// IssueLeaf issues a leaf NPS NID certificate per NPS-RFC-0002 §4.1.
func IssueLeaf(opts IssueLeafOptions) (*cryptox509.Certificate, error) {
	if opts.SubjectPublicKey == nil {
		return nil, fmt.Errorf("subject public key is nil")
	}
	if opts.CAPrivateKey == nil {
		return nil, fmt.Errorf("CA private key is nil")
	}

	ekuOid := OidEkuAgentIdentity
	if opts.Role == LeafRoleNode {
		ekuOid = OidEkuNodeIdentity
	}
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{ekuOid})
	if err != nil {
		return nil, fmt.Errorf("marshal EKU: %w", err)
	}

	// ASN.1 ENUMERATED encoding of assurance level: tag=0x0A, len=0x01, value=<rank>.
	assuranceDer := []byte{0x0A, 0x01, byte(opts.AssuranceLevel.Rank)}

	uri, err := url.Parse(opts.SubjectNID)
	if err != nil {
		return nil, fmt.Errorf("subject NID parse: %w", err)
	}

	tmpl := &cryptox509.Certificate{
		SerialNumber:          opts.SerialNumber,
		Subject:               pkix.Name{CommonName: opts.SubjectNID},
		Issuer:                pkix.Name{CommonName: opts.IssuerNID},
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		KeyUsage:              cryptox509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{uri},
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionExtendedKeyUsage, Critical: true, Value: ekuValue},
			{Id: OidNidAssuranceLevel, Critical: false, Value: assuranceDer},
		},
	}

	// Issuer template carries the CN we want; CreateCertificate uses parent.Subject as issuer.
	parent := &cryptox509.Certificate{Subject: pkix.Name{CommonName: opts.IssuerNID}}

	der, err := cryptox509.CreateCertificate(rand.Reader, tmpl, parent,
		opts.SubjectPublicKey, opts.CAPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	return cryptox509.ParseCertificate(der)
}

// IssueRoot issues a self-signed CA root certificate (testing / private CA).
func IssueRoot(opts IssueRootOptions) (*cryptox509.Certificate, error) {
	if opts.CAPrivateKey == nil {
		return nil, fmt.Errorf("CA private key is nil")
	}
	tmpl := &cryptox509.Certificate{
		SerialNumber:          opts.SerialNumber,
		Subject:               pkix.Name{CommonName: opts.CANID},
		Issuer:                pkix.Name{CommonName: opts.CANID},
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	pub := opts.CAPrivateKey.Public().(ed25519.PublicKey)
	der, err := cryptox509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, opts.CAPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}
	return cryptox509.ParseCertificate(der)
}
