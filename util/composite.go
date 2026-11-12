/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/pkg/errors"
)

// AlgoComposite pede um certificado Composite ML-DSA. O tamanho é o nível ML-DSA: 44, 65 ou 87.
const AlgoComposite = "composite"

var (
	oidSubjectKeyID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
)

func IsCompositeKeyRequest(kr *csr.KeyRequest) bool {
	return kr != nil && kr.Algo() == AlgoComposite
}

func compositeKeyGenOpts(kr *csr.KeyRequest, ephemeral bool) (bccsp.KeyGenOpts, error) {
	level, err := MLDSALevel(kr.Size())
	if err != nil {
		return nil, err
	}
	alg, err := composite.AlgorithmForLevel(level)
	if err != nil {
		return nil, err
	}
	log.Debugf("Composite: key request size %d -> %s", kr.Size(), alg.Label)
	return &bccsp.CompositeKeyGenOpts{OID: alg.OID, Temporary: ephemeral}, nil
}

type authorityKeyIdentifier struct {
	ID []byte `asn1:"optional,tag:0"`
}

// RewriteAsCompositeCertificate is RewriteAsExternalCertificate restricted to a Composite ML-DSA
// issuer. A nil subject keeps the SPKI of the draft.
func RewriteAsCompositeCertificate(draftPEM []byte, subject *composite.PublicKey, issuer crypto.Signer, authorityKeyID []byte) ([]byte, error) {
	if _, ok := issuer.Public().(*composite.PublicKey); !ok {
		return nil, errors.Errorf("Composite certificate issuer must have a Composite ML-DSA key, got %T", issuer.Public())
	}
	var subjectPub crypto.PublicKey
	if subject != nil {
		subjectPub = subject
	}
	return RewriteAsExternalCertificate(draftPEM, subjectPub, issuer, authorityKeyID)
}

// RewriteAsCompositeCRL is RewriteAsExternalCRL restricted to a Composite ML-DSA issuer.
func RewriteAsCompositeCRL(draftDER []byte, issuer crypto.Signer) ([]byte, error) {
	if _, ok := issuer.Public().(*composite.PublicKey); !ok {
		return nil, errors.Errorf("Composite CRL issuer must have a Composite ML-DSA key, got %T", issuer.Public())
	}
	return RewriteAsExternalCRL(draftDER, issuer)
}

// GetCompositePrivateKey lê uma chave privada composite em PEM PKCS#8.
func GetCompositePrivateKey(raw []byte) (*composite.PrivateKey, error) {
	decoded, _ := pem.Decode(raw)
	if decoded == nil {
		return nil, errors.New("Failed to decode the PEM-encoded Composite ML-DSA key")
	}
	key, err := composite.ParsePKCS8PrivateKey(decoded.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed parsing Composite ML-DSA private key")
	}
	return key, nil
}

// Estruturas do PKCS #10 (RFC 2986).
type certificationRequest struct {
	Info               asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

type certificationRequestInfo struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes asn1.RawValue
}

var oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

// ParseCompositeCertificateRequest is ParseExternalCertificateRequest restricted to a Composite
// ML-DSA key. A well-formed CSR with any other key fails with composite.ErrNotComposite.
func ParseCompositeCertificateRequest(der []byte) (*x509.CertificateRequest, *composite.PublicKey, error) {
	if req, err := x509.ParseCertificateRequest(der); err == nil && !composite.IsPKIXPublicKey(req.RawSubjectPublicKeyInfo) {
		return nil, nil, composite.ErrNotComposite
	}
	req, pub, err := ParseExternalCertificateRequest(der)
	if err != nil {
		return nil, nil, err
	}
	compositePub, ok := pub.(*composite.PublicKey)
	if !ok {
		return nil, nil, errors.Errorf("The CSR key is %T, not a Composite ML-DSA key", pub)
	}
	return req, compositePub, nil
}

// CompositeDraftRequest is ExternalDraftRequest restricted to a Composite ML-DSA CSR. A CSR of any
// other external algorithm is refused; a classical CSR comes back unchanged with a nil key.
func CompositeDraftRequest(csrPEM []byte, throwaway *ecdsa.PrivateKey) (*composite.PublicKey, []byte, error) {
	pub, draft, err := ExternalDraftRequest(csrPEM, throwaway)
	if err != nil || pub == nil {
		return nil, draft, err
	}
	compositePub, ok := pub.(*composite.PublicKey)
	if !ok {
		return nil, nil, errors.Errorf("The CSR key is %T, not a Composite ML-DSA key", pub)
	}
	return compositePub, draft, nil
}

// replaceCSRPublicKey troca o SPKI de um CertificationRequestInfo e mantém os outros campos byte a byte.
func replaceCSRPublicKey(infoDER, spki []byte) ([]byte, error) {
	var info certificationRequestInfo
	rest, err := asn1.Unmarshal(infoDER, &info)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to parse the CertificationRequestInfo")
	}
	if len(rest) != 0 {
		return nil, errors.New("Trailing data after the CertificationRequestInfo")
	}
	if info.Version != 0 {
		return nil, errors.Errorf("Unsupported CSR version %d", info.Version)
	}
	info.PublicKey = asn1.RawValue{FullBytes: spki}
	return asn1.Marshal(info)
}

func assembleCSR(info, algID, signature []byte) ([]byte, error) {
	return asn1.Marshal(certificationRequest{
		Info:               asn1.RawValue{FullBytes: info},
		SignatureAlgorithm: asn1.RawValue{FullBytes: algID},
		Signature:          asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
}
