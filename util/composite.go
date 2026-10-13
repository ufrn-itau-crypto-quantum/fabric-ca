/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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

// RewriteAsCompositeCertificate transforma o rascunho que o cfssl emitiu com uma chave descartável
// no certificado composite. Troca o SPKI, o algoritmo de assinatura e os identificadores de chave,
// e assina o TBS inteiro com issuer. authorityKeyID substitui o AuthorityKeyId do rascunho, quando existe.
// Com subject nil, o SPKI e o SubjectKeyId do rascunho não mudam.
func RewriteAsCompositeCertificate(draftPEM []byte, subject *composite.PublicKey, issuer crypto.Signer, authorityKeyID []byte) ([]byte, error) {
	issuerPub, ok := issuer.Public().(*composite.PublicKey)
	if !ok {
		return nil, errors.Errorf("Composite certificate issuer must have a Composite ML-DSA key, got %T", issuer.Public())
	}
	block, _ := pem.Decode(draftPEM)
	if block == nil {
		return nil, errors.New("Failed to decode the draft certificate: not valid PEM")
	}
	draft, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to parse the draft certificate")
	}
	tbs, err := ParseTBSCertificate(draft.RawTBSCertificate)
	if err != nil {
		return nil, err
	}

	algID, err := composite.AlgorithmIdentifier(issuerPub.Algorithm)
	if err != nil {
		return nil, err
	}
	tbs.SignatureAlgorithm = algID

	if subject != nil {
		if tbs.SubjectPublicKeyInfo, err = composite.MarshalPKIXPublicKey(subject); err != nil {
			return nil, err
		}
		skid, err := composite.SubjectKeyID(subject)
		if err != nil {
			return nil, err
		}
		skidValue, err := asn1.Marshal(skid)
		if err != nil {
			return nil, err
		}
		tbs.SetExtension(pkix.Extension{Id: oidSubjectKeyID, Value: skidValue})
	}
	if _, found := tbs.Extension(oidAuthorityKeyID); found {
		if len(authorityKeyID) == 0 {
			return nil, errors.New("The draft certificate has an AuthorityKeyId but none was given for the composite issuer")
		}
		akidValue, err := asn1.Marshal(authorityKeyIdentifier{ID: authorityKeyID})
		if err != nil {
			return nil, err
		}
		tbs.SetExtension(pkix.Extension{Id: oidAuthorityKeyID, Value: akidValue})
	}

	tbsDER, err := tbs.Marshal()
	if err != nil {
		return nil, err
	}
	// Certificados usam ctx vazio.
	signature, err := issuer.Sign(rand.Reader, tbsDER, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to sign the composite certificate")
	}
	der, err := AssembleCertificate(tbsDER, algID, signature)
	if err != nil {
		return nil, err
	}
	log.Debugf("Composite: certificate '%s' signed with %s (%d bytes)", draft.Subject.CommonName, issuerPub.Algorithm.Label, len(der))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// RewriteAsCompositeCRL transforma a CRL DER que o cfssl gerou com uma chave descartável na CRL
// composite. Troca o algoritmo de assinatura do TBSCertList e assina o TBSCertList inteiro com issuer.
func RewriteAsCompositeCRL(draftDER []byte, issuer crypto.Signer) ([]byte, error) {
	issuerPub, ok := issuer.Public().(*composite.PublicKey)
	if !ok {
		return nil, errors.Errorf("Composite CRL issuer must have a Composite ML-DSA key, got %T", issuer.Public())
	}
	var outer struct {
		TBS                asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		Signature          asn1.BitString
	}
	if _, err := asn1.Unmarshal(draftDER, &outer); err != nil {
		return nil, errors.WithMessage(err, "Failed to parse the draft CRL")
	}
	var fields []asn1.RawValue
	for rest := outer.TBS.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			return nil, errors.WithMessage(err, "Failed to parse the draft TBSCertList")
		}
		fields = append(fields, field)
	}
	// O version é opcional e vem antes do signature.
	i := 0
	if len(fields) > 0 && fields[0].Class == asn1.ClassUniversal && fields[0].Tag == asn1.TagInteger {
		i = 1
	}
	if len(fields) <= i {
		return nil, errors.New("The draft TBSCertList has no signature field")
	}
	algID, err := composite.AlgorithmIdentifier(issuerPub.Algorithm)
	if err != nil {
		return nil, err
	}
	var content []byte
	for j, field := range fields {
		if j == i {
			content = append(content, algID...)
			continue
		}
		content = append(content, field.FullBytes...)
	}
	tbs, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	if err != nil {
		return nil, err
	}
	// CRLs usam ctx vazio.
	signature, err := issuer.Sign(rand.Reader, tbs, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to sign the composite CRL")
	}
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.SignatureAlgorithm = asn1.RawValue{FullBytes: algID}
	outer.Signature = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	return asn1.Marshal(outer)
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

// compositeCSRDER monta um CSR com uma chave descartável e troca o SPKI pela chave composite.
func compositeCSRDER(priv crypto.Signer, pub *composite.PublicKey, req *csr.CertificateRequest) ([]byte, error) {
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to generate the throwaway key for the draft CSR")
	}
	draftDER, err := generateCSRDER(throwaway, req)
	if err != nil {
		return nil, err
	}
	draft, err := x509.ParseCertificateRequest(draftDER)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to parse the draft CSR")
	}
	spki, err := composite.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	info, err := replaceCSRPublicKey(draft.RawTBSCertificateRequest, spki)
	if err != nil {
		return nil, err
	}
	algID, err := composite.AlgorithmIdentifier(pub.Algorithm)
	if err != nil {
		return nil, err
	}
	// CSRs usam ctx vazio.
	signature, err := priv.Sign(rand.Reader, info, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to sign the composite CSR")
	}
	log.Debugf("Composite: CSR signed with %s", pub.Algorithm.Label)
	return assembleCSR(info, algID, signature)
}

// ParseCompositeCertificateRequest lê um CSR composite e verifica a assinatura com a chave do próprio CSR.
func ParseCompositeCertificateRequest(der []byte) (*x509.CertificateRequest, *composite.PublicKey, error) {
	var outer certificationRequest
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to parse the composite CSR")
	}
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to parse the composite CSR")
	}
	pub, err := composite.ParsePKIXPublicKey(req.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, nil, err
	}
	algID, err := composite.AlgorithmIdentifier(pub.Algorithm)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(outer.SignatureAlgorithm.FullBytes, algID) {
		return nil, nil, errors.Errorf("The CSR key is %s but the CSR signature algorithm is different", pub.Algorithm.Label)
	}
	if outer.Signature.BitLength%8 != 0 {
		return nil, nil, errors.New("The composite CSR signature is not a whole number of bytes")
	}
	if err := composite.Verify(pub, req.RawTBSCertificateRequest, outer.Signature.Bytes, nil); err != nil {
		return nil, nil, errors.WithMessage(err, "The composite CSR signature is not valid")
	}
	return req, pub, nil
}

// CompositeDraftRequest prepara o CSR que o cfssl recebe numa CA composite. Para um CSR composite,
// verifica a assinatura e devolve a chave do subject e um rascunho igual ao CSR, mas com a chave
// descartável no SPKI e assinado por ela. Um CSR de outro algoritmo volta sem mudança e com chave nil.
func CompositeDraftRequest(csrPEM []byte, throwaway *ecdsa.PrivateKey) (*composite.PublicKey, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, errors.New("Failed to decode the CSR: not valid PEM")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to parse the CSR")
	}
	if !composite.IsPKIXPublicKey(req.RawSubjectPublicKeyInfo) {
		return nil, csrPEM, nil
	}
	req, pub, err := ParseCompositeCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	spki, err := x509.MarshalPKIXPublicKey(&throwaway.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	info, err := replaceCSRPublicKey(req.RawTBSCertificateRequest, spki)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(info)
	signature, err := ecdsa.SignASN1(rand.Reader, throwaway, digest[:])
	if err != nil {
		return nil, nil, err
	}
	algID, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256})
	if err != nil {
		return nil, nil, err
	}
	der, err := assembleCSR(info, algID, signature)
	if err != nil {
		return nil, nil, err
	}
	return pub, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
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
