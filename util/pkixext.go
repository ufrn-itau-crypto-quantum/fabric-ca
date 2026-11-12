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
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/pkg/errors"
)

// Certificates, CRLs and CSRs of algorithms that crypto/x509 does not know, such as Composite ML-DSA
// and SLH-DSA, are produced in two steps: cfssl or crypto/x509 builds a draft signed by a throwaway
// ECDSA key, and the draft is rewritten with the real key and signature. Every function here
// dispatches on the pkixext registry, so it serves every registered scheme.

// IsExternalKeyRequest reports whether the key request asks for an algorithm outside crypto/x509.
func IsExternalKeyRequest(kr *csr.KeyRequest) bool {
	if kr == nil {
		return false
	}
	if kr.Algo() == AlgoComposite {
		return true
	}
	_, _, err := slhdsaKeyRequest(kr)
	return err == nil
}

func isExternalPublicKey(pub crypto.PublicKey) bool {
	_, ok := pkixext.SchemeForKey(pub)
	return ok
}

func externalAlgorithmName(pub crypto.PublicKey) string {
	s, ok := pkixext.SchemeForKey(pub)
	if !ok {
		return "unknown"
	}
	algID, err := s.AlgorithmIdentifier(pub)
	if err != nil {
		return s.Name()
	}
	var ai pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(algID, &ai); err != nil {
		return s.Name()
	}
	return s.Name() + " " + ai.Algorithm.String()
}

// RewriteAsExternalCertificate turns the draft certificate that cfssl issued with a throwaway key
// into the final one. It replaces the SPKI, the signature algorithm and the key identifiers, and
// signs the whole TBS with issuer.
//
// authorityKeyID replaces the AuthorityKeyId of the draft, when the draft has one. With a nil
// subject the SPKI and the SubjectKeyId of the draft are kept, which is the case of a classical
// subject under an external issuer.
func RewriteAsExternalCertificate(draftPEM []byte, subject crypto.PublicKey, issuer crypto.Signer, authorityKeyID []byte) ([]byte, error) {
	if !isExternalPublicKey(issuer.Public()) {
		return nil, errors.Errorf("Certificate issuer must have a key of a registered external algorithm, got %T", issuer.Public())
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

	algID, err := pkixext.AlgorithmIdentifier(issuer.Public())
	if err != nil {
		return nil, err
	}
	tbs.SignatureAlgorithm = algID

	if subject != nil {
		if tbs.SubjectPublicKeyInfo, err = pkixext.MarshalPKIXPublicKey(subject); err != nil {
			return nil, err
		}
		skid, err := pkixext.SubjectKeyID(subject)
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
			return nil, errors.New("The draft certificate has an AuthorityKeyId but none was given for the issuer")
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
	signature, err := issuer.Sign(rand.Reader, tbsDER, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to sign the certificate")
	}
	der, err := AssembleCertificate(tbsDER, algID, signature)
	if err != nil {
		return nil, err
	}
	log.Debugf("Certificate '%s' signed with %s (%d bytes)", draft.Subject.CommonName, externalAlgorithmName(issuer.Public()), len(der))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// RewriteAsExternalCRL turns the DER CRL that cfssl generated with a throwaway key into the final
// one: it replaces the signature algorithm of the TBSCertList and signs the whole TBSCertList with
// issuer. The optional version comes before the signature field.
func RewriteAsExternalCRL(draftDER []byte, issuer crypto.Signer) ([]byte, error) {
	algID, err := pkixext.AlgorithmIdentifier(issuer.Public())
	if err != nil {
		return nil, errors.WithMessage(err, "CRL issuer must have a key of a registered external algorithm")
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
	i := 0
	if len(fields) > 0 && fields[0].Class == asn1.ClassUniversal && fields[0].Tag == asn1.TagInteger {
		i = 1
	}
	if len(fields) <= i {
		return nil, errors.New("The draft TBSCertList has no signature field")
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
	signature, err := issuer.Sign(rand.Reader, tbs, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to sign the CRL")
	}
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.SignatureAlgorithm = asn1.RawValue{FullBytes: algID}
	outer.Signature = asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)}
	return asn1.Marshal(outer)
}

// GetExternalPrivateKey reads a PEM PKCS#8 private key of a registered external algorithm.
func GetExternalPrivateKey(raw []byte) (crypto.Signer, error) {
	decoded, _ := pem.Decode(raw)
	if decoded == nil {
		return nil, errors.New("Failed to decode the PEM-encoded private key")
	}
	key, err := pkixext.ParsePKCS8PrivateKey(decoded.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed parsing the private key")
	}
	return key, nil
}

// externalCSRDER builds a CSR with a throwaway key and replaces the SPKI with pub, then signs the
// CertificationRequestInfo with priv.
func externalCSRDER(priv crypto.Signer, pub crypto.PublicKey, req *csr.CertificateRequest) ([]byte, error) {
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
	spki, err := pkixext.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	info, err := replaceCSRPublicKey(draft.RawTBSCertificateRequest, spki)
	if err != nil {
		return nil, err
	}
	algID, err := pkixext.AlgorithmIdentifier(pub)
	if err != nil {
		return nil, err
	}
	signature, err := priv.Sign(rand.Reader, info, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to sign the CSR")
	}
	log.Debugf("CSR signed with %s", externalAlgorithmName(pub))
	return assembleCSR(info, algID, signature)
}

// ParseExternalCertificateRequest reads a CSR of a registered external algorithm and verifies its
// signature with the key of the CSR itself. The signature algorithm must be byte-identical to the
// AlgorithmIdentifier of that key.
func ParseExternalCertificateRequest(der []byte) (*x509.CertificateRequest, crypto.PublicKey, error) {
	var outer certificationRequest
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to parse the CSR")
	}
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to parse the CSR")
	}
	s, ok := pkixext.SchemeByOID(spkiAlgorithm(req.RawSubjectPublicKeyInfo))
	if !ok {
		return nil, nil, errors.New("The CSR key is not of a registered external algorithm")
	}
	pub, err := s.ParsePKIXPublicKey(req.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, nil, err
	}
	algID, err := s.AlgorithmIdentifier(pub)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(outer.SignatureAlgorithm.FullBytes, algID) {
		return nil, nil, errors.Errorf("The CSR key is %s but the CSR signature algorithm is different", externalAlgorithmName(pub))
	}
	if outer.Signature.BitLength%8 != 0 {
		return nil, nil, errors.New("The CSR signature is not a whole number of bytes")
	}
	if err := s.Verify(pub, req.RawTBSCertificateRequest, outer.Signature.Bytes); err != nil {
		return nil, nil, errors.WithMessage(err, "The CSR signature is not valid")
	}
	return req, pub, nil
}

func spkiAlgorithm(spki []byte) asn1.ObjectIdentifier {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil
	}
	return info.Algorithm.Algorithm
}

// ExternalDraftRequest prepares the CSR that cfssl receives at a CA with an external key. For a CSR
// of an external algorithm it verifies the signature and returns the subject key and a draft equal
// to the CSR, but with the throwaway key in the SPKI and signed by it. A CSR of any other algorithm
// comes back unchanged with a nil key.
func ExternalDraftRequest(csrPEM []byte, throwaway *ecdsa.PrivateKey) (crypto.PublicKey, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, errors.New("Failed to decode the CSR: not valid PEM")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed to parse the CSR")
	}
	if !pkixext.IsExternalPublicKey(req.RawSubjectPublicKeyInfo) {
		return nil, csrPEM, nil
	}
	req, pub, err := ParseExternalCertificateRequest(block.Bytes)
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
