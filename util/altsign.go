/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

// Issuance and verification of the ITU-T X.509 (2019) alternative signature, clause 9.8.
//
// The alternative signature is not computed over the tbsCertificate but over a
// PreTBSCertificate: the same structure without the signature field and without the
// altSignatureValue extension. Both omissions are part of the definition -- the verifier
// rebuilds the PreTBSCertificate from the issued certificate, and anything else produces a
// signature it cannot reproduce.
//
// Issuance happens after the certificate has already been signed conventionally, because the
// serial number, validity and extensions are only settled once cfssl has built the
// tbsCertificate. The certificate is taken apart, the two extensions are added, and the
// conventional signature is recomputed over the result. The first signature is discarded: it
// covers a tbsCertificate that no longer exists.

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
)

// AddAlternativeSignature rewrites an already issued certificate so that it carries the
// altSignatureAlgorithm and altSignatureValue extensions, and returns the new PEM.
//
// altSigner is the issuer's ML-DSA key and classicalSigner the issuer's conventional key, the
// one that signed certPEM in the first place. Both belong to the issuer, never to the subject:
// the alternative signature is an issuer statement, in parallel with the conventional one.
func AddAlternativeSignature(certPEM []byte, altSigner crypto.Signer, classicalSigner crypto.Signer) ([]byte, error) {
	if altSigner == nil || classicalSigner == nil {
		return nil, errors.New("Alternative signature requires both the issuer's ML-DSA and conventional signers")
	}
	altPub, ok := altSigner.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("Issuer's alternative key is not an ML-DSA key, got %T", altSigner.Public())
	}
	level, err := MLDSALevelForKey(altPub)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("Failed to decode the issued certificate: not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to parse the issued certificate")
	}
	hash, err := hashForSignatureAlgorithm(cert.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	tbs, err := ParseTBSCertificate(cert.RawTBSCertificate)
	if err != nil {
		return nil, err
	}
	algorithmExt, err := MarshalAltSignatureAlgorithmExtension(level)
	if err != nil {
		return nil, err
	}
	tbs.SetExtension(algorithmExt)
	tbs.RemoveExtension(OIDAltSignatureValue)

	preTBS, err := tbs.MarshalPreTBS(OIDAltSignatureValue)
	if err != nil {
		return nil, err
	}
	altSignature, err := altSigner.Sign(rand.Reader, preTBS, crypto.Hash(0))
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to compute the alternative signature")
	}
	valueExt, err := MarshalAltSignatureValueExtension(altSignature)
	if err != nil {
		return nil, err
	}
	tbs.SetExtension(valueExt)

	tbsDER, err := tbs.Marshal()
	if err != nil {
		return nil, err
	}
	digest := hash.New()
	digest.Write(tbsDER)
	signature, err := classicalSigner.Sign(rand.Reader, digest.Sum(nil), hash)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to re-sign the certificate")
	}
	der, err := AssembleCertificate(tbsDER, tbs.SignatureAlgorithm, signature)
	if err != nil {
		return nil, err
	}

	log.Debugf("ML-DSA: certificate '%s' signed with an ML-DSA-%d alternative signature of %d bytes",
		cert.Subject.CommonName, level, len(altSignature))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// HasAlternativeSignature reports whether a certificate carries an alternative signature.
func HasAlternativeSignature(cert *x509.Certificate) bool {
	_, found := findExtension(cert.Extensions, OIDAltSignatureValue)
	return found
}

// VerifyAlternativeSignature checks the certificate's alternative signature against the issuer's
// ML-DSA public key, the one the issuer's certificate carries in its altSubjectPublicKeyInfo
// extension.
//
// It fails when either extension is missing: a caller that treats an absent alternative
// signature as valid gets no post-quantum protection at all, so the decision of what to do with
// a certificate that has none belongs to the caller, above this function.
func VerifyAlternativeSignature(cert *x509.Certificate, issuerAltPub *mldsa.PublicKey) error {
	if cert == nil {
		return errors.New("Certificate is nil")
	}
	if issuerAltPub == nil {
		return errors.New("Issuer's alternative public key is nil")
	}
	issuerLevel, err := MLDSALevelForKey(issuerAltPub)
	if err != nil {
		return err
	}

	level, found, err := ParseAltSignatureAlgorithmExtension(cert.Extensions)
	if err != nil {
		return err
	}
	if !found {
		return errors.Errorf("Certificate carries no %s extension", OIDAltSignatureAlgorithm)
	}
	if level != issuerLevel {
		return errors.Errorf("Certificate announces ML-DSA-%d but the issuer's alternative key is ML-DSA-%d",
			level, issuerLevel)
	}

	signature, found, err := ParseAltSignatureValueExtension(cert.Extensions)
	if err != nil {
		return err
	}
	if !found {
		return errors.Errorf("Certificate carries no %s extension", OIDAltSignatureValue)
	}

	preTBS, err := PreTBSCertificate(cert)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(issuerAltPub, preTBS, signature, nil); err != nil {
		return errors.WithMessage(err, "Alternative signature verification failed")
	}
	log.Debugf("ML-DSA: alternative signature of '%s' verified against an ML-DSA-%d issuer key",
		cert.Subject.CommonName, issuerLevel)
	return nil
}

// PreTBSCertificate rebuilds the structure the alternative signature was computed over.
func PreTBSCertificate(cert *x509.Certificate) ([]byte, error) {
	tbs, err := ParseTBSCertificate(cert.RawTBSCertificate)
	if err != nil {
		return nil, err
	}
	return tbs.MarshalPreTBS(OIDAltSignatureValue)
}

func hashForSignatureAlgorithm(algorithm x509.SignatureAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case x509.ECDSAWithSHA256, x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		return crypto.SHA256, nil
	case x509.ECDSAWithSHA384, x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		return crypto.SHA384, nil
	case x509.ECDSAWithSHA512, x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return crypto.SHA512, nil
	default:
		return 0, errors.Errorf("Cannot re-sign a certificate signed with '%s'", algorithm)
	}
}
