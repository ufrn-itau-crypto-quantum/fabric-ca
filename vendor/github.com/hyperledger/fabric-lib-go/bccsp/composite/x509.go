/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/pkg/errors"
)

// AlgorithmIdentifier devolve o AlgorithmIdentifier DER do par, sem o campo parameters.
func AlgorithmIdentifier(alg Algorithm) ([]byte, error) {
	return asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: alg.OID})
}

// SubjectKeyID calcula o SHA-1 da chave pública composta bruta, pelo método 1 da RFC 5280 §4.2.1.2.
func SubjectKeyID(pub *PublicKey) ([]byte, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(raw)
	return sum[:], nil
}

type certificateOuter struct {
	TBS                asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

// CheckCertificateSignature confere a assinatura composite de cert com a chave do emissor.
// Recusa o certificado quando o algoritmo externo e o algoritmo do TBS são diferentes.
func CheckCertificateSignature(cert *x509.Certificate, issuer *PublicKey) error {
	if cert == nil || issuer == nil {
		return errors.New("Certificate and issuer public key are required")
	}
	var outer certificateOuter
	rest, err := asn1.Unmarshal(cert.Raw, &outer)
	if err != nil {
		return errors.WithMessage(err, "Failed to decode the certificate")
	}
	if len(rest) != 0 {
		return errors.New("Trailing data after the certificate")
	}
	inner, err := tbsSignatureAlgorithm(outer.TBS.Bytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(inner, outer.SignatureAlgorithm.FullBytes) {
		return errors.New("Certificate signature algorithm differs from the one in the tbsCertificate")
	}

	var ai pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(outer.SignatureAlgorithm.FullBytes, &ai); err != nil {
		return errors.WithMessage(err, "Failed to decode the certificate signature algorithm")
	}
	alg, err := algorithmFromIdentifier(ai)
	if err != nil {
		return err
	}
	if !alg.OID.Equal(issuer.Algorithm.OID) {
		return errors.Errorf("Certificate is signed with %s but the issuer key is %s", alg.Label, issuer.Algorithm.Label)
	}
	if outer.Signature.BitLength != len(outer.Signature.Bytes)*8 {
		return errors.New("Certificate signature is not a whole number of bytes")
	}
	// Certificados usam ctx vazio
	return Verify(issuer, outer.TBS.FullBytes, outer.Signature.Bytes, nil)
}

// tbsSignatureAlgorithm devolve o DER do campo signature do tbsCertificate, depois de version e serialNumber.
func tbsSignatureAlgorithm(tbsContent []byte) ([]byte, error) {
	rest := tbsContent
	var element asn1.RawValue
	var err error
	if rest, err = asn1.Unmarshal(rest, &element); err != nil {
		return nil, errors.WithMessage(err, "Malformed tbsCertificate")
	}
	if element.Class == asn1.ClassContextSpecific && element.Tag == 0 {
		if rest, err = asn1.Unmarshal(rest, &element); err != nil {
			return nil, errors.WithMessage(err, "Malformed tbsCertificate: serialNumber")
		}
	}
	if _, err = asn1.Unmarshal(rest, &element); err != nil {
		return nil, errors.WithMessage(err, "Malformed tbsCertificate: signature")
	}
	return element.FullBytes, nil
}
