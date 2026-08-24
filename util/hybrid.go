/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

// ML-DSA support for certificates, in two modes selected by csr.keyrequest.algo:
//
//   - "mldsa"        pure ML-DSA: the SubjectPublicKeyInfo is the ML-DSA key.
//   - "mldsa-hybrid" hybrid: the SubjectPublicKeyInfo stays classical (ECDSA) and the ML-DSA
//                    public key travels in a non-critical X.509v3 extension, so verifiers
//                    that do not know ML-DSA keep working.
//
// Two OID roles are involved in the hybrid mode and must not be confused: the extension OID
// is 2.5.29.72 (altSubjectPublicKeyInfo, ITU-T X.509 (2019) clause 9.8), while the algorithm
// OIDs for ML-DSA-44/65/87 live inside the extension value, in the AlgorithmIdentifier of the
// SubjectPublicKeyInfo. A single extension OID therefore covers all three parameter sets, and
// the verifier learns the level from the AlgorithmIdentifier.

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	cspsigner "github.com/hyperledger/fabric-lib-go/bccsp/signer"
	"github.com/pkg/errors"
)

const (
	// AlgoMLDSA is the value of csr.keyrequest.algo requesting a pure ML-DSA certificate.
	AlgoMLDSA = "mldsa"
	// AlgoMLDSAHybrid is the value of csr.keyrequest.algo requesting a hybrid
	// (classical + ML-DSA) certificate.
	AlgoMLDSAHybrid = "mldsa-hybrid"
)

// OIDAltSubjectPublicKeyInfo is the X.509v3 extension carrying an alternative public key.
// ITU-T X.509 (2019), clause 9.8.
var OIDAltSubjectPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}

// IsMLDSAKeyRequest reports whether the key request asks for a pure ML-DSA certificate.
func IsMLDSAKeyRequest(kr *csr.KeyRequest) bool {
	return kr != nil && kr.Algo() == AlgoMLDSA
}

// IsHybridKeyRequest reports whether the key request asks for a hybrid
// (classical + ML-DSA) certificate.
func IsHybridKeyRequest(kr *csr.KeyRequest) bool {
	return kr != nil && kr.Algo() == AlgoMLDSAHybrid
}

// MLDSALevel validates an ML-DSA security level as taken from csr.keyrequest.size.
func MLDSALevel(size int) (int, error) {
	switch size {
	case 44, 65, 87:
		return size, nil
	default:
		return 0, errors.Errorf("Invalid MLDSA key size: %d (expecting 44, 65 or 87)", size)
	}
}

// MLDSAParametersForLevel returns the crypto/mldsa parameter set for a security level.
func MLDSAParametersForLevel(level int) (mldsa.Parameters, error) {
	switch level {
	case 44:
		return mldsa.MLDSA44(), nil
	case 65:
		return mldsa.MLDSA65(), nil
	case 87:
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, errors.Errorf("Invalid MLDSA key size: %d (expecting 44, 65 or 87)", level)
	}
}

// MLDSALevelForKey returns the security level of an ML-DSA public key.
func MLDSALevelForKey(pub *mldsa.PublicKey) (int, error) {
	if pub == nil {
		return 0, errors.New("ML-DSA public key is nil")
	}
	switch pub.Parameters() {
	case mldsa.MLDSA44():
		return 44, nil
	case mldsa.MLDSA65():
		return 65, nil
	case mldsa.MLDSA87():
		return 87, nil
	default:
		return 0, errors.Errorf("Unrecognized ML-DSA parameters '%s'", pub.Parameters())
	}
}

// ClassicKeyRequestForLevel returns the classical key request to pair with an ML-DSA level in
// hybrid mode, choosing a curve of comparable strength. Level 87 pairs with P-384 because the
// BCCSP does not support P-521.
func ClassicKeyRequestForLevel(level int) (*csr.KeyRequest, error) {
	switch level {
	case 44:
		return &csr.KeyRequest{A: "ecdsa", S: 256}, nil
	case 65, 87:
		return &csr.KeyRequest{A: "ecdsa", S: 384}, nil
	default:
		return nil, errors.Errorf("Invalid MLDSA key size: %d (expecting 44, 65 or 87)", level)
	}
}

// MarshalAltPublicKeyExtension encodes an ML-DSA public key as a non-critical
// altSubjectPublicKeyInfo extension. The key is the BCCSP public key, whose Bytes() already
// returns a SubjectPublicKeyInfo in DER.
func MarshalAltPublicKeyExtension(pub bccsp.Key) (pkix.Extension, error) {
	if pub == nil {
		return pkix.Extension{}, errors.New("ML-DSA public key is nil")
	}
	spki, err := pub.Bytes()
	if err != nil {
		return pkix.Extension{}, errors.WithMessage(err, "Failed to marshal ML-DSA public key")
	}
	return MarshalAltPublicKeyExtensionFromSPKI(spki)
}

// MarshalAltPublicKeyExtensionFromSPKI is MarshalAltPublicKeyExtension for a public key already
// in SubjectPublicKeyInfo DER, such as one recovered from another certificate or from a CSR.
// The value is validated by parsing it before it can reach a certificate.
func MarshalAltPublicKeyExtensionFromSPKI(spki []byte) (pkix.Extension, error) {
	pub, err := MLDSAPublicKeyFromSPKI(spki)
	if err != nil {
		return pkix.Extension{}, err
	}
	level, _ := MLDSALevelForKey(pub)
	log.Debugf("ML-DSA: emitting extension %s with an ML-DSA-%d key (%d bytes of SPKI)",
		OIDAltSubjectPublicKeyInfo, level, len(spki))
	return pkix.Extension{
		Id:       OIDAltSubjectPublicKeyInfo,
		Critical: false,
		Value:    spki,
	}, nil
}

// MLDSAPublicKeyFromSPKI parses a SubjectPublicKeyInfo and requires it to hold an ML-DSA key.
func MLDSAPublicKeyFromSPKI(spki []byte) (*mldsa.PublicKey, error) {
	if len(spki) == 0 {
		return nil, errors.New("Alternative public key info is empty")
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to decode alternative public key info")
	}
	mldsaPub, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("Alternative public key is not an ML-DSA key, got %T", pub)
	}
	if _, err := MLDSALevelForKey(mldsaPub); err != nil {
		return nil, err
	}
	return mldsaPub, nil
}

// ParseAltPublicKeyExtension looks for the altSubjectPublicKeyInfo extension and returns the
// ML-DSA public key it carries, along with the raw SubjectPublicKeyInfo. It takes the extension
// slice so it works on both a certificate and a parsed CSR. found is false, with no error,
// when the extension is absent.
func ParseAltPublicKeyExtension(exts []pkix.Extension) (pub *mldsa.PublicKey, spki []byte, found bool, err error) {
	for _, ext := range exts {
		if !ext.Id.Equal(OIDAltSubjectPublicKeyInfo) {
			continue
		}
		pub, err := MLDSAPublicKeyFromSPKI(ext.Value)
		if err != nil {
			log.Debugf("ML-DSA: extension %s present but unusable: %s", OIDAltSubjectPublicKeyInfo, err)
			return nil, nil, true, err
		}
		level, _ := MLDSALevelForKey(pub)
		log.Debugf("ML-DSA: found extension %s carrying an ML-DSA-%d key",
			OIDAltSubjectPublicKeyInfo, level)
		return pub, ext.Value, true, nil
	}
	log.Debugf("ML-DSA: no %s extension present; treating as a non-hybrid certificate",
		OIDAltSubjectPublicKeyInfo)
	return nil, nil, false, nil
}

// GetAltPublicKeyFromCert is a convenience wrapper returning the ML-DSA public key carried by a
// certificate, if any.
func GetAltPublicKeyFromCert(cert *x509.Certificate) (*mldsa.PublicKey, bool, error) {
	pub, _, found, err := ParseAltPublicKeyExtension(cert.Extensions)
	return pub, found, err
}

// GetAltPublicKeyBCCSPFromCert imports the ML-DSA public key carried by a certificate into the
// BCCSP and returns it. It returns (nil, nil) when the certificate carries no such extension.
func GetAltPublicKeyBCCSPFromCert(cert *x509.Certificate, csp bccsp.BCCSP) (bccsp.Key, error) {
	if csp == nil {
		return nil, errors.New("CSP was not initialized")
	}
	_, spki, found, err := ParseAltPublicKeyExtension(cert.Extensions)
	if err != nil || !found {
		return nil, err
	}
	pub, err := csp.KeyImport(spki, &bccsp.MLDSAPKIXPublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to import the certificate's alternative public key")
	}
	return pub, nil
}

// GetAltSignerFromCert returns a crypto.Signer for the ML-DSA private key matching the
// alternative public key carried by a certificate. It returns (nil, nil) when the certificate
// carries no such extension.
//
// The lookup works because the BCCSP derives a private key's SKI from its public key, so the
// keystore can be searched starting from the public key in the certificate.
func GetAltSignerFromCert(cert *x509.Certificate, csp bccsp.BCCSP) (bccsp.Key, crypto.Signer, error) {
	pub, err := GetAltPublicKeyBCCSPFromCert(cert, csp)
	if err != nil || pub == nil {
		return nil, nil, err
	}
	ski := pub.SKI()
	log.Debugf("ML-DSA: looking up the alternative private key in the keystore, SKI '%s'",
		hex.EncodeToString(ski))
	privateKey, err := csp.GetKey(ski)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Could not find matching ML-DSA private key for SKI")
	}
	// BCCSP returns a public key if the private key for the SKI wasn't found, so
	// we need to return an error in that case.
	if !privateKey.Private() {
		return nil, nil, errors.Errorf("The ML-DSA private key associated with the certificate with SKI '%s' was not found", hex.EncodeToString(ski))
	}
	cspSigner, err := cspsigner.New(csp, privateKey)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "Failed initializing ML-DSA CryptoSigner")
	}
	return privateKey, cspSigner, nil
}
