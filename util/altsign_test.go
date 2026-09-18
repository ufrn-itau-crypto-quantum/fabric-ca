/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hybridIssuer is a CA holding the two keys of the hybrid design: a conventional one backing its
// SubjectPublicKeyInfo and an ML-DSA one carried in its altSubjectPublicKeyInfo extension.
type hybridIssuer struct {
	cert      *x509.Certificate
	classical crypto.Signer
	alt       crypto.Signer
}

func newHybridIssuer(t *testing.T, params mldsa.Parameters) *hybridIssuer {
	t.Helper()
	classical, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	alt, err := mldsa.GenerateKey(params)
	require.NoError(t, err)

	spki, err := x509.MarshalPKIXPublicKey(alt.Public())
	require.NoError(t, err)
	ext, err := MarshalAltPublicKeyExtensionFromSPKI(spki)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hybrid-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, classical.Public(), classical)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &hybridIssuer{cert: cert, classical: classical, alt: alt}
}

func (ca *hybridIssuer) issue(t *testing.T, commonName string) []byte {
	t.Helper()
	subject, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, subject.Public(), ca.classical)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca *hybridIssuer) altPublicKey(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	pub, found, err := GetAltPublicKeyFromCert(ca.cert)
	require.NoError(t, err)
	require.True(t, found)
	return pub
}

func parseCertPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// TestAddAlternativeSignatureKeepsTheConventionalOneValid is the backwards-compatibility claim of
// the whole design: a verifier that ignores the three extensions must still accept the
// certificate. Rewriting the tbsCertificate invalidates the original signature, so the
// conventional one has to be recomputed over the new structure.
func TestAddAlternativeSignatureKeepsTheConventionalOneValid(t *testing.T) {
	for name, params := range map[string]mldsa.Parameters{
		"ml-dsa-44": mldsa.MLDSA44(), "ml-dsa-65": mldsa.MLDSA65(), "ml-dsa-87": mldsa.MLDSA87(),
	} {
		t.Run(name, func(t *testing.T) {
			ca := newHybridIssuer(t, params)

			rewritten, err := AddAlternativeSignature(ca.issue(t, "peer0"), ca.alt, ca.classical)
			require.NoError(t, err)

			cert := parseCertPEM(t, rewritten)
			assert.NoError(t, cert.CheckSignatureFrom(ca.cert), "a assinatura convencional deve continuar valida")
			assert.NoError(t, VerifyAlternativeSignature(cert, ca.altPublicKey(t)))
			assert.True(t, HasAlternativeSignature(cert))
		})
	}
}

// TestAlternativeSignatureIsIssuerBound guards against verifying the alternative signature with
// the wrong key: an issuer's signature must not validate under another issuer's key.
func TestAlternativeSignatureIsIssuerBound(t *testing.T) {
	ca := newHybridIssuer(t, mldsa.MLDSA44())
	other := newHybridIssuer(t, mldsa.MLDSA44())

	rewritten, err := AddAlternativeSignature(ca.issue(t, "peer0"), ca.alt, ca.classical)
	require.NoError(t, err)
	cert := parseCertPEM(t, rewritten)

	require.NoError(t, VerifyAlternativeSignature(cert, ca.altPublicKey(t)))
	assert.Error(t, VerifyAlternativeSignature(cert, other.altPublicKey(t)))
}

// TestAlternativeSignatureRejectsTampering checks that the signature actually covers the
// certificate content, and not only the extensions that carry it.
func TestAlternativeSignatureRejectsTampering(t *testing.T) {
	ca := newHybridIssuer(t, mldsa.MLDSA44())
	rewritten, err := AddAlternativeSignature(ca.issue(t, "peer0"), ca.alt, ca.classical)
	require.NoError(t, err)
	cert := parseCertPEM(t, rewritten)

	tbs, err := ParseTBSCertificate(cert.RawTBSCertificate)
	require.NoError(t, err)
	tbs.SerialNumber[len(tbs.SerialNumber)-1] ^= 0x01
	tampered, err := tbs.Marshal()
	require.NoError(t, err)
	forged, err := AssembleCertificate(tampered, tbs.SignatureAlgorithm, cert.Signature)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(forged)
	require.NoError(t, err)

	assert.Error(t, VerifyAlternativeSignature(parsed, ca.altPublicKey(t)))
}

func TestVerifyAlternativeSignatureRequiresBothExtensions(t *testing.T) {
	ca := newHybridIssuer(t, mldsa.MLDSA44())
	plain := parseCertPEM(t, ca.issue(t, "peer0"))

	assert.False(t, HasAlternativeSignature(plain))
	assert.Error(t, VerifyAlternativeSignature(plain, ca.altPublicKey(t)))

	rewritten, err := AddAlternativeSignature(ca.issue(t, "peer0"), ca.alt, ca.classical)
	require.NoError(t, err)
	cert := parseCertPEM(t, rewritten)

	assert.Error(t, VerifyAlternativeSignature(cert, nil))
	assert.Error(t, VerifyAlternativeSignature(nil, ca.altPublicKey(t)))
}

// TestVerifyAlternativeSignatureRejectsALevelMismatch covers the case of an issuer that rotated
// its alternative key to another parameter set: the announced level and the key must agree.
func TestVerifyAlternativeSignatureRejectsALevelMismatch(t *testing.T) {
	ca := newHybridIssuer(t, mldsa.MLDSA44())
	other := newHybridIssuer(t, mldsa.MLDSA87())

	rewritten, err := AddAlternativeSignature(ca.issue(t, "peer0"), ca.alt, ca.classical)
	require.NoError(t, err)
	cert := parseCertPEM(t, rewritten)

	err = VerifyAlternativeSignature(cert, other.altPublicKey(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ML-DSA-44")
}

// TestAddAlternativeSignatureIsIdempotent covers a certificate that already carries the
// extensions, as happens when an intermediate CA certificate is re-issued.
func TestAddAlternativeSignatureIsIdempotent(t *testing.T) {
	ca := newHybridIssuer(t, mldsa.MLDSA44())

	once, err := AddAlternativeSignature(ca.issue(t, "peer0"), ca.alt, ca.classical)
	require.NoError(t, err)
	twice, err := AddAlternativeSignature(once, ca.alt, ca.classical)
	require.NoError(t, err)

	cert := parseCertPEM(t, twice)
	assert.NoError(t, cert.CheckSignatureFrom(ca.cert))
	assert.NoError(t, VerifyAlternativeSignature(cert, ca.altPublicKey(t)))
	assert.Len(t, extensionsWithOID(cert, OIDAltSignatureValue), 1, "a extensao nao deve duplicar")
	assert.Len(t, extensionsWithOID(cert, OIDAltSignatureAlgorithm), 1)
}

func TestAddAlternativeSignatureRejectsBadInput(t *testing.T) {
	ca := newHybridIssuer(t, mldsa.MLDSA44())
	certPEM := ca.issue(t, "peer0")

	_, err := AddAlternativeSignature(certPEM, nil, ca.classical)
	assert.Error(t, err)
	_, err = AddAlternativeSignature(certPEM, ca.alt, nil)
	assert.Error(t, err)
	_, err = AddAlternativeSignature([]byte("nao e PEM"), ca.alt, ca.classical)
	assert.Error(t, err)
	_, err = AddAlternativeSignature(certPEM, ca.classical, ca.classical)
	assert.Error(t, err, "a chave alternativa precisa ser ML-DSA")
}

func extensionsWithOID(cert *x509.Certificate, oid interface{ String() string }) []pkix.Extension {
	var found []pkix.Extension
	for _, ext := range cert.Extensions {
		if ext.Id.String() == oid.String() {
			found = append(found, ext)
		}
	}
	return found
}
