/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMLDSALevel(t *testing.T) {
	for _, level := range []int{44, 65, 87} {
		got, err := MLDSALevel(level)
		assert.NoError(t, err)
		assert.Equal(t, level, got)
	}
	for _, bad := range []int{0, 43, 256, 88} {
		_, err := MLDSALevel(bad)
		assert.Error(t, err, "size %d must be rejected", bad)
	}
}

func TestClassicKeyRequestForLevel(t *testing.T) {
	// The classical half must be strong enough for the level it is paired with, and the
	// BCCSP does not support P-521, so 87 also lands on P-384.
	for level, size := range map[int]int{44: 256, 65: 384, 87: 384} {
		kr, err := ClassicKeyRequestForLevel(level)
		require.NoError(t, err)
		assert.Equal(t, "ecdsa", kr.A)
		assert.Equal(t, size, kr.S)
	}
	_, err := ClassicKeyRequestForLevel(12)
	assert.Error(t, err)
}

func TestIsKeyRequest(t *testing.T) {
	assert.True(t, IsMLDSAKeyRequest(&csr.KeyRequest{A: AlgoMLDSA, S: 65}))
	assert.False(t, IsHybridKeyRequest(&csr.KeyRequest{A: AlgoMLDSA, S: 65}))
	assert.True(t, IsHybridKeyRequest(&csr.KeyRequest{A: AlgoMLDSAHybrid, S: 65}))
	assert.False(t, IsMLDSAKeyRequest(&csr.KeyRequest{A: AlgoMLDSAHybrid, S: 65}))
	assert.False(t, IsMLDSAKeyRequest(&csr.KeyRequest{A: "ecdsa", S: 256}))
	assert.False(t, IsMLDSAKeyRequest(nil))
	assert.False(t, IsHybridKeyRequest(nil))
}

// TestAltPublicKeyExtensionRoundTrip covers the whole extension path per level, ending in a
// real signature verification with the recovered key.
func TestAltPublicKeyExtensionRoundTrip(t *testing.T) {
	for _, level := range []int{44, 65, 87} {
		params, err := MLDSAParametersForLevel(level)
		require.NoError(t, err)

		priv, err := mldsa.GenerateKey(params)
		require.NoError(t, err)

		spki, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
		require.NoError(t, err)

		ext, err := MarshalAltPublicKeyExtensionFromSPKI(spki)
		require.NoError(t, err)
		assert.True(t, ext.Id.Equal(OIDAltSubjectPublicKeyInfo))
		assert.False(t, ext.Critical, "the extension must not be critical")

		pub, gotSPKI, found, err := ParseAltPublicKeyExtension([]pkix.Extension{ext})
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, spki, gotSPKI)

		gotLevel, err := MLDSALevelForKey(pub)
		require.NoError(t, err)
		assert.Equal(t, level, gotLevel)
		assert.Equal(t, params.PublicKeySize(), len(pub.Bytes()))

		// The recovered key must verify a signature made by the original private key.
		msg := []byte("fabric-ca hybrid identity")
		sig, err := priv.Sign(rand.Reader, msg, &mldsa.Options{})
		require.NoError(t, err)
		assert.NoError(t, mldsa.Verify(pub, msg, sig, &mldsa.Options{}))
	}
}

func TestParseAltPublicKeyExtensionAbsent(t *testing.T) {
	// An unrelated extension must be reported as "not found", not as an error.
	other := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x00}}
	pub, spki, found, err := ParseAltPublicKeyExtension([]pkix.Extension{other})
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, pub)
	assert.Nil(t, spki)

	_, _, found, err = ParseAltPublicKeyExtension(nil)
	assert.NoError(t, err)
	assert.False(t, found)
}

func TestParseAltPublicKeyExtensionRejectsBadValues(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecSPKI, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)

	for name, value := range map[string][]byte{
		"empty":        {},
		"garbage":      []byte("not der at all"),
		"truncatedDER": {0x30, 0x82, 0x07, 0xb2},
		// A well-formed SPKI carrying the wrong algorithm must be refused, otherwise a
		// classical key could masquerade as the post-quantum one.
		"classicalKey": ecSPKI,
	} {
		t.Run(name, func(t *testing.T) {
			ext := pkix.Extension{Id: OIDAltSubjectPublicKeyInfo, Value: value}
			_, _, found, err := ParseAltPublicKeyExtension([]pkix.Extension{ext})
			assert.True(t, found, "a present-but-invalid extension must be reported as found")
			assert.Error(t, err)

			// The same values must be refused on the way in, so a bad CSR is rejected
			// before it can produce a certificate.
			_, err = MarshalAltPublicKeyExtensionFromSPKI(value)
			assert.Error(t, err)
		})
	}
}

func TestGetAltPublicKeyFromCert(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	require.NoError(t, err)
	ext, err := MarshalAltPublicKeyExtensionFromSPKI(spki)
	require.NoError(t, err)

	cert := &x509.Certificate{Extensions: []pkix.Extension{ext}}
	pub, found, err := GetAltPublicKeyFromCert(cert)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, priv.PublicKey().Equal(pub))

	_, found, err = GetAltPublicKeyFromCert(&x509.Certificate{})
	assert.NoError(t, err)
	assert.False(t, found)
}

// TestBCCSPKeyRequestGenerateHybridContract pins the contract the whole issuance chain relies
// on: the returned bccsp.Key is always the one backing the SubjectPublicKeyInfo, and the
// signer always matches it.
func TestBCCSPKeyRequestGenerateHybridContract(t *testing.T) {
	csp := newTestCSP(t)

	t.Run("hybrid", func(t *testing.T) {
		key, pqcKey, signer, err := BCCSPKeyRequestGenerateHybrid(
			&csr.CertificateRequest{KeyRequest: &csr.KeyRequest{A: AlgoMLDSAHybrid, S: 65}}, csp)
		require.NoError(t, err)
		require.NotNil(t, pqcKey, "a hybrid request must yield an ML-DSA key")

		_, isECDSA := signer.Public().(*ecdsa.PublicKey)
		assert.True(t, isECDSA, "the signer must be classical, got %T", signer.Public())

		// The classical key is what the certificate's SKI is computed from, so it is the one
		// that has to be returned as the primary key.
		pub, err := key.PublicKey()
		require.NoError(t, err)
		raw, err := pub.Bytes()
		require.NoError(t, err)
		parsed, err := x509.ParsePKIXPublicKey(raw)
		require.NoError(t, err)
		assert.IsType(t, &ecdsa.PublicKey{}, parsed)

		pqcPub, err := pqcKey.PublicKey()
		require.NoError(t, err)
		pqcRaw, err := pqcPub.Bytes()
		require.NoError(t, err)
		pqcParsed, err := x509.ParsePKIXPublicKey(pqcRaw)
		require.NoError(t, err)
		assert.IsType(t, &mldsa.PublicKey{}, pqcParsed)
	})

	t.Run("pure", func(t *testing.T) {
		key, pqcKey, signer, err := BCCSPKeyRequestGenerateHybrid(
			&csr.CertificateRequest{KeyRequest: &csr.KeyRequest{A: AlgoMLDSA, S: 44}}, csp)
		require.NoError(t, err)
		assert.Nil(t, pqcKey, "a pure request keeps the ML-DSA key as the primary one")
		_, isMLDSA := signer.Public().(*mldsa.PublicKey)
		assert.True(t, isMLDSA, "the signer must be ML-DSA, got %T", signer.Public())
		assert.NotNil(t, key)
	})

	t.Run("classical", func(t *testing.T) {
		key, pqcKey, signer, err := BCCSPKeyRequestGenerateHybrid(
			&csr.CertificateRequest{KeyRequest: &csr.KeyRequest{A: "ecdsa", S: 256}}, csp)
		require.NoError(t, err)
		assert.Nil(t, pqcKey)
		assert.NotNil(t, key)
		_, isECDSA := signer.Public().(*ecdsa.PublicKey)
		assert.True(t, isECDSA)
	})

	t.Run("badLevel", func(t *testing.T) {
		_, _, _, err := BCCSPKeyRequestGenerateHybrid(
			&csr.CertificateRequest{KeyRequest: &csr.KeyRequest{A: AlgoMLDSAHybrid, S: 128}}, csp)
		assert.Error(t, err)
	})
}

// TestGetAltSignerFromCert covers H6: finding the ML-DSA private key in the keystore starting
// from the certificate that carries its public key. It only works because the BCCSP derives a
// private key's SKI from its public key.
func TestGetAltSignerFromCert(t *testing.T) {
	csp := newTestCSP(t)

	_, pqcKey, _, err := BCCSPKeyRequestGenerateHybrid(
		&csr.CertificateRequest{KeyRequest: &csr.KeyRequest{A: AlgoMLDSAHybrid, S: 65}}, csp)
	require.NoError(t, err)

	pqcPub, err := pqcKey.PublicKey()
	require.NoError(t, err)
	ext, err := MarshalAltPublicKeyExtension(pqcPub)
	require.NoError(t, err)
	cert := &x509.Certificate{Extensions: []pkix.Extension{ext}}

	key, signer, err := GetAltSignerFromCert(cert, csp)
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.True(t, key.Private())
	assert.Equal(t, pqcKey.SKI(), key.SKI())

	// The recovered signer must actually be the counterpart of the key in the extension.
	msg := []byte("reenrollment with a reused key")
	sig, err := signer.Sign(rand.Reader, msg, &mldsa.Options{})
	require.NoError(t, err)
	recovered, found, err := GetAltPublicKeyFromCert(cert)
	require.NoError(t, err)
	require.True(t, found)
	assert.NoError(t, mldsa.Verify(recovered, msg, sig, &mldsa.Options{}))

	// A certificate without the extension is not an error, just nothing to find.
	key, signer, err = GetAltSignerFromCert(&x509.Certificate{}, csp)
	assert.NoError(t, err)
	assert.Nil(t, key)
	assert.Nil(t, signer)
}

// TestGenerateCSRWithMLDSAKey is the regression test for the vendored cfssl csr.Generate,
// which rejects any key whose signature algorithm it does not recognise, ML-DSA included.
func TestGenerateCSRWithMLDSAKey(t *testing.T) {
	csp := newTestCSP(t)

	for _, tc := range []struct {
		name   string
		algo   string
		size   int
		sigAlg x509.SignatureAlgorithm
	}{
		{"pure ML-DSA-44", AlgoMLDSA, 44, x509.MLDSA44},
		{"pure ML-DSA-65", AlgoMLDSA, 65, x509.MLDSA65},
		{"pure ML-DSA-87", AlgoMLDSA, 87, x509.MLDSA87},
		{"classical", "ecdsa", 256, x509.ECDSAWithSHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &csr.CertificateRequest{
				CN:         "csr-test",
				KeyRequest: &csr.KeyRequest{A: tc.algo, S: tc.size},
			}
			_, _, signer, err := BCCSPKeyRequestGenerateHybrid(req, csp)
			require.NoError(t, err)

			csrPEM, err := GenerateCSR(signer, req)
			require.NoError(t, err)

			parsed := parseCSR(t, csrPEM)
			assert.Equal(t, tc.sigAlg, parsed.SignatureAlgorithm)
			assert.NoError(t, parsed.CheckSignature())
		})
	}
}

// TestGenerateCSRCarriesExtensions covers the client side of the hybrid enrollment: the
// alternative public key has to survive into the CSR, which the cfssl of the previous
// vendored version silently dropped.
func TestGenerateCSRCarriesExtensions(t *testing.T) {
	csp := newTestCSP(t)

	req := &csr.CertificateRequest{
		CN:         "csr-test",
		KeyRequest: &csr.KeyRequest{A: AlgoMLDSAHybrid, S: 65},
	}
	_, pqcKey, signer, err := BCCSPKeyRequestGenerateHybrid(req, csp)
	require.NoError(t, err)

	pqcPub, err := pqcKey.PublicKey()
	require.NoError(t, err)
	ext, err := MarshalAltPublicKeyExtension(pqcPub)
	require.NoError(t, err)
	req.Extensions = append(req.Extensions, ext)

	csrPEM, err := GenerateCSR(signer, req)
	require.NoError(t, err)

	parsed := parseCSR(t, csrPEM)
	require.NoError(t, parsed.CheckSignature())

	pub, _, found, err := ParseAltPublicKeyExtension(parsed.Extensions)
	require.NoError(t, err)
	require.True(t, found, "the CSR must carry the alternative public key extension")

	expected, err := pqcPub.Bytes()
	require.NoError(t, err)
	got, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	assert.Equal(t, expected, got)
}

func parseCSR(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block, "the CSR must be valid PEM")
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	return parsed
}

func newTestCSP(t *testing.T) bccsp.BCCSP {
	t.Helper()
	homeDir := t.TempDir()
	var opts *factory.FactoryOpts
	csp, err := InitBCCSP(&opts, "msp", homeDir)
	require.NoError(t, err, "failed initializing BCCSP")
	return csp
}
