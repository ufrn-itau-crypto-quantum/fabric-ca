/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHybridRootCACert is the regression test for H3. Attaching the extension to the
// cfssl CertificateRequest is not enough: initca.NewFromSigner signs with a policy that has
// neither CopyExtensions nor an ExtensionWhitelist, so the extension used to be dropped
// silently and the CA certificate came out without it.
func TestHybridRootCACert(t *testing.T) {
	for _, level := range []int{44, 65, 87} {
		t.Run(mldsaName(level), func(t *testing.T) {
			ca := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: util.AlgoMLDSAHybrid, Size: level})

			cert := caCertOf(t, ca)

			// The SubjectPublicKeyInfo stays classical, which is what keeps chain validation,
			// TLS and the MSP algorithm gate working unchanged.
			assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm, "the SPKI must remain classical")

			pqcPub, found, err := util.GetAltPublicKeyFromCert(cert)
			require.NoError(t, err)
			require.True(t, found, "the CA certificate must carry the alternative public key extension")
			require.NotNil(t, pqcPub)

			gotLevel, err := util.MLDSALevelForKey(pqcPub)
			require.NoError(t, err)
			assert.Equal(t, level, gotLevel)

			// The extension must appear exactly once and be non-critical, so verifiers that
			// do not understand it still accept the certificate.
			count := 0
			for _, ext := range cert.Extensions {
				if ext.Id.Equal(util.OIDAltSubjectPublicKeyInfo) {
					count++
					assert.False(t, ext.Critical, "the extension must not be critical")
				}
			}
			assert.Equal(t, 1, count, "the extension must not be duplicated")
		})
	}
}

// TestPureMLDSARootCACert covers the other mode: the ML-DSA key is the SubjectPublicKeyInfo
// and signs the certificate, with no extension involved.
func TestPureMLDSARootCACert(t *testing.T) {
	for _, tc := range []struct {
		level  int
		sigAlg x509.SignatureAlgorithm
	}{
		{44, x509.MLDSA44},
		{65, x509.MLDSA65},
		{87, x509.MLDSA87},
	} {
		t.Run(mldsaName(tc.level), func(t *testing.T) {
			ca := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: util.AlgoMLDSA, Size: tc.level})

			cert := caCertOf(t, ca)

			assert.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm)
			assert.Equal(t, tc.sigAlg, cert.SignatureAlgorithm)

			// A pure certificate is self-describing, so it carries no alternative key.
			_, found, err := util.GetAltPublicKeyFromCert(cert)
			assert.NoError(t, err)
			assert.False(t, found, "a pure ML-DSA certificate must not carry the extension")

			// Self-signed: it must verify against itself.
			assert.NoError(t, cert.CheckSignatureFrom(cert))
		})
	}
}

// TestClassicalRootCACertHasNoExtension guards against the hybrid path leaking into ordinary
// classical CAs.
func TestClassicalRootCACertHasNoExtension(t *testing.T) {
	ca := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: "ecdsa", Size: 256})

	cert := caCertOf(t, ca)

	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
	_, found, err := util.GetAltPublicKeyFromCert(cert)
	assert.NoError(t, err)
	assert.False(t, found, "a classical CA certificate must not carry the extension")
}

func caCertOf(t *testing.T, ca *CA) *x509.Certificate {
	t.Helper()
	certPEM, err := ca.getCACert()
	require.NoError(t, err, "failed generating the CA certificate")

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "the CA certificate must be valid PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "the CA certificate must parse as X.509")
	return cert
}

func newTestCAForKeyRequest(t *testing.T, kr *api.KeyRequest) *CA {
	t.Helper()
	homeDir := t.TempDir()

	ca := &CA{
		HomeDir: homeDir,
		Config:  &CAConfig{},
	}
	ca.Config.CSR.CN = "mldsa-test-ca"
	ca.Config.CSR.KeyRequest = kr

	csp, err := util.InitBCCSP(&ca.Config.CSP, "msp", homeDir)
	require.NoError(t, err, "failed initializing BCCSP")
	ca.csp = csp

	return ca
}

func mldsaName(level int) string {
	switch level {
	case 44:
		return "ML-DSA-44"
	case 65:
		return "ML-DSA-65"
	default:
		return "ML-DSA-87"
	}
}
