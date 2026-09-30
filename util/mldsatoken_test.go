package util

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLDSATokenRoundTrip pins the pairing CreateToken and VerifyToken have to keep: a pure
// ML-DSA certificate must produce a token the server accepts.
//
// Without the ML-DSA case, CreateToken returns an empty token and no error, and every
// token-authenticated call answers "No authorization header" while enroll keeps working.
func TestMLDSATokenRoundTrip(t *testing.T) {
	csp := newTestCSP(t)

	body := []byte(`{"id":"peer0"}`)
	req := &csr.CertificateRequest{
		CN:         "mldsa-token",
		KeyRequest: &csr.KeyRequest{A: AlgoMLDSA, S: 65},
	}
	key, signer, err := BCCSPKeyRequestGenerate(req, csp)
	require.NoError(t, err)

	certPEM := selfSignedTestCert(t, signer)

	token, err := CreateToken(csp, certPEM, key, "POST", "/api/v1/register", body)
	require.NoError(t, err)
	require.NotEmpty(t, token, "token must not be empty for an ML-DSA certificate")

	_, err = VerifyToken(csp, token, "POST", "/api/v1/register", body, false)
	assert.NoError(t, err)

	_, err = VerifyToken(csp, token, "POST", "/api/v1/revoke", body, false)
	assert.Error(t, err, "the URI is part of the signed payload")
}

// TestHybridTokenUsesClassicalKey documents that a hybrid certificate does not take the
// ML-DSA branch: its SubjectPublicKeyInfo is classical, so the token is signed with the
// classical key and the ML-DSA key stays in the extension.
func TestHybridTokenUsesClassicalKey(t *testing.T) {
	csp := newTestCSP(t)

	body := []byte(`{"id":"peer0"}`)
	key, pqcKey, signer, err := BCCSPKeyRequestGenerateHybrid(
		&csr.CertificateRequest{KeyRequest: &csr.KeyRequest{A: AlgoMLDSAHybrid, S: 65}}, csp)
	require.NoError(t, err)
	require.NotNil(t, pqcKey)

	certPEM := selfSignedTestCert(t, signer)

	token, err := CreateToken(csp, certPEM, key, "POST", "/api/v1/register", body)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	_, err = VerifyToken(csp, token, "POST", "/api/v1/register", body, false)
	assert.NoError(t, err)
}

func selfSignedTestCert(t *testing.T, signer crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mldsa-token"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
