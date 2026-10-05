/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/stretchr/testify/require"
)

// compositeDraft emite, com chaves ECDSA descartáveis, um rascunho assinado por outra CA, com
// SubjectKeyId e AuthorityKeyId.
func compositeDraft(t *testing.T) (draftPEM []byte, draft *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "draft-ca"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafSKID := sha1.Sum(elliptic.MarshalCompressed(elliptic.P256(), leafKey.X, leafKey.Y))
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "draft-leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: leafSKID[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	draft, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	require.NotEmpty(t, draft.SubjectKeyId)
	require.Equal(t, []byte{1, 2, 3, 4}, draft.AuthorityKeyId)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), draft
}

func compositeTestKey(t *testing.T, level int) *composite.PrivateKey {
	t.Helper()
	alg, err := composite.AlgorithmForLevel(level)
	require.NoError(t, err)
	key, err := composite.GenerateKey(alg)
	require.NoError(t, err)
	return key
}

func TestCompositeRewriteIssuedCertificate(t *testing.T) {
	draftPEM, draft := compositeDraft(t)
	issuer := compositeTestKey(t, 65)
	subject := compositeTestKey(t, 44)
	issuerSKID, err := composite.SubjectKeyID(issuer.PublicKey())
	require.NoError(t, err)

	out, err := RewriteAsCompositeCertificate(draftPEM, subject.PublicKey(), issuer, issuerSKID)
	require.NoError(t, err)
	block, _ := pem.Decode(out)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	require.NoError(t, composite.CheckCertificateSignature(cert, issuer.PublicKey()))
	require.Error(t, composite.CheckCertificateSignature(cert, subject.PublicKey()))

	pub, err := composite.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	require.True(t, pub.Equal(subject.PublicKey()))
	raw, err := subject.PublicKey().Bytes()
	require.NoError(t, err)
	sum := sha1.Sum(raw)
	require.Equal(t, sum[:], cert.SubjectKeyId)
	require.Equal(t, issuerSKID, cert.AuthorityKeyId)
	require.False(t, bytes.Contains(block.Bytes, draft.RawSubjectPublicKeyInfo))
	require.False(t, bytes.Contains(block.Bytes, draft.SubjectKeyId))

	require.Equal(t, draft.SerialNumber, cert.SerialNumber)
	require.Equal(t, draft.RawSubject, cert.RawSubject)
	require.Equal(t, draft.RawIssuer, cert.RawIssuer)
	require.Equal(t, draft.NotBefore, cert.NotBefore)
	require.Equal(t, draft.NotAfter, cert.NotAfter)
	require.Equal(t, draft.KeyUsage, cert.KeyUsage)
}

func TestCompositeRewriteRejects(t *testing.T) {
	draftPEM, _ := compositeDraft(t)
	issuer := compositeTestKey(t, 44)
	subject := compositeTestKey(t, 44)

	_, err := RewriteAsCompositeCertificate(draftPEM, subject.PublicKey(), issuer, nil)
	require.Error(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = RewriteAsCompositeCertificate(draftPEM, subject.PublicKey(), ecKey, []byte{1})
	require.Error(t, err)

	_, err = RewriteAsCompositeCertificate([]byte("not pem"), subject.PublicKey(), issuer, []byte{1})
	require.Error(t, err)
}

func TestCompositeKeyRequest(t *testing.T) {
	require.True(t, IsCompositeKeyRequest(&csr.KeyRequest{A: AlgoComposite, S: 65}))
	require.False(t, IsCompositeKeyRequest(&csr.KeyRequest{A: AlgoMLDSAHybrid, S: 65}))
	require.False(t, IsCompositeKeyRequest(nil))

	for level, oid := range map[int]string{44: "1.3.6.1.5.5.7.6.40", 65: "1.3.6.1.5.5.7.6.46", 87: "1.3.6.1.5.5.7.6.49"} {
		opts, err := getBCCSPKeyOpts(&csr.KeyRequest{A: AlgoComposite, S: level}, true)
		require.NoError(t, err)
		composite, ok := opts.(*bccsp.CompositeKeyGenOpts)
		require.True(t, ok)
		require.Equal(t, oid, composite.OID.String())
		require.True(t, composite.Temporary)
	}
	_, err := getBCCSPKeyOpts(&csr.KeyRequest{A: AlgoComposite, S: 256}, true)
	require.Error(t, err)
}
