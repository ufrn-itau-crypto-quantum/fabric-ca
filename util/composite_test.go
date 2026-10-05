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
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
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

var oidTestCSRExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

func compositeTestCSRRequest() *csr.CertificateRequest {
	return &csr.CertificateRequest{
		CN:         "composite-csr",
		Names:      []csr.Name{{O: "org1", OU: "peer"}},
		Hosts:      []string{"peer0.org1.example.com", "10.0.0.1", "admin@org1.example.com", "spiffe://org1/peer0"},
		Extensions: []pkix.Extension{{Id: oidTestCSRExtension, Value: []byte{0x05, 0x00}}},
	}
}

func compositeTestCSR(t *testing.T, key *composite.PrivateKey) []byte {
	t.Helper()
	csrPEM, err := GenerateCSR(key, compositeTestCSRRequest())
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE REQUEST", block.Type)
	return block.Bytes
}

func TestCompositeCSR(t *testing.T) {
	// AlgorithmIdentifier copiado dos certificados x5c do apêndice E do draft 19
	for level, algID := range map[int]string{44: "300a06082b06010505070628", 65: "300a06082b0601050507062e", 87: "300a06082b06010505070631"} {
		key := compositeTestKey(t, level)
		der := compositeTestCSR(t, key)

		req, pub, err := ParseCompositeCertificateRequest(der)
		require.NoError(t, err)
		require.True(t, pub.Equal(key.PublicKey()))

		var outer certificationRequest
		_, err = asn1.Unmarshal(der, &outer)
		require.NoError(t, err)
		require.Equal(t, algID, hex.EncodeToString(outer.SignatureAlgorithm.FullBytes))
		var spki struct {
			Algorithm asn1.RawValue
			PublicKey asn1.BitString
		}
		_, err = asn1.Unmarshal(req.RawSubjectPublicKeyInfo, &spki)
		require.NoError(t, err)
		require.Equal(t, algID, hex.EncodeToString(spki.Algorithm.FullBytes))

		require.Equal(t, "composite-csr", req.Subject.CommonName)
		require.Equal(t, []string{"org1"}, req.Subject.Organization)
		require.Equal(t, []string{"peer"}, req.Subject.OrganizationalUnit)
		require.Equal(t, []string{"peer0.org1.example.com"}, req.DNSNames)
		require.True(t, req.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")))
		require.Equal(t, []string{"admin@org1.example.com"}, req.EmailAddresses)
		require.Equal(t, "spiffe://org1/peer0", req.URIs[0].String())
		found := false
		for _, ext := range req.Extensions {
			found = found || ext.Id.Equal(oidTestCSRExtension)
		}
		require.True(t, found)

		require.Nil(t, req.PublicKey)
		require.Error(t, req.CheckSignature())
	}
}

func TestCompositeCSRRejects(t *testing.T) {
	key := compositeTestKey(t, 65)
	der := compositeTestCSR(t, key)
	req, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	var outer certificationRequest
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)

	tampered := bytes.Clone(der)
	i := bytes.Index(tampered, []byte("composite-csr"))
	require.Positive(t, i)
	tampered[i] = 'k'
	_, _, err = ParseCompositeCertificateRequest(tampered)
	require.ErrorContains(t, err, "signature is not valid")

	other := compositeTestKey(t, 65)
	otherSPKI, err := composite.MarshalPKIXPublicKey(other.PublicKey())
	require.NoError(t, err)
	info, err := replaceCSRPublicKey(req.RawTBSCertificateRequest, otherSPKI)
	require.NoError(t, err)
	swapped, err := assembleCSR(info, outer.SignatureAlgorithm.FullBytes, outer.Signature.Bytes)
	require.NoError(t, err)
	_, _, err = ParseCompositeCertificateRequest(swapped)
	require.ErrorContains(t, err, "signature is not valid")

	for _, algID := range []string{"300a06082b06010505070628", "300c06082b0601050507062e0500"} {
		raw, err := hex.DecodeString(algID)
		require.NoError(t, err)
		wrongAlg, err := assembleCSR(req.RawTBSCertificateRequest, raw, outer.Signature.Bytes)
		require.NoError(t, err)
		_, _, err = ParseCompositeCertificateRequest(wrongAlg)
		require.ErrorContains(t, err, "signature algorithm is different")
	}

	_, _, err = ParseCompositeCertificateRequest(append(bytes.Clone(der), 0))
	require.Error(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecPEM, err := GenerateCSR(ecKey, compositeTestCSRRequest())
	require.NoError(t, err)
	block, _ := pem.Decode(ecPEM)
	_, _, err = ParseCompositeCertificateRequest(block.Bytes)
	require.ErrorIs(t, err, composite.ErrNotComposite)
}

func TestCompositeDraftRequest(t *testing.T) {
	key := compositeTestKey(t, 87)
	der := compositeTestCSR(t, key)
	orig, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pub, draftPEM, err := CompositeDraftRequest(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), throwaway)
	require.NoError(t, err)
	require.True(t, pub.Equal(key.PublicKey()))
	block, _ := pem.Decode(draftPEM)
	require.NotNil(t, block)
	draft, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	require.NoError(t, draft.CheckSignature())
	require.True(t, throwaway.PublicKey.Equal(draft.PublicKey))

	restored, err := replaceCSRPublicKey(draft.RawTBSCertificateRequest, orig.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	require.Equal(t, orig.RawTBSCertificateRequest, restored)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecPEM, err := GenerateCSR(ecKey, compositeTestCSRRequest())
	require.NoError(t, err)
	pub, out, err := CompositeDraftRequest(ecPEM, throwaway)
	require.NoError(t, err)
	require.Nil(t, pub)
	require.Equal(t, ecPEM, out)

	var info certificationRequestInfo
	_, err = asn1.Unmarshal(orig.RawTBSCertificateRequest, &info)
	require.NoError(t, err)
	info.Version = 1
	infoV1, err := asn1.Marshal(info)
	require.NoError(t, err)
	sigV1, err := key.Sign(rand.Reader, infoV1, nil)
	require.NoError(t, err)
	algID, err := composite.AlgorithmIdentifier(key.PublicKey().Algorithm)
	require.NoError(t, err)
	v1, err := assembleCSR(infoV1, algID, sigV1)
	require.NoError(t, err)
	_, _, err = CompositeDraftRequest(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: v1}), throwaway)
	require.ErrorContains(t, err, "Unsupported CSR version 1")

	tampered := bytes.Clone(der)
	tampered[bytes.Index(tampered, []byte("composite-csr"))] = 'k'
	_, _, err = CompositeDraftRequest(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}), throwaway)
	require.ErrorContains(t, err, "signature is not valid")
}

func TestCompositeRewriteKeepsClassicalSubject(t *testing.T) {
	draftPEM, draft := compositeDraft(t)
	issuer := compositeTestKey(t, 44)
	issuerSKID, err := composite.SubjectKeyID(issuer.PublicKey())
	require.NoError(t, err)

	out, err := RewriteAsCompositeCertificate(draftPEM, nil, issuer, issuerSKID)
	require.NoError(t, err)
	block, _ := pem.Decode(out)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	require.NoError(t, composite.CheckCertificateSignature(cert, issuer.PublicKey()))
	require.Equal(t, draft.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo)
	require.Equal(t, draft.SubjectKeyId, cert.SubjectKeyId)
	require.Equal(t, issuerSKID, cert.AuthorityKeyId)
}
