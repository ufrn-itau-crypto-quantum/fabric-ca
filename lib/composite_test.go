/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compositeEnrollPort é a porta do servidor de TestCompositeEnrollment.
const compositeEnrollPort = 7096

// OID e AlgorithmIdentifier DER copiados dos certificados x5c do apêndice E do draft 19.
var compositeCAFixtures = []struct {
	level int
	oid   string
	algID string
}{
	{44, "1.3.6.1.5.5.7.6.40", "300a06082b06010505070628"},
	{65, "1.3.6.1.5.5.7.6.46", "300a06082b0601050507062e"},
	{87, "1.3.6.1.5.5.7.6.49", "300a06082b06010505070631"},
}

type compositeCertParts struct {
	TBS                asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

func TestCompositeRootCACert(t *testing.T) {
	for _, fx := range compositeCAFixtures {
		t.Run(mldsaName(fx.level), func(t *testing.T) {
			ca := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: util.AlgoComposite, Size: fx.level})
			cert := caCertOf(t, ca)

			pub, err := composite.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
			require.NoError(t, err)
			require.Equal(t, fx.oid, pub.Algorithm.OID.String())
			require.NoError(t, composite.CheckCertificateSignature(cert, pub))

			var parts compositeCertParts
			_, err = asn1.Unmarshal(cert.Raw, &parts)
			require.NoError(t, err)
			require.Equal(t, fx.algID, hex.EncodeToString(parts.SignatureAlgorithm.FullBytes))
			var spki struct {
				Algorithm asn1.RawValue
				PublicKey asn1.BitString
			}
			_, err = asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
			require.NoError(t, err)
			require.Equal(t, fx.algID, hex.EncodeToString(spki.Algorithm.FullBytes))

			require.True(t, cert.BasicConstraintsValid)
			require.True(t, cert.IsCA)
			require.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)

			raw, err := pub.Bytes()
			require.NoError(t, err)
			sum := sha1.Sum(raw)
			require.Equal(t, sum[:], cert.SubjectKeyId)
			if len(cert.AuthorityKeyId) > 0 {
				require.Equal(t, cert.SubjectKeyId, cert.AuthorityKeyId)
			}

			require.Nil(t, cert.PublicKey)
			require.Equal(t, x509.UnknownPublicKeyAlgorithm, cert.PublicKeyAlgorithm)
			require.Error(t, cert.CheckSignatureFrom(cert))
		})
	}
}

func TestCompositeCAKeyMaterialReload(t *testing.T) {
	ca := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: util.AlgoComposite, Size: 65})
	certFile := filepath.Join(ca.HomeDir, "ca-cert.pem")
	ca.Config.CA.Certfile = certFile
	require.NoError(t, ca.initKeyMaterial(false))

	reloaded := &CA{HomeDir: ca.HomeDir, Config: &CAConfig{}}
	reloaded.Config.CA.Certfile = certFile
	reloaded.Config.CSR.KeyRequest = &api.KeyRequest{Algo: util.AlgoComposite, Size: 65}
	csp, err := util.InitBCCSP(&reloaded.Config.CSP, "msp", ca.HomeDir)
	require.NoError(t, err)
	reloaded.csp = csp
	require.NoError(t, reloaded.initKeyMaterial(false))

	before, err := os.ReadFile(certFile)
	require.NoError(t, err)
	_, signer, cert, err := util.GetSignerFromCertFile(certFile, csp)
	require.NoError(t, err)
	pub, ok := signer.Public().(*composite.PublicKey)
	require.True(t, ok)
	require.NoError(t, composite.CheckCertificateSignature(cert, pub))
	after, err := os.ReadFile(certFile)
	require.NoError(t, err)
	require.Equal(t, before, after, "reloading must not issue a new certificate")

	keyFiles, err := filepath.Glob(filepath.Join(ca.HomeDir, "msp", "keystore", "*_sk"))
	require.NoError(t, err)
	require.Len(t, keyFiles, 1)
	require.NoError(t, validateMatchingKeys(cert, keyFiles[0]))

	other := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: util.AlgoComposite, Size: 65})
	caCertOf(t, other)
	otherKeys, err := filepath.Glob(filepath.Join(other.HomeDir, "msp", "keystore", "*_sk"))
	require.NoError(t, err)
	require.Len(t, otherKeys, 1)
	require.Error(t, validateMatchingKeys(cert, otherKeys[0]))
}

// TestCompositeEnrollment verifica o caminho de emissão de uma CA composite: enroll com chave
// composite de outro nível, reenroll com a mesma chave e enroll com chave clássica.
func TestCompositeEnrollment(t *testing.T) {
	home := path.Join(serversDir, "compositeenroll")
	srv := TestGetServer(compositeEnrollPort, home, "", -1, t)
	require.NotNil(t, srv)
	srv.CA.Config.CSR.KeyRequest = &api.KeyRequest{Algo: util.AlgoComposite, Size: 65}
	require.NoError(t, srv.Start())
	defer func() {
		assert.NoError(t, srv.Stop())
		os.RemoveAll(home)
	}()

	caCert, err := util.GetX509CertificateFromPEMFile(srv.CA.Config.CA.Certfile)
	require.NoError(t, err)
	caPub, err := composite.ParsePKIXPublicKey(caCert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)

	url := fmt.Sprintf("http://admin:adminpw@localhost:%d", compositeEnrollPort)
	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("http://localhost:%d", compositeEnrollPort),
		CSR: api.CSRInfo{KeyRequest: &api.KeyRequest{Algo: util.AlgoComposite, Size: 44}},
	}
	resp, err := clientConfig.Enroll(url, t.TempDir())
	require.NoError(t, err)
	cert, err := util.GetX509CertificateFromPEM(resp.Identity.GetECert().Cert())
	require.NoError(t, err)

	// Chave do cliente (ML-DSA-44) no SPKI, assinatura da CA (ML-DSA-65); valores do apêndice E do draft 19
	var parts compositeCertParts
	_, err = asn1.Unmarshal(cert.Raw, &parts)
	require.NoError(t, err)
	require.Equal(t, "300a06082b0601050507062e", hex.EncodeToString(parts.SignatureAlgorithm.FullBytes))
	pub, err := composite.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	require.Equal(t, "1.3.6.1.5.5.7.6.40", pub.Algorithm.OID.String())
	keySPKI, err := resp.Identity.GetECert().Key().PublicKey()
	require.NoError(t, err)
	keyDER, err := keySPKI.Bytes()
	require.NoError(t, err)
	require.Equal(t, keyDER, cert.RawSubjectPublicKeyInfo, "the certificate must carry the client's key")

	require.NoError(t, composite.CheckCertificateSignature(cert, caPub))
	require.Equal(t, caCert.RawSubject, cert.RawIssuer)
	require.Equal(t, caCert.SubjectKeyId, cert.AuthorityKeyId)
	raw, err := pub.Bytes()
	require.NoError(t, err)
	sum := sha1.Sum(raw)
	require.Equal(t, sum[:], cert.SubjectKeyId)
	require.Equal(t, "admin", cert.Subject.CommonName)
	require.False(t, cert.IsCA)

	for _, ext := range cert.Extensions {
		require.False(t, ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 72}), "altSubjectPublicKeyInfo must not be issued")
	}
	require.False(t, util.HasAlternativeSignature(cert))

	reenrolled, err := resp.Identity.Reenroll(&api.ReenrollmentRequest{
		CSR: &api.CSRInfo{KeyRequest: &api.KeyRequest{ReuseKey: true}},
	})
	require.NoError(t, err)
	recert, err := util.GetX509CertificateFromPEM(reenrolled.Identity.GetECert().Cert())
	require.NoError(t, err)
	require.Equal(t, cert.RawSubjectPublicKeyInfo, recert.RawSubjectPublicKeyInfo)
	require.NotEqual(t, cert.SerialNumber, recert.SerialNumber)
	require.NoError(t, composite.CheckCertificateSignature(recert, caPub))

	classicConfig := &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", compositeEnrollPort)}
	classicResp, err := classicConfig.Enroll(url, t.TempDir())
	require.NoError(t, err)
	classic, err := util.GetX509CertificateFromPEM(classicResp.Identity.GetECert().Cert())
	require.NoError(t, err)
	_, ok := classic.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.NoError(t, composite.CheckCertificateSignature(classic, caPub))
	require.NotEmpty(t, classic.SubjectKeyId)
	require.Equal(t, caCert.SubjectKeyId, classic.AuthorityKeyId)

	require.NoError(t, srv.CA.VerifyCertificate(cert, false))
	outsider := caCertOf(t, newTestCAForKeyRequest(t, &api.KeyRequest{Algo: util.AlgoComposite, Size: 65}))
	require.ErrorContains(t, srv.CA.VerifyCertificate(outsider, false), "unknown authority")

	records, err := srv.CA.certDBAccessor.GetCertificatesByID("admin")
	require.NoError(t, err)
	require.Len(t, records, 3)
	delivered := map[string][]byte{}
	for _, c := range []*x509.Certificate{cert, recert, classic} {
		delivered[c.SerialNumber.String()] = c.Raw
	}
	for _, record := range records {
		stored, err := util.GetX509CertificateFromPEM([]byte(record.PEM))
		require.NoError(t, err)
		assert.Equal(t, delivered[stored.SerialNumber.String()], stored.Raw)
	}
}

func TestCompositeKeyRequestRejectsInvalidSize(t *testing.T) {
	ca := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: util.AlgoComposite, Size: 256})
	_, err := ca.getCACert()
	require.Error(t, err)
}
