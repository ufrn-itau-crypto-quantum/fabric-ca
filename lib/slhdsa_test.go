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
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	stls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const slhdsaEnrollPort = 7097

// OIDs of RFC 9909 and of the experimental composite pairs of bccsp/composite.
var slhdsaCAFixtures = []struct {
	algo string
	size int
	oid  string
}{
	{"slhdsa-sha2-f", 128, "2.16.840.1.101.3.4.3.21"},
	{"slhdsa-sha2-s", 128, "2.16.840.1.101.3.4.3.20"},
	{"slhdsa-shake-f", 192, "2.16.840.1.101.3.4.3.29"},
	{"composite-slhdsa-sha2-f", 128, "1.3.6.1.4.1.32473.1.2"},
}

func TestSLHDSARootCACert(t *testing.T) {
	for _, fx := range slhdsaCAFixtures {
		t.Run(fmt.Sprintf("%s-%d", fx.algo, fx.size), func(t *testing.T) {
			ca := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: fx.algo, Size: fx.size})
			cert := caCertOf(t, ca)

			pub, err := pkixext.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
			require.NoError(t, err)
			require.NoError(t, pkixext.CheckCertificateSignature(cert, pub))

			algID, err := pkixext.AlgorithmIdentifier(pub)
			require.NoError(t, err)
			var ai struct{ Algorithm asn1.ObjectIdentifier }
			_, err = asn1.Unmarshal(algID, &ai)
			require.NoError(t, err)
			require.Equal(t, fx.oid, ai.Algorithm.String())
			var parts compositeCertParts
			_, err = asn1.Unmarshal(cert.Raw, &parts)
			require.NoError(t, err)
			require.Equal(t, algID, parts.SignatureAlgorithm.FullBytes)

			require.True(t, cert.IsCA)
			require.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
			skid, err := pkixext.SubjectKeyID(pub)
			require.NoError(t, err)
			require.Equal(t, skid, cert.SubjectKeyId)
			require.Nil(t, cert.PublicKey)
		})
	}
}

func TestSLHDSAKeyRequestRejectsInvalid(t *testing.T) {
	for _, kr := range []*api.KeyRequest{
		{Algo: "slhdsa-sha2-s", Size: 100},
		{Algo: "slhdsa-sha3-s", Size: 128},
		{Algo: "slhdsa-sha2-x", Size: 128},
		{Algo: "composite-slhdsa-shake-s", Size: 128},
	} {
		ca := newTestCAForKeyRequest(t, kr)
		_, err := ca.getCACert()
		require.Error(t, err, "%s-%d", kr.Algo, kr.Size)
	}
}

func TestSLHDSACAKeyMaterialReload(t *testing.T) {
	kr := &api.KeyRequest{Algo: "slhdsa-sha2-f", Size: 128}
	ca := newTestCAForKeyRequest(t, kr)
	certFile := filepath.Join(ca.HomeDir, "ca-cert.pem")
	ca.Config.CA.Certfile = certFile
	require.NoError(t, ca.initKeyMaterial(false))

	reloaded := &CA{HomeDir: ca.HomeDir, Config: &CAConfig{}}
	reloaded.Config.CA.Certfile = certFile
	reloaded.Config.CSR.KeyRequest = kr
	csp, err := util.InitBCCSP(&reloaded.Config.CSP, "msp", ca.HomeDir)
	require.NoError(t, err)
	reloaded.csp = csp
	require.NoError(t, reloaded.initKeyMaterial(false))

	_, signer, cert, err := util.GetSignerFromCertFile(certFile, csp)
	require.NoError(t, err)
	pub, ok := signer.Public().(*slhdsa.PublicKey)
	require.True(t, ok)
	require.NoError(t, pkixext.CheckCertificateSignature(cert, pub))

	keyFiles, err := filepath.Glob(filepath.Join(ca.HomeDir, "msp", "keystore", "*_sk"))
	require.NoError(t, err)
	require.Len(t, keyFiles, 1)
	require.NoError(t, validateMatchingKeys(cert, keyFiles[0]))

	other := newTestCAForKeyRequest(t, kr)
	caCertOf(t, other)
	otherKeys, err := filepath.Glob(filepath.Join(other.HomeDir, "msp", "keystore", "*_sk"))
	require.NoError(t, err)
	require.Error(t, validateMatchingKeys(cert, otherKeys[0]))
}

// TestSLHDSAEnrollment covers the issuance path of an SLH-DSA-SHA2-128f CA: enroll with an
// SLH-DSA-SHA2-128s key, reenroll with the same key, enroll with a composite SLH-DSA key and with a
// classical key, then revoke and generate the CRL.
func TestSLHDSAEnrollment(t *testing.T) {
	home := path.Join(serversDir, "slhdsaenroll")
	srv := TestGetServer(slhdsaEnrollPort, home, "", -1, t)
	require.NotNil(t, srv)
	srv.CA.Config.CSR.KeyRequest = &api.KeyRequest{Algo: "slhdsa-sha2-f", Size: 128}
	require.NoError(t, srv.Start())
	defer func() {
		assert.NoError(t, srv.Stop())
		os.RemoveAll(home)
	}()

	caCert, err := util.GetX509CertificateFromPEMFile(srv.CA.Config.CA.Certfile)
	require.NoError(t, err)
	caPub, err := pkixext.ParsePKIXPublicKey(caCert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	caAlgID, err := pkixext.AlgorithmIdentifier(caPub)
	require.NoError(t, err)

	url := fmt.Sprintf("http://admin:adminpw@localhost:%d", slhdsaEnrollPort)
	enroll := func(kr *api.KeyRequest) (*EnrollmentResponse, *x509.Certificate) {
		t.Helper()
		cfg := &ClientConfig{URL: fmt.Sprintf("http://localhost:%d", slhdsaEnrollPort)}
		if kr != nil {
			cfg.CSR = api.CSRInfo{KeyRequest: kr}
		}
		resp, err := cfg.Enroll(url, t.TempDir())
		require.NoError(t, err)
		cert, err := util.GetX509CertificateFromPEM(resp.Identity.GetECert().Cert())
		require.NoError(t, err)
		require.NoError(t, pkixext.CheckCertificateSignature(cert, caPub))
		require.Equal(t, caCert.RawSubject, cert.RawIssuer)
		require.Equal(t, caCert.SubjectKeyId, cert.AuthorityKeyId)
		var parts compositeCertParts
		_, err = asn1.Unmarshal(cert.Raw, &parts)
		require.NoError(t, err)
		require.Equal(t, caAlgID, parts.SignatureAlgorithm.FullBytes)
		require.NoError(t, srv.CA.VerifyCertificate(cert, false))
		return resp, cert
	}

	resp, cert := enroll(&api.KeyRequest{Algo: "slhdsa-sha2-s", Size: 128})
	pub, err := pkixext.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	slhPub, ok := pub.(*slhdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, slhdsa.SHA2_128s, slhPub.ParameterSet)
	raw, err := slhPub.Bytes()
	require.NoError(t, err)
	sum := sha1.Sum(raw)
	require.Equal(t, sum[:], cert.SubjectKeyId)
	keySPKI, err := resp.Identity.GetECert().Key().PublicKey()
	require.NoError(t, err)
	keyDER, err := keySPKI.Bytes()
	require.NoError(t, err)
	require.Equal(t, keyDER, cert.RawSubjectPublicKeyInfo, "the certificate must carry the client's key")

	reenrolled, err := resp.Identity.Reenroll(&api.ReenrollmentRequest{
		CSR: &api.CSRInfo{KeyRequest: &api.KeyRequest{ReuseKey: true}},
	})
	require.NoError(t, err)
	recert, err := util.GetX509CertificateFromPEM(reenrolled.Identity.GetECert().Cert())
	require.NoError(t, err)
	require.Equal(t, cert.RawSubjectPublicKeyInfo, recert.RawSubjectPublicKeyInfo)
	require.NoError(t, pkixext.CheckCertificateSignature(recert, caPub))

	_, compCert := enroll(&api.KeyRequest{Algo: "composite-slhdsa-sha2-f", Size: 128})
	compPub, err := pkixext.ParsePKIXPublicKey(compCert.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	require.IsType(t, &composite.PublicKey{}, compPub)

	_, classic := enroll(nil)
	_, ok = classic.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	outsider := caCertOf(t, newTestCAForKeyRequest(t, &api.KeyRequest{Algo: "slhdsa-sha2-f", Size: 128}))
	require.ErrorContains(t, srv.CA.VerifyCertificate(outsider, false), "unknown authority")

	_, err = resp.Identity.Revoke(&api.RevocationRequest{
		Serial: util.GetSerialAsHex(classic.SerialNumber),
		AKI:    hex.EncodeToString(classic.AuthorityKeyId),
	})
	require.NoError(t, err)
	crlResp, err := resp.Identity.GenCRL(&api.GenCRLRequest{})
	require.NoError(t, err)
	block, _ := pem.Decode(crlResp.CRL)
	require.NotNil(t, block)
	//nolint:staticcheck
	crl, err := x509.ParseCRL(block.Bytes)
	require.NoError(t, err)
	require.True(t, pkixext.IsCRLSignedWithExternal(crl))
	require.NoError(t, pkixext.CheckCRLSignature(crl, caPub))
	require.Len(t, crl.TBSCertList.RevokedCertificates, 1)
	require.Equal(t, classic.SerialNumber, crl.TBSCertList.RevokedCertificates[0].SerialNumber)
}

// TestSLHDSATLSPKI mirrors the TLS PKI of the runner: a root and an intermediate with SLH-DSA keys,
// both serving TLS with the ML-DSA certificate each generates for itself, the intermediate enrolling
// with the root over TLS, and a client enrolling with the intermediate over TLS.
func TestSLHDSATLSPKI(t *testing.T) {
	const rootPort, interPort = 7091, 7092
	rootHome := path.Join(serversDir, "slhdsatlsroot")
	interHome := path.Join(serversDir, "slhdsatlsinter")
	defer os.RemoveAll(rootHome)
	defer os.RemoveAll(interHome)
	slh := &api.KeyRequest{Algo: "slhdsa-sha2-f", Size: 128}
	tlsLeaf := stls.KeyRequest{Algo: util.AlgoMLDSA, Size: 44}

	root := TestGetServer(rootPort, rootHome, "", -1, t)
	require.NotNil(t, root)
	root.CA.Config.CSR.KeyRequest = slh
	root.CA.Config.CSR.Hosts = []string{"localhost"}
	root.Config.CAcfg.CSR.Hosts = []string{"localhost"}
	root.Config.TLS = stls.ServerTLSConfig{Enabled: true, CertFile: "tls-cert.pem", KeyRequest: tlsLeaf}
	require.NoError(t, root.Start())
	defer func() { assert.NoError(t, root.Stop()) }()

	rootCAFile := root.CA.Config.CA.Certfile
	rootCA, err := util.GetX509CertificateFromPEMFile(rootCAFile)
	require.NoError(t, err)
	rootPub, err := pkixext.ParsePKIXPublicKey(rootCA.RawSubjectPublicKeyInfo)
	require.NoError(t, err)
	tlsCert, err := util.GetX509CertificateFromPEMFile(root.Config.TLS.CertFile)
	require.NoError(t, err)
	require.Equal(t, x509.MLDSA, tlsCert.PublicKeyAlgorithm, "the TLS certificate follows tls.keyrequest")
	require.NoError(t, pkixext.CheckCertificateSignature(tlsCert, rootPub))

	inter := TestGetServer(interPort, interHome, fmt.Sprintf("https://admin:adminpw@localhost:%d", rootPort), -1, t)
	require.NotNil(t, inter)
	inter.CA.Config.CSR.KeyRequest = slh
	inter.CA.Config.CSR.CN = ""
	inter.CA.Config.CSR.Hosts = []string{"localhost"}
	inter.Config.CAcfg.CSR.Hosts = []string{"localhost"}
	inter.CA.Config.Intermediate.TLS = stls.ClientTLSConfig{Enabled: true, CertFiles: []string{rootCAFile}}
	inter.Config.TLS = stls.ServerTLSConfig{Enabled: true, CertFile: "tls-cert.pem", KeyRequest: tlsLeaf}
	require.NoError(t, inter.Start())
	defer func() { assert.NoError(t, inter.Stop()) }()

	interCA, err := util.GetX509CertificateFromPEMFile(inter.CA.Config.CA.Certfile)
	require.NoError(t, err)
	require.Equal(t, rootCA.RawSubject, interCA.RawIssuer)
	require.NoError(t, pkixext.CheckCertificateSignature(interCA, rootPub))

	trust := filepath.Join(t.TempDir(), "tls-trust.pem")
	rootPEM, err := os.ReadFile(rootCAFile)
	require.NoError(t, err)
	interPEM, err := os.ReadFile(inter.CA.Config.CA.Certfile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(trust, append(rootPEM, interPEM...), 0o600))

	enroll := func(trustFile string) error {
		cfg := &ClientConfig{
			URL: fmt.Sprintf("https://localhost:%d", interPort),
			TLS: stls.ClientTLSConfig{Enabled: true, CertFiles: []string{trustFile}},
			CSR: api.CSRInfo{KeyRequest: &api.KeyRequest{Algo: util.AlgoMLDSA, Size: 44}},
		}
		_, err := cfg.Enroll(fmt.Sprintf("https://admin:adminpw@localhost:%d", interPort), t.TempDir())
		return err
	}
	require.NoError(t, enroll(trust))

	outsider := newTestCAForKeyRequest(t, slh)
	outsiderFile := filepath.Join(t.TempDir(), "outsider.pem")
	require.NoError(t, os.WriteFile(outsiderFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertOf(t, outsider).Raw}), 0o600))
	require.ErrorContains(t, enroll(outsiderFile), "unknown authority")
}
