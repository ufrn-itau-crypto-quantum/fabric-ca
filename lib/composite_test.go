/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/stretchr/testify/require"
)

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

func TestCompositeKeyRequestRejectsInvalidSize(t *testing.T) {
	ca := newTestCAForKeyRequest(t, &api.KeyRequest{Algo: util.AlgoComposite, Size: 256})
	_, err := ca.getCACert()
	require.Error(t, err)
}
