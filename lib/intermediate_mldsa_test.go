/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ports dedicated to the ML-DSA intermediate CA tests, apart from the ones other lib tests use.
const (
	mldsaRootPort         = 7093
	mldsaIntermediatePort = 7094
)

// mldsaChain is a root CA, an intermediate CA enrolled with it, and a leaf enrolled with the
// intermediate, all generated with the same key request.
type mldsaChain struct {
	root, intermediate, leaf *x509.Certificate
	chainFile                []*x509.Certificate
}

// startMLDSAChain starts a root and an intermediate server with the given key request, enrolls a
// leaf with the intermediate and returns the three certificates plus the intermediate's
// ca-chain.pem. Both servers are stopped when the test ends.
func startMLDSAChain(t *testing.T, kr *api.KeyRequest) mldsaChain {
	t.Helper()
	base := t.TempDir()

	root := TestGetServer(mldsaRootPort, path.Join(base, "root"), "", -1, t)
	require.NotNil(t, root)
	root.CA.Config.CSR.KeyRequest = kr
	require.NoError(t, root.Start())
	t.Cleanup(func() { assert.NoError(t, root.Stop()) })

	parentURL := fmt.Sprintf("http://admin:adminpw@localhost:%d", mldsaRootPort)
	intermediate := TestGetServer(mldsaIntermediatePort, path.Join(base, "intermediate"), parentURL, -1, t)
	require.NotNil(t, intermediate)
	intermediate.CA.Config.CSR.KeyRequest = kr
	require.NoError(t, intermediate.Start(), "the intermediate CA must enroll with the root")
	t.Cleanup(func() { assert.NoError(t, intermediate.Stop()) })

	clientConfig := &ClientConfig{
		URL: fmt.Sprintf("http://localhost:%d", mldsaIntermediatePort),
		CSR: api.CSRInfo{KeyRequest: kr},
	}
	resp, err := clientConfig.Enroll(
		fmt.Sprintf("http://admin:adminpw@localhost:%d", mldsaIntermediatePort), path.Join(base, "client"))
	require.NoError(t, err, "a leaf must enroll with the intermediate CA")

	var chain mldsaChain
	chain.root, err = util.GetX509CertificateFromPEMFile(root.CA.Config.CA.Certfile)
	require.NoError(t, err)
	chain.intermediate, err = util.GetX509CertificateFromPEMFile(intermediate.CA.Config.CA.Certfile)
	require.NoError(t, err)
	chain.leaf, err = util.GetX509CertificateFromPEM(resp.Identity.GetECert().Cert())
	require.NoError(t, err)

	chainPEM, err := os.ReadFile(intermediate.CA.Config.CA.Chainfile)
	require.NoError(t, err)
	chain.chainFile, err = util.GetX509CertificatesFromPEM(chainPEM)
	require.NoError(t, err)
	return chain
}

// verifyConventionalChain checks leaf -> intermediate -> root with the standard library, which is
// what every verifier that ignores the alternative extensions does.
func verifyConventionalChain(t *testing.T, chain mldsaChain) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(chain.root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain.intermediate)

	chains, err := chain.leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, err, "the leaf must chain to the root through the intermediate")
	require.Len(t, chains, 1)
	assert.Len(t, chains[0], 3)
}

func TestHybridIntermediateCA(t *testing.T) {
	chain := startMLDSAChain(t, &api.KeyRequest{Algo: util.AlgoMLDSAHybrid, Size: 44})

	require.Len(t, chain.chainFile, 2, "ca-chain.pem holds the intermediate and the root")
	assert.Equal(t, chain.intermediate.Raw, chain.chainFile[0].Raw)
	assert.Equal(t, chain.root.Raw, chain.chainFile[1].Raw)

	assert.True(t, chain.intermediate.IsCA)
	assert.Equal(t, x509.ECDSA, chain.intermediate.PublicKeyAlgorithm, "the SPKI must remain classical")
	verifyConventionalChain(t, chain)

	rootAlt, found, err := util.GetAltPublicKeyFromCert(chain.root)
	require.NoError(t, err)
	require.True(t, found)
	intermediateAlt, found, err := util.GetAltPublicKeyFromCert(chain.intermediate)
	require.NoError(t, err)
	require.True(t, found, "the intermediate must carry its own ML-DSA key to sign the leaves")

	assert.NoError(t, util.VerifyAlternativeSignature(chain.intermediate, rootAlt),
		"the root signs the intermediate with its ML-DSA key")
	assert.NoError(t, util.VerifyAlternativeSignature(chain.leaf, intermediateAlt),
		"the intermediate signs the leaf with its ML-DSA key")
	assert.Error(t, util.VerifyAlternativeSignature(chain.leaf, rootAlt),
		"the leaf's alternative signature belongs to the intermediate, not to the root")
}

func TestPureMLDSAIntermediateCA(t *testing.T) {
	chain := startMLDSAChain(t, &api.KeyRequest{Algo: util.AlgoMLDSA, Size: 44})

	require.Len(t, chain.chainFile, 2, "ca-chain.pem holds the root and the intermediate")

	for name, cert := range map[string]*x509.Certificate{
		"intermediate": chain.intermediate,
		"leaf":         chain.leaf,
	} {
		assert.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm, "%s SPKI", name)
		assert.Equal(t, x509.MLDSA44, cert.SignatureAlgorithm, "%s signature", name)
		assert.False(t, util.HasAlternativeSignature(cert), "%s must not carry an alternative signature", name)
	}
	assert.True(t, chain.intermediate.IsCA)
	verifyConventionalChain(t, chain)
}
