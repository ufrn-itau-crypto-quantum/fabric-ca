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
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var oidTestExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}

func testCert(t *testing.T, signer crypto.Signer, extra ...pkix.Extension) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "tbs-test", Organization: []string{"Hyperledger"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"peer0"},
		ExtraExtensions:       extra,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func signers(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ml, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	return map[string]crypto.Signer{"ecdsa-p256": ec, "ml-dsa-44": ml}
}

// TestTBSRoundTrip pins the property the whole file rests on: re-encoding an unmodified
// TBSCertificate reproduces the input byte for byte.
//
// Without it, signing a re-encoded structure would be unsafe — the verifier rebuilds the
// structure from the issued certificate, and a single differing byte makes the signature fail
// with no indication of why.
func TestTBSRoundTrip(t *testing.T) {
	hybridExt := pkix.Extension{Id: oidTestExtension, Value: []byte("alternative key material")}

	for name, signer := range signers(t) {
		for _, withExt := range []bool{false, true} {
			label := name
			var extra []pkix.Extension
			if withExt {
				label += "+extensao"
				extra = []pkix.Extension{hybridExt}
			}
			t.Run(label, func(t *testing.T) {
				cert := testCert(t, signer, extra...)

				tbs, err := ParseTBSCertificate(cert.RawTBSCertificate)
				require.NoError(t, err)

				encoded, err := tbs.Marshal()
				require.NoError(t, err)
				assert.Equal(t, cert.RawTBSCertificate, encoded)
			})
		}
	}
}

// TestAssembleCertificateIsVerifiable takes a certificate apart and puts it back together from
// its raw pieces, then asks crypto/x509 to validate the signature over the result. It is the
// end-to-end check that the assembly produces a certificate a real verifier accepts.
func TestAssembleCertificateIsVerifiable(t *testing.T) {
	for name, signer := range signers(t) {
		t.Run(name, func(t *testing.T) {
			cert := testCert(t, signer)

			tbs, err := ParseTBSCertificate(cert.RawTBSCertificate)
			require.NoError(t, err)
			tbsDER, err := tbs.Marshal()
			require.NoError(t, err)

			// RFC 5280 4.1.1.2: the outer identifier repeats the one inside the TBS.
			rebuilt, err := AssembleCertificate(tbsDER, tbs.SignatureAlgorithm, cert.Signature)
			require.NoError(t, err)
			assert.Equal(t, cert.Raw, rebuilt)

			parsed, err := x509.ParseCertificate(rebuilt)
			require.NoError(t, err)
			assert.NoError(t, parsed.CheckSignatureFrom(parsed))
		})
	}
}

// TestMarshalPreTBS covers the structure the ITU-T alternative signature is computed over: the
// tbsCertificate without the signature field and without the extension that will carry the
// signature.
func TestMarshalPreTBS(t *testing.T) {
	altValue := pkix.Extension{Id: oidTestExtension, Value: []byte("previous signature")}
	keep := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 72}, Value: []byte("alt public key")}

	cert := testCert(t, mustECDSA(t), keep, altValue)
	tbs, err := ParseTBSCertificate(cert.RawTBSCertificate)
	require.NoError(t, err)

	pre, err := tbs.MarshalPreTBS(oidTestExtension)
	require.NoError(t, err)

	// O PreTBSCertificate nao e reparseavel por ParseTBSCertificate: sem o campo signature, o
	// issuer ocupa a posicao dele e os dois sao SEQUENCE, entao a leitura posicional nao os
	// distingue. A conferencia e feita sobre os bytes.
	var outer cryptobyte.String
	input := cryptobyte.String(pre)
	require.True(t, input.ReadASN1(&outer, cbasn1.SEQUENCE), "o PreTBS deve ser um SEQUENCE valido")
	require.True(t, input.Empty())

	assert.NotContains(t, string(pre), string(tbs.SignatureAlgorithm),
		"o campo signature deve sair do PreTBSCertificate")

	omitted, err := asn1.Marshal(altValue)
	require.NoError(t, err)
	assert.NotContains(t, string(pre), string(omitted),
		"a extensao da assinatura alternativa deve sair")

	preserved, err := asn1.Marshal(keep)
	require.NoError(t, err)
	assert.Contains(t, string(pre), string(preserved), "as demais extensoes devem permanecer")

	for name, field := range map[string][]byte{
		"serialNumber": tbs.SerialNumber,
		"subject":      tbs.Subject,
		"spki":         tbs.SubjectPublicKeyInfo,
	} {
		assert.Contains(t, string(pre), string(field), "%s deve permanecer", name)
	}
	assert.Less(t, len(pre), len(cert.RawTBSCertificate))
}

// TestPreTBSChangesWithContent guards the signing input: any change to the certificate must
// change the bytes that get signed, or a signature would carry over to a different certificate.
func TestPreTBSChangesWithContent(t *testing.T) {
	signer := mustECDSA(t)
	tbsOf := func(cert *x509.Certificate) []byte {
		parsed, err := ParseTBSCertificate(cert.RawTBSCertificate)
		require.NoError(t, err)
		pre, err := parsed.MarshalPreTBS(oidTestExtension)
		require.NoError(t, err)
		return pre
	}

	first := tbsOf(testCert(t, signer))
	second := tbsOf(testCert(t, signer, pkix.Extension{Id: oidTestExtension, Value: []byte("x")}))
	assert.Equal(t, first, second, "só a extensão omitida mudou, o PreTBS deve ser igual")

	third := tbsOf(testCert(t, signer, pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 72}, Value: []byte("alt key"),
	}))
	assert.NotEqual(t, first, third, "uma extensão preservada deve mudar o PreTBS")
}

func TestExtensionHelpers(t *testing.T) {
	tbs := &TBSCertificate{}
	first := pkix.Extension{Id: oidTestExtension, Value: []byte("a")}

	tbs.SetExtension(first)
	got, present := tbs.Extension(oidTestExtension)
	require.True(t, present)
	assert.Equal(t, []byte("a"), got.Value)

	tbs.SetExtension(pkix.Extension{Id: oidTestExtension, Value: []byte("b")})
	assert.Len(t, tbs.Extensions, 1, "SetExtension substitui, não duplica")
	got, _ = tbs.Extension(oidTestExtension)
	assert.Equal(t, []byte("b"), got.Value)

	assert.True(t, tbs.RemoveExtension(oidTestExtension))
	assert.False(t, tbs.RemoveExtension(oidTestExtension))
	assert.Empty(t, tbs.Extensions)
}

func TestParseTBSCertificateRejectsGarbage(t *testing.T) {
	for name, input := range map[string][]byte{
		"vazio":             {},
		"nao e sequence":    {0x02, 0x01, 0x00},
		"sequence truncada": {0x30, 0x10, 0x02, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTBSCertificate(input)
			assert.Error(t, err)
		})
	}
}

func mustECDSA(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}
