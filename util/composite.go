/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/pkg/errors"
)

// AlgoComposite pede um certificado Composite ML-DSA. O tamanho é o nível ML-DSA: 44, 65 ou 87.
const AlgoComposite = "composite"

var (
	oidSubjectKeyID   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
)

func IsCompositeKeyRequest(kr *csr.KeyRequest) bool {
	return kr != nil && kr.Algo() == AlgoComposite
}

func compositeKeyGenOpts(kr *csr.KeyRequest, ephemeral bool) (bccsp.KeyGenOpts, error) {
	level, err := MLDSALevel(kr.Size())
	if err != nil {
		return nil, err
	}
	alg, err := composite.AlgorithmForLevel(level)
	if err != nil {
		return nil, err
	}
	log.Debugf("Composite: key request size %d -> %s", kr.Size(), alg.Label)
	return &bccsp.CompositeKeyGenOpts{OID: alg.OID, Temporary: ephemeral}, nil
}

type authorityKeyIdentifier struct {
	ID []byte `asn1:"optional,tag:0"`
}

// RewriteAsCompositeCertificate transforma o rascunho que o cfssl emitiu com uma chave descartável
// no certificado composite. Troca o SPKI, o algoritmo de assinatura e os identificadores de chave,
// e assina o TBS inteiro com issuer. authorityKeyID substitui o AuthorityKeyId do rascunho, quando existe.
func RewriteAsCompositeCertificate(draftPEM []byte, subject *composite.PublicKey, issuer crypto.Signer, authorityKeyID []byte) ([]byte, error) {
	issuerPub, ok := issuer.Public().(*composite.PublicKey)
	if !ok {
		return nil, errors.Errorf("Composite certificate issuer must have a Composite ML-DSA key, got %T", issuer.Public())
	}
	block, _ := pem.Decode(draftPEM)
	if block == nil {
		return nil, errors.New("Failed to decode the draft certificate: not valid PEM")
	}
	draft, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to parse the draft certificate")
	}
	tbs, err := ParseTBSCertificate(draft.RawTBSCertificate)
	if err != nil {
		return nil, err
	}

	if tbs.SubjectPublicKeyInfo, err = composite.MarshalPKIXPublicKey(subject); err != nil {
		return nil, err
	}
	algID, err := composite.AlgorithmIdentifier(issuerPub.Algorithm)
	if err != nil {
		return nil, err
	}
	tbs.SignatureAlgorithm = algID

	skid, err := composite.SubjectKeyID(subject)
	if err != nil {
		return nil, err
	}
	skidValue, err := asn1.Marshal(skid)
	if err != nil {
		return nil, err
	}
	tbs.SetExtension(pkix.Extension{Id: oidSubjectKeyID, Value: skidValue})
	if _, found := tbs.Extension(oidAuthorityKeyID); found {
		if len(authorityKeyID) == 0 {
			return nil, errors.New("The draft certificate has an AuthorityKeyId but none was given for the composite issuer")
		}
		akidValue, err := asn1.Marshal(authorityKeyIdentifier{ID: authorityKeyID})
		if err != nil {
			return nil, err
		}
		tbs.SetExtension(pkix.Extension{Id: oidAuthorityKeyID, Value: akidValue})
	}

	tbsDER, err := tbs.Marshal()
	if err != nil {
		return nil, err
	}
	// Certificados usam ctx vazio.
	signature, err := issuer.Sign(rand.Reader, tbsDER, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to sign the composite certificate")
	}
	der, err := AssembleCertificate(tbsDER, algID, signature)
	if err != nil {
		return nil, err
	}
	log.Debugf("Composite: certificate '%s' signed with %s (%d bytes)", draft.Subject.CommonName, issuerPub.Algorithm.Label, len(der))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// GetCompositePrivateKey lê uma chave privada composite em PEM PKCS#8.
func GetCompositePrivateKey(raw []byte) (*composite.PrivateKey, error) {
	decoded, _ := pem.Decode(raw)
	if decoded == nil {
		return nil, errors.New("Failed to decode the PEM-encoded Composite ML-DSA key")
	}
	key, err := composite.ParsePKCS8PrivateKey(decoded.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed parsing Composite ML-DSA private key")
	}
	return key, nil
}
