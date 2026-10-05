/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/cloudflare/cfssl/signer"
	cflocalsigner "github.com/cloudflare/cfssl/signer/local"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/pkg/errors"
)

// signCertificate emite um certificado com o enrollSigner, ou pelo caminho composite quando a
// chave da CA é Composite ML-DSA.
func (ca *CA) signCertificate(req signer.SignRequest) ([]byte, error) {
	local, ok := ca.enrollSigner.(*cflocalsigner.Signer)
	if !ok {
		return ca.enrollSigner.Sign(req)
	}
	caCert, err := local.Certificate("", "ca")
	if err != nil {
		return nil, err
	}
	if caCert == nil || !composite.IsPKIXPublicKey(caCert.RawSubjectPublicKeyInfo) {
		return ca.enrollSigner.Sign(req)
	}
	return ca.signCompositeCertificate(req, caCert)
}

// signCompositeCertificate emite com o cfssl um rascunho assinado por uma chave ECDSA descartável,
// criada para esta emissão, e reescreve o rascunho com a assinatura composite da CA. O rascunho sai
// com o emissor e o AuthorityKeyId da CA.
func (ca *CA) signCompositeCertificate(req signer.SignRequest, caCert *x509.Certificate) ([]byte, error) {
	_, caSigner, _, err := util.GetSignerFromCertFile(ca.Config.CA.Certfile, ca.csp)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to load the composite CA signer")
	}
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to generate the throwaway key for the draft certificate")
	}
	subject, draftCSR, err := util.CompositeDraftRequest([]byte(req.Request), throwaway)
	if err != nil {
		return nil, err
	}
	req.Request = string(draftCSR)

	draftSigner, err := cflocalsigner.NewSigner(throwaway, caCert, x509.ECDSAWithSHA256, ca.enrollSigner.Policy())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create the draft signer")
	}
	draftSigner.SetDBAccessor(ca.certDBAccessor)
	draft, err := draftSigner.Sign(req)
	if err != nil {
		return nil, err
	}

	cert, err := util.RewriteAsCompositeCertificate(draft, subject, caSigner, caCert.SubjectKeyId)
	if err != nil {
		return nil, err
	}
	if err = ca.certDBAccessor.UpdateCertificatePEM(cert); err != nil {
		return nil, err
	}
	return cert, nil
}
