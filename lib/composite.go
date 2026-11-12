/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/cloudflare/cfssl/crl"
	"github.com/cloudflare/cfssl/signer"
	cflocalsigner "github.com/cloudflare/cfssl/signer/local"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp/pkixext"
	"github.com/pkg/errors"
)

// signCertificate issues a certificate with the enrollSigner, or through the external path when the
// CA key is of a registered external algorithm, such as Composite ML-DSA or SLH-DSA.
func (ca *CA) signCertificate(req signer.SignRequest) ([]byte, error) {
	local, ok := ca.enrollSigner.(*cflocalsigner.Signer)
	if !ok {
		return ca.enrollSigner.Sign(req)
	}
	caCert, err := local.Certificate("", "ca")
	if err != nil {
		return nil, err
	}
	if caCert == nil || !pkixext.IsExternalPublicKey(caCert.RawSubjectPublicKeyInfo) {
		return ca.enrollSigner.Sign(req)
	}
	return ca.signExternalCertificate(req, caCert)
}

// signExternalCertificate has cfssl issue a draft signed by a throwaway ECDSA key, created for this
// issuance, and rewrites the draft with the signature of the CA key. The draft carries the issuer
// and the AuthorityKeyId of the CA.
func (ca *CA) signExternalCertificate(req signer.SignRequest, caCert *x509.Certificate) ([]byte, error) {
	_, caSigner, _, err := util.GetSignerFromCertFile(ca.Config.CA.Certfile, ca.csp)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to load the CA signer")
	}
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to generate the throwaway key for the draft certificate")
	}
	subject, draftCSR, err := util.ExternalDraftRequest([]byte(req.Request), throwaway)
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

	cert, err := util.RewriteAsExternalCertificate(draft, subject, caSigner, caCert.SubjectKeyId)
	if err != nil {
		return nil, err
	}
	if err = ca.certDBAccessor.UpdateCertificatePEM(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// createCRL generates the DER CRL with cfssl. With a key of a registered external algorithm, cfssl
// signs with a throwaway ECDSA key and the CRL is rewritten with the signature of the CA key.
func createCRL(revoked []pkix.RevokedCertificate, caSigner crypto.Signer, caCert *x509.Certificate, expiry time.Time) ([]byte, error) {
	if _, ok := pkixext.SchemeForKey(caSigner.Public()); !ok {
		return crl.CreateGenericCRL(revoked, caSigner, caCert, expiry)
	}
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to generate the throwaway key for the draft CRL")
	}
	draft, err := crl.CreateGenericCRL(revoked, throwaway, caCert, expiry)
	if err != nil {
		return nil, err
	}
	return util.RewriteAsExternalCRL(draft, caSigner)
}
