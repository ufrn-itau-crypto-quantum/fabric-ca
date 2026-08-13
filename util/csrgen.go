/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/mail"
	"net/url"

	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

// GenerateCSR creates a PEM encoded CSR from a CertificateRequest and an existing key.
//
// It replaces cfssl's csr.Generate, which cannot be used with an ML-DSA key: it starts by
// calling helpers.SignerAlgo, which knows only RSA and ECDSA and returns
// UnknownSignatureAlgorithm for anything else, and then hard-fails on that value. The rest of
// this function is a faithful copy of csr.GenerateDER/csr.Generate; only the signature
// algorithm decision differs. Patching the vendored cfssl was avoided on purpose, the same way
// newSelfSignedCACert replicates initca.NewFromSigner instead of changing it.
func GenerateCSR(priv crypto.Signer, req *csr.CertificateRequest) ([]byte, error) {
	der, err := generateCSRDER(priv, req)
	if err != nil {
		return nil, err
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	log.Info("encoded CSR")
	return pem.EncodeToMemory(&block), nil
}

func generateCSRDER(priv crypto.Signer, req *csr.CertificateRequest) ([]byte, error) {
	sigAlgo, err := csrSigAlgo(priv)
	if err != nil {
		return nil, err
	}

	subj, err := req.Name()
	if err != nil {
		return nil, err
	}

	tpl := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: sigAlgo,
	}

	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else if uri, err := url.ParseRequestURI(req.Hosts[i]); err == nil && uri != nil {
			tpl.URIs = append(tpl.URIs, uri)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	tpl.ExtraExtensions = []pkix.Extension{}

	if req.CA != nil {
		if err := appendCAInfoToCSR(req.CA, &tpl); err != nil {
			return nil, cferr.Wrap(cferr.CSRError, cferr.GenerationFailed, err)
		}
	}

	if req.DelegationEnabled {
		// cfssl appends to tpl.Extensions here, which x509.CreateCertificateRequest ignores;
		// ExtraExtensions is the field that reaches the CSR. fabric-ca never enables
		// delegation, so this is a difference on a path nothing exercises.
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, helpers.DelegationExtension)
	}

	tpl.ExtraExtensions = append(tpl.ExtraExtensions, req.Extensions...)

	der, err := x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		log.Errorf("failed to generate a CSR: %v", err)
		return nil, cferr.Wrap(cferr.CSRError, cferr.BadRequest, err)
	}
	return der, nil
}

// csrSigAlgo picks the signature algorithm for a CSR.
//
// For an ML-DSA key it returns the zero value on purpose: crypto/x509 derives the algorithm
// from the key's parameter set (signingParamsForKey maps MLDSA44/65/87), and there is no
// choice to make, since a given parameter set admits exactly one signature algorithm.
func csrSigAlgo(priv crypto.Signer) (x509.SignatureAlgorithm, error) {
	if sigAlgo := helpers.SignerAlgo(priv); sigAlgo != x509.UnknownSignatureAlgorithm {
		return sigAlgo, nil
	}
	if _, ok := priv.Public().(*mldsa.PublicKey); ok {
		return x509.UnknownSignatureAlgorithm, nil
	}
	return x509.UnknownSignatureAlgorithm, cferr.New(cferr.PrivateKeyError, cferr.Unavailable)
}

// appendCAInfoToCSR appends the BasicConstraints extension derived from the CA config, as
// cfssl's unexported function of the same name does.
func appendCAInfoToCSR(reqConf *csr.CAConfig, req *x509.CertificateRequest) error {
	pathlen := reqConf.PathLength
	if pathlen == 0 && !reqConf.PathLenZero {
		pathlen = -1
	}
	val, err := asn1.Marshal(csr.BasicConstraints{IsCA: true, MaxPathLen: pathlen})
	if err != nil {
		return err
	}

	req.ExtraExtensions = append(req.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Value:    val,
		Critical: true,
	})

	return nil
}
