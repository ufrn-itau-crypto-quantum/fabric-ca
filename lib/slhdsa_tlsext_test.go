//go:build tlsext

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"crypto/x509"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	stls "github.com/hyperledger/fabric-ca/lib/tls"
)

// TestSLHDSATLSLeaf is TestSLHDSATLSPKI with SLH-DSA TLS leaves, the default of phase 10: it needs
// the go-tlsext toolchain and the tlsext tag, which register SLH-DSA in crypto/tls.
func TestSLHDSATLSLeaf(t *testing.T) {
	testTLSPKI(t, &api.KeyRequest{Algo: "slhdsa-sha2-f", Size: 128}, stls.KeyRequest{Algo: "slhdsa-sha2-f", Size: 128},
		x509.UnknownPublicKeyAlgorithm)
}

// TestCompositeTLSLeaf runs the TLS PKI with composite root, intermediate and leaves, for an ML-DSA
// and an SLH-DSA pair, which needs the composite pairs registered in crypto/tls.
func TestCompositeTLSLeaf(t *testing.T) {
	for _, kr := range []api.KeyRequest{{Algo: "composite", Size: 44}, {Algo: "composite-slhdsa-sha2-f", Size: 128}} {
		testTLSPKI(t, &kr, stls.KeyRequest{Algo: kr.Algo, Size: kr.Size}, x509.UnknownPublicKeyAlgorithm)
	}
}
