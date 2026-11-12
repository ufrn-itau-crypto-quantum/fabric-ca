/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"strings"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/composite"
	"github.com/hyperledger/fabric-lib-go/bccsp/slhdsa"
	"github.com/pkg/errors"
)

// Key request algorithms for SLH-DSA. The hash family and the variant are in the algorithm and the
// security level (128, 192 or 256) is the size, as in "slhdsa-sha2-s" with size 128.
const (
	AlgoSLHDSAPrefix          = "slhdsa-"
	AlgoCompositeSLHDSAPrefix = "composite-slhdsa-"
)

// slhdsaKeyRequest maps a key request onto its SLH-DSA parameter set and reports whether it asks
// for the composite pair. The algorithm is [composite-]slhdsa-{sha2,shake}-{s,f}; composite pairs
// exist only for SHA2.
func slhdsaKeyRequest(kr *csr.KeyRequest) (slhdsa.ParameterSet, bool, error) {
	algo := kr.Algo()
	isComposite := strings.HasPrefix(algo, AlgoCompositeSLHDSAPrefix)
	rest, ok := strings.CutPrefix(algo, AlgoSLHDSAPrefix)
	if isComposite {
		rest, ok = strings.CutPrefix(algo, AlgoCompositeSLHDSAPrefix)
	}
	if !ok {
		return slhdsa.ParameterSet{}, false, errors.Errorf("Not an SLH-DSA algorithm: %s", algo)
	}
	hash, variant, ok := strings.Cut(rest, "-")
	if !ok || (hash != "sha2" && hash != "shake") || (variant != "s" && variant != "f") {
		return slhdsa.ParameterSet{}, false, errors.Errorf("Invalid SLH-DSA algorithm %s (expecting [composite-]slhdsa-{sha2,shake}-{s,f})", algo)
	}
	switch kr.Size() {
	case 128, 192, 256:
	default:
		return slhdsa.ParameterSet{}, false, errors.Errorf("Invalid SLH-DSA key size: %d (expecting 128, 192 or 256)", kr.Size())
	}
	name := fmt.Sprintf("SLH-DSA-%s-%d%s", strings.ToUpper(hash), kr.Size(), variant)
	for _, ps := range slhdsa.ParameterSets() {
		if ps.Name == name {
			return ps, isComposite, nil
		}
	}
	return slhdsa.ParameterSet{}, false, errors.Errorf("Unknown SLH-DSA parameter set %s", name)
}

func IsSLHDSAKeyRequest(kr *csr.KeyRequest) bool {
	if kr == nil {
		return false
	}
	_, _, err := slhdsaKeyRequest(kr)
	return err == nil
}

func slhdsaKeyGenOpts(kr *csr.KeyRequest, ephemeral bool) (bccsp.KeyGenOpts, error) {
	ps, isComposite, err := slhdsaKeyRequest(kr)
	if err != nil {
		return nil, err
	}
	if !isComposite {
		log.Debugf("SLH-DSA: key request %s-%d -> %s", kr.Algo(), kr.Size(), ps.Name)
		return &bccsp.SLHDSAKeyGenOpts{OID: ps.OID, Temporary: ephemeral}, nil
	}
	alg, err := composite.AlgorithmForSLHDSA(ps)
	if err != nil {
		return nil, err
	}
	log.Debugf("Composite: key request %s-%d -> %s", kr.Algo(), kr.Size(), alg.Label)
	return &bccsp.CompositeKeyGenOpts{OID: alg.OID, Temporary: ephemeral}, nil
}
