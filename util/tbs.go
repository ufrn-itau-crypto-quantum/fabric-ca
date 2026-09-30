/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

// Assembly of a tbsCertificate outside the happy path of crypto/x509.
//
// Both post-quantum certificate designs the project pursues need to sign a tbsCertificate that
// x509.CreateCertificate will not produce on its own:
//
//   - the ITU-T alternative-signature design signs a PreTBSCertificate, which is the
//     tbsCertificate without the signature field and without the altSignatureValue extension;
//   - the composite design signs a tbsCertificate whose algorithm identifiers crypto/x509 does
//     not recognise, and therefore refuses to build or sign.
//
// Every field is kept as the raw DER element read from the input, so re-encoding an unmodified
// TBSCertificate reproduces the input byte for byte. That property is what makes it safe to
// sign a re-encoded structure: a signature over bytes that differ from what the verifier will
// reconstruct is silently invalid.

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Context-specific tags of the optional tbsCertificate fields, per RFC 5280 §4.1.
var (
	tagVersion         = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagIssuerUniqueID  = cbasn1.Tag(1).ContextSpecific()
	tagSubjectUniqueID = cbasn1.Tag(2).ContextSpecific()
	tagExtensions      = cbasn1.Tag(3).Constructed().ContextSpecific()
)

// TBSCertificate is a parsed tbsCertificate whose fields are kept as raw DER elements, each one
// including its own tag and length. A nil field is one that was absent from the input.
//
// Extensions are the exception: they are parsed, because both designs need to add and remove
// them. Re-encoding relies on the input following DER, where a critical flag of false is
// absent rather than encoded; a certificate that encodes it explicitly would not round-trip.
type TBSCertificate struct {
	Version              []byte
	SerialNumber         []byte
	SignatureAlgorithm   []byte
	Issuer               []byte
	Validity             []byte
	Subject              []byte
	SubjectPublicKeyInfo []byte
	IssuerUniqueID       []byte
	SubjectUniqueID      []byte
	Extensions           []pkix.Extension
}

// ParseTBSCertificate parses the DER of a tbsCertificate, as found in
// x509.Certificate.RawTBSCertificate.
func ParseTBSCertificate(der []byte) (*TBSCertificate, error) {
	input := cryptobyte.String(der)

	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, errors.New("Malformed tbsCertificate: not a SEQUENCE")
	}
	if !input.Empty() {
		return nil, errors.New("Trailing data after the tbsCertificate")
	}

	out := &TBSCertificate{}

	if tbs.PeekASN1Tag(tagVersion) {
		if out.Version = readElement(&tbs, tagVersion); out.Version == nil {
			return nil, errors.New("Malformed tbsCertificate: version")
		}
	}

	for _, field := range []struct {
		name string
		tag  cbasn1.Tag
		dest *[]byte
	}{
		{"serialNumber", cbasn1.INTEGER, &out.SerialNumber},
		{"signature", cbasn1.SEQUENCE, &out.SignatureAlgorithm},
		{"issuer", cbasn1.SEQUENCE, &out.Issuer},
		{"validity", cbasn1.SEQUENCE, &out.Validity},
		{"subject", cbasn1.SEQUENCE, &out.Subject},
		{"subjectPublicKeyInfo", cbasn1.SEQUENCE, &out.SubjectPublicKeyInfo},
	} {
		if *field.dest = readElement(&tbs, field.tag); *field.dest == nil {
			return nil, errors.Errorf("Malformed tbsCertificate: %s", field.name)
		}
	}

	if tbs.PeekASN1Tag(tagIssuerUniqueID) {
		out.IssuerUniqueID = readElement(&tbs, tagIssuerUniqueID)
	}
	if tbs.PeekASN1Tag(tagSubjectUniqueID) {
		out.SubjectUniqueID = readElement(&tbs, tagSubjectUniqueID)
	}

	if tbs.PeekASN1Tag(tagExtensions) {
		var wrapper, list cryptobyte.String
		if !tbs.ReadASN1(&wrapper, tagExtensions) || !wrapper.ReadASN1(&list, cbasn1.SEQUENCE) {
			return nil, errors.New("Malformed tbsCertificate: extensions")
		}
		for !list.Empty() {
			element := readElement(&list, cbasn1.SEQUENCE)
			if element == nil {
				return nil, errors.New("Malformed tbsCertificate: extension element")
			}
			var ext pkix.Extension
			if _, err := asn1.Unmarshal(element, &ext); err != nil {
				return nil, errors.WithMessage(err, "Failed to parse a certificate extension")
			}
			out.Extensions = append(out.Extensions, ext)
		}
	}

	if !tbs.Empty() {
		return nil, errors.New("Trailing data inside the tbsCertificate")
	}
	return out, nil
}

func readElement(s *cryptobyte.String, tag cbasn1.Tag) []byte {
	var element cryptobyte.String
	if !s.ReadASN1Element(&element, tag) {
		return nil
	}
	return append([]byte(nil), element...)
}

// Marshal encodes the tbsCertificate, including the signature field.
func (t *TBSCertificate) Marshal() ([]byte, error) {
	return t.marshal(true, nil)
}

// MarshalPreTBS encodes the PreTBSCertificate that the ITU-T alternative signature is computed
// over: the tbsCertificate without the signature field and without the extension named by
// omitExtension, which is the one about to receive the resulting signature.
//
// Dropping the signature field is not an optimisation, it is part of the definition. Signing a
// structure that still carries it produces a signature the verifier cannot reproduce, because
// the verifier rebuilds the PreTBSCertificate from the issued certificate.
//
// The result is not accepted by ParseTBSCertificate. Without the signature field the issuer
// takes its position, both are SEQUENCE, and the positional read cannot tell them apart. A
// PreTBSCertificate is only ever produced to be signed or verified, never parsed back.
func (t *TBSCertificate) MarshalPreTBS(omitExtension asn1.ObjectIdentifier) ([]byte, error) {
	return t.marshal(false, omitExtension)
}

func (t *TBSCertificate) marshal(withSignatureAlgorithm bool, omitExtension asn1.ObjectIdentifier) ([]byte, error) {
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"serialNumber", t.SerialNumber},
		{"issuer", t.Issuer},
		{"validity", t.Validity},
		{"subject", t.Subject},
		{"subjectPublicKeyInfo", t.SubjectPublicKeyInfo},
	} {
		if len(field.value) == 0 {
			return nil, errors.Errorf("tbsCertificate is missing the %s field", field.name)
		}
	}
	if withSignatureAlgorithm && len(t.SignatureAlgorithm) == 0 {
		return nil, errors.New("tbsCertificate is missing the signature field")
	}

	extensions := t.Extensions
	if omitExtension != nil {
		extensions = make([]pkix.Extension, 0, len(t.Extensions))
		for _, ext := range t.Extensions {
			if !ext.Id.Equal(omitExtension) {
				extensions = append(extensions, ext)
			}
		}
	}

	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
		tbs.AddBytes(t.Version)
		tbs.AddBytes(t.SerialNumber)
		if withSignatureAlgorithm {
			tbs.AddBytes(t.SignatureAlgorithm)
		}
		tbs.AddBytes(t.Issuer)
		tbs.AddBytes(t.Validity)
		tbs.AddBytes(t.Subject)
		tbs.AddBytes(t.SubjectPublicKeyInfo)
		tbs.AddBytes(t.IssuerUniqueID)
		tbs.AddBytes(t.SubjectUniqueID)

		if len(extensions) == 0 {
			return
		}
		tbs.AddASN1(tagExtensions, func(wrapper *cryptobyte.Builder) {
			wrapper.AddASN1(cbasn1.SEQUENCE, func(list *cryptobyte.Builder) {
				for _, ext := range extensions {
					encoded, err := asn1.Marshal(ext)
					if err != nil {
						list.SetError(err)
						return
					}
					list.AddBytes(encoded)
				}
			})
		})
	})
	return builder.Bytes()
}

// Extension returns the extension carrying the given OID.
func (t *TBSCertificate) Extension(oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, ext := range t.Extensions {
		if ext.Id.Equal(oid) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}

// SetExtension adds an extension, replacing any existing one with the same OID.
func (t *TBSCertificate) SetExtension(ext pkix.Extension) {
	for i, existing := range t.Extensions {
		if existing.Id.Equal(ext.Id) {
			t.Extensions[i] = ext
			return
		}
	}
	t.Extensions = append(t.Extensions, ext)
}

// RemoveExtension drops the extension carrying the given OID, and reports whether it was there.
func (t *TBSCertificate) RemoveExtension(oid asn1.ObjectIdentifier) bool {
	for i, ext := range t.Extensions {
		if ext.Id.Equal(oid) {
			t.Extensions = append(t.Extensions[:i], t.Extensions[i+1:]...)
			return true
		}
	}
	return false
}

// AssembleCertificate builds the DER of a Certificate from a tbsCertificate, the outer
// AlgorithmIdentifier and a signature computed elsewhere.
//
// It exists because x509.CreateCertificate signs with an algorithm of its own choosing and
// refuses one it does not recognise, which is exactly the case of a composite algorithm. The
// algorithm identifier must be the same one encoded in the tbsCertificate signature field;
// RFC 5280 §4.1.1.2 requires the two to match, and a verifier that checks it rejects the
// certificate otherwise.
func AssembleCertificate(tbsDER, algorithmIdentifierDER, signature []byte) ([]byte, error) {
	if len(tbsDER) == 0 || len(algorithmIdentifierDER) == 0 || len(signature) == 0 {
		return nil, errors.New("Certificate assembly requires a tbsCertificate, an algorithm identifier and a signature")
	}

	builder := cryptobyte.NewBuilder(nil)
	builder.AddASN1(cbasn1.SEQUENCE, func(cert *cryptobyte.Builder) {
		cert.AddBytes(tbsDER)
		cert.AddBytes(algorithmIdentifierDER)
		cert.AddASN1BitString(signature)
	})
	return builder.Bytes()
}
