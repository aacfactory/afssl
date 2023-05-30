package pkcs7

import (
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/aacfactory/afssl/gmsm/smx509"
)

func (p7 *PKCS7) Verify() (err error) {
	return p7.VerifyWithChain(nil)
}

func (p7 *PKCS7) VerifyWithChain(truststore *smx509.CertPool) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer, truststore, nil); err != nil {
			return err
		}
	}
	return nil
}

func (p7 *PKCS7) VerifyWithChainAtTime(truststore *smx509.CertPool, currentTime *time.Time) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer, truststore, currentTime); err != nil {
			return err
		}
	}
	return nil
}

func verifySignature(p7 *PKCS7, signer signerInfo, truststore *smx509.CertPool, currentTime *time.Time) (err error) {
	signedData := p7.Content
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		return errors.New("pkcs7: No certificate for signer")
	}
	signingTime := time.Now().UTC()
	if len(signer.AuthenticatedAttributes) > 0 {
		// TODO(fullsailor): First check the content type match
		var digest []byte
		err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest)
		if err != nil {
			return err
		}
		hasher, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
		if err != nil {
			return err
		}
		h := newHash(hasher, signer.DigestAlgorithm.Algorithm)
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if subtle.ConstantTimeCompare(digest, computed) != 1 {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}
		signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
		err = unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime)
		if err == nil {
			// signing time found, performing validity check
			if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
				return fmt.Errorf("pkcs7: signing time %q is outside of certificate validity %q to %q",
					signingTime.Format(time.RFC3339),
					ee.NotBefore.Format(time.RFC3339),
					ee.NotAfter.Format(time.RFC3339))
			}
		}
	}
	if truststore != nil {
		if currentTime != nil {
			signingTime = *currentTime
		}
		_, err = verifyCertChain(ee, p7.Certificates, truststore, signingTime)
		if err != nil {
			return err
		}
	}
	sigalg, err := getSignatureAlgorithm(signer.DigestEncryptionAlgorithm, signer.DigestAlgorithm)
	if err != nil {
		return err
	}
	return ee.CheckSignature(smx509.SignatureAlgorithm(sigalg), signedData, signer.EncryptedDigest)
}

func (p7 *PKCS7) GetOnlySigner() *smx509.Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

func parseSignedData(data []byte) (*PKCS7, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	// Compound octet string
	if compound.IsCompound && compound.Tag == 4 {
		if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
			return nil, err
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

func verifyCertChain(ee *smx509.Certificate, certs []*smx509.Certificate, truststore *smx509.CertPool, currentTime time.Time) (chains [][]*smx509.Certificate, err error) {
	intermediates := smx509.NewCertPool()
	for _, intermediate := range certs {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := smx509.VerifyOptions{
		Roots:         truststore,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   currentTime,
	}
	chains, err = ee.Verify(verifyOptions)
	if err != nil {
		return chains, fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
	}
	return
}

type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

func getSignatureAlgorithm(digestEncryption, digest pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, error) {
	switch {
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA1):
		return x509.ECDSAWithSHA1, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA256):
		return x509.ECDSAWithSHA256, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA384):
		return x509.ECDSAWithSHA384, nil
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmECDSASHA512):
		return x509.ECDSAWithSHA512, nil
	case digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSA),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA1),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA256),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA384),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmRSASHA512):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1):
			return x509.SHA1WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return x509.SHA256WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA384):
			return x509.SHA384WithRSA, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA512):
			return x509.SHA512WithRSA, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDDigestAlgorithmDSA),
		digestEncryption.Algorithm.Equal(OIDDigestAlgorithmDSASHA1):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1):
			return x509.DSAWithSHA1, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return x509.DSAWithSHA256, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP256),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP384),
		digestEncryption.Algorithm.Equal(OIDEncryptionAlgorithmECDSAP521):
		switch {
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA1):
			return x509.ECDSAWithSHA1, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA256):
			return x509.ECDSAWithSHA256, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA384):
			return x509.ECDSAWithSHA384, nil
		case digest.Algorithm.Equal(OIDDigestAlgorithmSHA512):
			return x509.ECDSAWithSHA512, nil
		default:
			return -1, fmt.Errorf("pkcs7: unsupported digest %q for encryption algorithm %q",
				digest.Algorithm.String(), digestEncryption.Algorithm.String())
		}
	case digestEncryption.Algorithm.Equal(OIDDigestEncryptionAlgorithmSM2):
		return smx509.SM2WithSM3, nil
	default:
		return -1, fmt.Errorf("pkcs7: unsupported algorithm %q",
			digestEncryption.Algorithm.String())
	}
}

func getCertFromCertsByIssuerAndSerial(certs []*smx509.Certificate, ias issuerAndSerial) *smx509.Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return errors.New("pkcs7: attribute type not in attributes")
}
