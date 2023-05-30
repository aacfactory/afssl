package pkcs7

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/aacfactory/afssl/gmsm/pkcs"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"github.com/aacfactory/afssl/gmsm/smx509"
)

type signedEnvelopedData struct {
	Version                    int                        `asn1:"default:1"`
	RecipientInfos             []recipientInfo            `asn1:"set"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	EncryptedContentInfo       encryptedContentInfo
	Certificates               rawCertificates       `asn1:"optional,tag:0"`
	CRLs                       []x509.RevocationList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo          `asn1:"set"`
}

func (data signedEnvelopedData) GetRecipient(cert *smx509.Certificate) *recipientInfo {
	for _, recp := range data.RecipientInfos {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return &recp
		}
	}
	return nil
}

func (data signedEnvelopedData) GetEncryptedContentInfo() *encryptedContentInfo {
	return &data.EncryptedContentInfo
}

func parseSignedEnvelopedData(data []byte) (*PKCS7, error) {
	var sed signedEnvelopedData
	if _, err := asn1.Unmarshal(data, &sed); err != nil {
		return nil, err
	}
	certs, err := sed.Certificates.Parse()
	if err != nil {
		return nil, err
	}

	return &PKCS7{
		Certificates: certs,
		CRLs:         sed.CRLs,
		Signers:      sed.SignerInfos,
		raw:          sed}, nil
}

type VerifyFunc func() error

func (p7 *PKCS7) DecryptAndVerifyOnlyOne(pkey crypto.PrivateKey, verifyFunc VerifyFunc) ([]byte, error) {
	sed, ok := p7.raw.(signedEnvelopedData)
	if !ok {
		return nil, errors.New("pkcs7: it's NOT SignedAndEvelopedData")
	}
	if len(sed.RecipientInfos) != 1 {
		return nil, errors.New("pkcs7: more than one recipients or no receipient")
	}
	defer func() {
		p7.Content = nil
	}()
	plaintext, err := decryptSED(p7, &sed, &sed.RecipientInfos[0], pkey)
	if err != nil {
		return nil, err
	}
	if verifyFunc != nil {
		p7.Content = plaintext
		if err = verifyFunc(); err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

func (p7 *PKCS7) DecryptAndVerify(cert *smx509.Certificate, pkey crypto.PrivateKey, verifyFunc VerifyFunc) ([]byte, error) {
	sed, ok := p7.raw.(signedEnvelopedData)
	if !ok {
		return nil, errors.New("pkcs7: it's NOT SignedAndEvelopedData")
	}
	recipient := sed.GetRecipient(cert)
	if recipient == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	defer func() {
		p7.Content = nil
	}()
	plaintext, err := decryptSED(p7, &sed, recipient, pkey)
	if err != nil {
		return nil, err
	}
	if verifyFunc != nil {
		p7.Content = plaintext
		if err = verifyFunc(); err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

func decryptSED(p7 *PKCS7, sed *signedEnvelopedData, recipient *recipientInfo, pkey crypto.PrivateKey) ([]byte, error) {
	switch pkey := pkey.(type) {
	case crypto.Decrypter:
		// Generic case to handle anything that provides the crypto.Decrypter interface.
		contentKey, err := pkey.Decrypt(rand.Reader, recipient.EncryptedKey, nil)
		if err != nil {
			return nil, err
		}
		return sed.GetEncryptedContentInfo().decrypt(contentKey)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

type SignedAndEnvelopedData struct {
	sed       signedEnvelopedData
	certs     []*smx509.Certificate
	data, cek []byte
	digestOid asn1.ObjectIdentifier
	isSM      bool
}

func NewSignedAndEnvelopedData(data []byte, cipher pkcs.Cipher) (*SignedAndEnvelopedData, error) {
	var key []byte
	var err error

	key = make([]byte, cipher.KeySize())
	_, err = rand.Read(key)
	if err != nil {
		return nil, err
	}

	id, ciphertext, err := cipher.Encrypt(key, data)
	if err != nil {
		return nil, err
	}

	sed := signedEnvelopedData{
		Version: 1, // 0 or 1?
		EncryptedContentInfo: encryptedContentInfo{
			ContentType:                OIDData,
			ContentEncryptionAlgorithm: *id,
			EncryptedContent:           marshalEncryptedContent(ciphertext),
		},
	}
	return &SignedAndEnvelopedData{sed: sed, data: data, cek: key, digestOid: OIDDigestAlgorithmSHA1, isSM: false}, nil
}

func NewSMSignedAndEnvelopedData(data []byte, cipher pkcs.Cipher) (*SignedAndEnvelopedData, error) {
	sd, err := NewSignedAndEnvelopedData(data, cipher)
	if err != nil {
		return nil, err
	}
	sd.digestOid = OIDDigestAlgorithmSM3
	sd.isSM = true
	sd.sed.EncryptedContentInfo.ContentType = SM2OIDData
	return sd, nil
}

func (saed *SignedAndEnvelopedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
	saed.digestOid = d
}

func (saed *SignedAndEnvelopedData) AddSigner(ee *smx509.Certificate, pkey crypto.PrivateKey) error {
	var parents []*smx509.Certificate
	return saed.AddSignerChain(ee, pkey, parents)
}

func (saed *SignedAndEnvelopedData) AddSignerChain(ee *smx509.Certificate, pkey crypto.PrivateKey, parents []*smx509.Certificate) error {
	var ias issuerAndSerial
	ias.SerialNumber = ee.SerialNumber
	if len(parents) == 0 {
		// no parent, the issuer is the end-entity cert itself
		ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
	} else {
		err := verifyPartialChain(ee, parents)
		if err != nil {
			return err
		}
		// the first parent is the issuer
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
	}
	saed.sed.DigestAlgorithmIdentifiers = append(saed.sed.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: saed.digestOid},
	)
	hasher, err := getHashForOID(saed.digestOid)
	if err != nil {
		return err
	}

	signatureOid, err := getOIDForEncryptionAlgorithm(pkey, saed.digestOid)
	if err != nil {
		return err
	}
	key, ok := pkey.(crypto.Signer)
	if !ok {
		return errors.New("pkcs7: private key does not implement crypto.Signer")
	}
	var signOpt crypto.SignerOpts
	var tobeSigned []byte

	if saed.isSM {
		signOpt = sm2.DefaultSignerOpts
		tobeSigned = saed.data
	} else {
		signOpt = hasher
		h := newHash(hasher, saed.digestOid)
		h.Write(saed.data)
		tobeSigned = h.Sum(nil)
	}
	signature, err := key.Sign(rand.Reader, tobeSigned, signOpt)
	if err != nil {
		return err
	}
	signer := signerInfo{
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: saed.digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	saed.certs = append(saed.certs, ee)
	if len(parents) > 0 {
		saed.certs = append(saed.certs, parents...)
	}
	saed.sed.SignerInfos = append(saed.sed.SignerInfos, signer)
	return nil
}

func (saed *SignedAndEnvelopedData) AddCertificate(cert *smx509.Certificate) {
	saed.certs = append(saed.certs, cert)
}

func (saed *SignedAndEnvelopedData) AddRecipient(recipient *smx509.Certificate) error {
	encryptedKey, err := encryptKey(saed.cek, recipient)
	if err != nil {
		return err
	}
	ias, err := cert2issuerAndSerial(recipient)
	if err != nil {
		return err
	}
	var keyEncryptionAlgorithm = OIDEncryptionAlgorithmRSA
	if recipient.SignatureAlgorithm == smx509.SM2WithSM3 {
		keyEncryptionAlgorithm = OIDKeyEncryptionAlgorithmSM2
	} else if saed.isSM {
		return errors.New("pkcs7: Shangmi does not support RSA")
	}
	info := recipientInfo{
		Version:               1,
		IssuerAndSerialNumber: ias,
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: keyEncryptionAlgorithm,
		},
		EncryptedKey: encryptedKey,
	}
	saed.sed.RecipientInfos = append(saed.sed.RecipientInfos, info)
	return nil
}

func (saed *SignedAndEnvelopedData) Finish() ([]byte, error) {
	saed.sed.Certificates = marshalCertificates(saed.certs)
	inner, err := asn1.Marshal(saed.sed)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: OIDSignedEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	if saed.isSM {
		outer.ContentType = SM2OIDSignedEnvelopedData
	}
	return asn1.Marshal(outer)
}
