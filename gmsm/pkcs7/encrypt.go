package pkcs7

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/aacfactory/afssl/gmsm/pkcs"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"github.com/aacfactory/afssl/gmsm/smx509"
)

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

func (data envelopedData) GetRecipient(cert *smx509.Certificate) *recipientInfo {
	for _, recp := range data.RecipientInfos {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return &recp
		}
	}
	return nil
}

func (data envelopedData) GetEncryptedContentInfo() *encryptedContentInfo {
	return &data.EncryptedContentInfo
}

var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC, AES-CBC, AES-GCM, SM4-CBC and SM4-GCM supported")

var ErrPSKNotProvided = errors.New("pkcs7: cannot encrypt content: PSK not provided")

func Encrypt(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return encrypt(cipher, content, recipients, false)
}

func EncryptSM(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return encrypt(cipher, content, recipients, true)
}

func encrypt(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate, isSM bool) ([]byte, error) {
	var key []byte
	var err error

	key = make([]byte, cipher.KeySize())
	_, err = rand.Read(key)
	if err != nil {
		return nil, err
	}

	id, ciphertext, err := cipher.Encrypt(key, content)
	if err != nil {
		return nil, err
	}

	envelope := envelopedData{
		Version: 0,
		EncryptedContentInfo: encryptedContentInfo{
			ContentType:                OIDData,
			ContentEncryptionAlgorithm: *id,
			EncryptedContent:           marshalEncryptedContent(ciphertext),
		},
	}

	if isSM {
		envelope.EncryptedContentInfo.ContentType = SM2OIDData
	}

	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKey(key, recipient)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}
		var keyEncryptionAlgorithm = OIDEncryptionAlgorithmRSA
		if recipient.SignatureAlgorithm == smx509.SM2WithSM3 {
			keyEncryptionAlgorithm = OIDKeyEncryptionAlgorithmSM2
		} else if isSM {
			return nil, errors.New("pkcs7: Shangmi does not support RSA")
		}

		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: keyEncryptionAlgorithm,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	envelope.RecipientInfos = recipientInfos

	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	wrapper := contentInfo{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	if isSM {
		wrapper.ContentType = SM2OIDEnvelopedData
	}

	return asn1.Marshal(wrapper)
}

func EncryptUsingPSK(cipher pkcs.Cipher, content []byte, key []byte) ([]byte, error) {
	return encryptUsingPSK(false, cipher, content, key)
}

func EncryptSMUsingPSK(cipher pkcs.Cipher, content []byte, key []byte) ([]byte, error) {
	return encryptUsingPSK(true, cipher, content, key)
}

func encryptUsingPSK(isSM bool, cipher pkcs.Cipher, content []byte, key []byte) ([]byte, error) {
	var err error

	if key == nil {
		return nil, ErrPSKNotProvided
	}

	id, ciphertext, err := cipher.Encrypt(key, content)
	if err != nil {
		return nil, err
	}

	// Prepare encrypted-data content
	ed := encryptedData{
		Version: 0,
		EncryptedContentInfo: encryptedContentInfo{
			ContentType:                OIDData,
			ContentEncryptionAlgorithm: *id,
			EncryptedContent:           marshalEncryptedContent(ciphertext),
		},
	}
	if isSM {
		ed.EncryptedContentInfo.ContentType = SM2OIDData
	}

	innerContent, err := asn1.Marshal(ed)
	if err != nil {
		return nil, err
	}

	var contentType = OIDEncryptedData
	if isSM {
		contentType = SM2OIDEncryptedData
	}
	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: contentType,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *smx509.Certificate) ([]byte, error) {
	if pub, ok := recipient.PublicKey.(*rsa.PublicKey); ok {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	}
	if pub, ok := recipient.PublicKey.(*ecdsa.PublicKey); ok && pub.Curve == sm2.P256() {
		return sm2.EncryptASN1(rand.Reader, pub, key)
	}
	return nil, errors.New("pkcs7: only supports RSA/SM2 key")
}
