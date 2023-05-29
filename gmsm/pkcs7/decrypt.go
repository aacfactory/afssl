package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"github.com/aacfactory/afssl/gmsm/pkcs"
	"github.com/aacfactory/afssl/gmsm/smx509"
)

var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, SM2, DES, DES-EDE3, AES and SM4 supported")

var ErrNotEncryptedContent = errors.New("pkcs7: content data is NOT a decryptAble data type")

type decryptAble interface {
	GetRecipient(cert *smx509.Certificate) *recipientInfo
	GetEncryptedContentInfo() *encryptedContentInfo
}

func (p7 *PKCS7) Decrypt(cert *smx509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	decryptableData, ok := p7.raw.(decryptAble)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := decryptableData.GetRecipient(cert)
	if recipient == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}

	switch pkey := pkey.(type) {
	case crypto.Decrypter:
		contentKey, err := pkey.Decrypt(rand.Reader, recipient.EncryptedKey, nil)
		if err != nil {
			return nil, err
		}
		return decryptableData.GetEncryptedContentInfo().decrypt(contentKey)
	}
	return nil, ErrUnsupportedAlgorithm
}

func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, error) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return data.EncryptedContentInfo.decrypt(key)
}

func (eci encryptedContentInfo) getCiphertext() (ciphertext []byte) {
	if eci.EncryptedContent.IsCompound {
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		ciphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		ciphertext = eci.EncryptedContent.Bytes
	}
	return
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	cipher, err := pkcs.GetCipher(eci.ContentEncryptionAlgorithm)
	if err != nil {
		return nil, ErrUnsupportedAlgorithm
	}
	return cipher.Decrypt(key, &eci.ContentEncryptionAlgorithm.Parameters, eci.getCiphertext())
}
