package cfca

import (
	"crypto/cipher"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/kdf"
	"github.com/aacfactory/afssl/gmsm/padding"
	"github.com/aacfactory/afssl/gmsm/pkcs"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"github.com/aacfactory/afssl/gmsm/sm4"
	"github.com/aacfactory/afssl/gmsm/smx509"
	"math/big"
)

type cfcaKeyPairData struct {
	Version      int `asn1:"default:1"`
	EncryptedKey keyData
	Certificate  certData
}

type keyData struct {
	ContentType      asn1.ObjectIdentifier
	Algorithm        asn1.ObjectIdentifier
	EncryptedContent asn1.RawValue
}

type certData struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawContent
}

var (
	oidSM2Data = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
	oidSM4     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104}
	oidSM4CBC  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
)

func Parse(keyPEM []byte, password []byte) (*smx509.Certificate, *sm2.PrivateKey, error) {
	block, rest := pem.Decode(keyPEM)
	if len(rest) != 0 {
		return nil, nil, errors.New("cfca: unexpected remaining PEM block during decode")
	}
	var keys cfcaKeyPairData
	if _, err := asn1.Unmarshal(block.Bytes, &keys); err != nil {
		return nil, nil, err
	}
	if !keys.Certificate.ContentType.Equal(oidSM2Data) {
		return nil, nil, fmt.Errorf("cfca: unsupported content type oid <%v>", keys.Certificate.ContentType)
	}
	if !keys.EncryptedKey.ContentType.Equal(oidSM2Data) {
		return nil, nil, fmt.Errorf("cfca: unsupported content type oid <%v>", keys.EncryptedKey.ContentType)
	}
	if !keys.EncryptedKey.Algorithm.Equal(oidSM4) && !keys.EncryptedKey.Algorithm.Equal(oidSM4CBC) {
		return nil, nil, fmt.Errorf("cfca: unsupported algorithm <%v>", keys.EncryptedKey.Algorithm)
	}
	iv := kdf.Kdf(sm3.New(), password, 32)
	marshalledIV, err := asn1.Marshal(iv[:16])
	if err != nil {
		return nil, nil, err
	}
	pk, err := pkcs.SM4CBC.Decrypt(iv[16:], &asn1.RawValue{FullBytes: marshalledIV}, keys.EncryptedKey.EncryptedContent.Bytes)
	if err != nil {
		return nil, nil, err
	}
	d := new(big.Int).SetBytes(pk)
	prvKey := new(sm2.PrivateKey)
	prvKey.Curve = sm2.P256()
	prvKey.D = d
	prvKey.PublicKey.X, prvKey.PublicKey.Y = prvKey.ScalarBaseMult(prvKey.D.Bytes())

	cert, err := smx509.ParseCertificate(keys.Certificate.Content)
	if err != nil {
		return nil, nil, err
	}

	if !prvKey.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New("cfca: public key and private key do not match")
	}
	return cert, prvKey, nil
}

func Marshal(cert *smx509.Certificate, key *sm2.PrivateKey, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("cfca: invalid password")
	}
	iv := kdf.Kdf(sm3.New(), password, 32)
	block, err := sm4.NewCipher(iv[16:])
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv[:16])
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plainText := pkcs7.Pad(key.D.Bytes())
	ciphertext := make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)

	ciphertext, err = asn1.Marshal(ciphertext)
	if err != nil {
		return nil, err
	}

	keys := cfcaKeyPairData{
		Version: 1,
		EncryptedKey: keyData{
			ContentType:      oidSM2Data,
			Algorithm:        oidSM4,
			EncryptedContent: asn1.RawValue{FullBytes: ciphertext},
		},
		Certificate: certData{
			ContentType: oidSM2Data,
			Content:     cert.Raw,
		},
	}

	return asn1.Marshal(keys)
}

func EncodeToPEM(cert *smx509.Certificate, key *sm2.PrivateKey, password []byte) ([]byte, error) {
	result, err := Marshal(cert, key, password)
	if err != nil {
		return nil, err
	}
	p := pem.EncodeToMemory(&pem.Block{
		Type:    "CFCA KEY",
		Headers: nil,
		Bytes:   result,
	})
	return p, nil
}
