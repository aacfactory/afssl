package afssl

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/smx509"
)

type KeyName string

type KeyType interface {
	Name() (name KeyName)
}

const unknownKeyTypeName = KeyName("UNKNOWN")

type unknownKeyType struct {
}

func (r *unknownKeyType) Name() (name KeyName) {
	name = unknownKeyTypeName
	return
}

func RSA() KeyType {
	return RSAWithBits(4096)
}

func RSAWithBits(bits int) KeyType {
	return &rsaKeyType{
		keyBits: bits,
	}
}

const rsaKeyTypeName = KeyName("RSA")

type rsaKeyType struct {
	keyBits int
}

func (r *rsaKeyType) Name() (name KeyName) {
	name = rsaKeyTypeName
	return
}

func ECDSA() KeyType {
	return ECDSAWithCurve(elliptic.P256())
}

func ECDSAWithCurve(curve elliptic.Curve) KeyType {
	return &ecdsaKeyType{
		curve: curve,
	}
}

const ecdsaKeyTypeName = KeyName("ECDSA")

type ecdsaKeyType struct {
	curve elliptic.Curve
}

func (r *ecdsaKeyType) Name() (name KeyName) {
	name = ecdsaKeyTypeName
	return
}

func ED25519() KeyType {
	return ED25519WithSeed(nil)
}

func ED25519WithSeed(seed []byte) KeyType {
	return &ed25519KeyType{
		seed: seed,
	}
}

const ed25519KeyTypeName = KeyName("ED25519")

type ed25519KeyType struct {
	seed []byte
}

func (r *ed25519KeyType) Name() (name KeyName) {
	name = ed25519KeyTypeName
	return
}

func X25519() KeyType {
	return &x25519KeyType{}
}

const x25519KeyTypeName = KeyName("X25519")

type x25519KeyType struct {
	seed []byte
}

func (r *x25519KeyType) Name() (name KeyName) {
	name = x25519KeyTypeName
	return
}

func SM2() KeyType {
	return &sm2KeyType{}
}

const sm2KeyTypeName = KeyName("SM2")

type sm2KeyType struct {
}

func (r *sm2KeyType) Name() (name KeyName) {
	name = sm2KeyTypeName
	return
}

func EncryptMasterSM9() KeyType {
	return &sm9KeyType{
		kind: "encrypt",
	}
}

func SignMasterSM9() KeyType {
	return &sm9KeyType{
		kind: "sign",
	}
}

const sm9KeyTypeName = KeyName("SM9")

type sm9KeyType struct {
	kind string
}

func (r *sm9KeyType) Name() (name KeyName) {
	name = sm9KeyTypeName
	return
}

func ParsePrivateKey(keyPEM []byte) (key any, keyType KeyType, err error) {
	keyBlock, _ := pem.Decode(keyPEM)
	keyBlockType := keyBlock.Type
	if keyBlockType == "" {
		err = fmt.Errorf("afssl: invalid private key block type")
		return
	}
	// PKCS1
	if keyBlock.Type == "RSA PRIVATE KEY" {
		rsaKey, parseKeyErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if parseKeyErr != nil {
			err = fmt.Errorf("afssl: parse pkcs1 rsa private key failed, %v", parseKeyErr)
			return
		}
		key = rsaKey
		keyType = RSAWithBits(rsaKey.N.BitLen())
		return
	}
	// GM
	gmKeyType, _ := smx509.GetGMPrivateKeyType(keyBlock.Bytes)
	// EC
	if keyBlock.Type != "PRIVATE KEY" {
		if gmKeyType == smx509.SM2Key {
			sm2Key, parseSM2KeyErr := smx509.ParseSM2PrivateKey(keyBlock.Bytes)
			if parseSM2KeyErr != nil {
				err = fmt.Errorf("afssl: parse sm2 private key failed, %v", parseSM2KeyErr)
				return
			}
			key = sm2Key
			keyType = SM2()
			return
		} else {
			ecKey, parseErr := x509.ParseECPrivateKey(keyBlock.Bytes)
			if parseErr != nil {
				err = fmt.Errorf("afssl: parse ec private key failed, %v", parseErr)
				return
			}
			key = ecKey
			keyType = ECDSAWithCurve(ecKey.Curve)
			return
		}
	}
	// PKCS8
	// SM2
	if gmKeyType == smx509.SM2Key {
		sm2Key, parseSM2KeyErr := smx509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if parseSM2KeyErr != nil {
			err = fmt.Errorf("afssl: parse sm2 private key failed, %v", parseSM2KeyErr)
			return
		}
		key = sm2Key
		keyType = SM2()
		return
	}
	// standards
	k, parseErr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if parseErr != nil {
		err = fmt.Errorf("afssl: parse PKCS8 private key failed, %v", parseErr)
		return
	}
	switch kk := k.(type) {
	case *rsa.PrivateKey:
		key = kk
		keyType = RSAWithBits(kk.N.BitLen())
		break
	case *ecdsa.PrivateKey:
		key = kk
		keyType = ECDSAWithCurve(kk.Curve)
		break
	case *ed25519.PrivateKey:
		key = kk
		keyType = ED25519WithSeed(kk.Seed())
		break
	case *ecdh.PrivateKey:
		key = kk
		keyType = X25519()
		break
	default:
		err = fmt.Errorf("afssl: parse PKCS8 private key failed, unknown key type")
		return
	}
	return
}
