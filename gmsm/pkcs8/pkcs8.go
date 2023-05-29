package pkcs8

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strconv"

	"github.com/aacfactory/afssl/gmsm/pkcs"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"github.com/aacfactory/afssl/gmsm/smx509"
)

type Hash uint

const (
	SHA1 Hash = 1 + iota
	SHA224
	SHA256
	SHA384
	SHA512
	SHA512_224
	SHA512_256
	SM3
)

func (h Hash) New() hash.Hash {
	switch h {
	case SM3:
		return sm3.New()
	case SHA1:
		return sha1.New()
	case SHA224:
		return sha256.New224()
	case SHA256:
		return sha256.New()
	case SHA384:
		return sha512.New384()
	case SHA512:
		return sha512.New()
	case SHA512_224:
		return sha512.New512_224()
	case SHA512_256:
		return sha512.New512_256()

	}
	panic("pkcs8: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

var DefaultOpts = &Opts{
	Cipher: pkcs.AES256CBC,
	KDFOpts: PBKDF2Opts{
		SaltSize:       8,
		IterationCount: 10000,
		HMACHash:       SHA256,
	},
}

type KDFOpts interface {
	DeriveKey(password, salt []byte, size int) (key []byte, params KDFParameters, err error)
	GetSaltSize() int
	OID() asn1.ObjectIdentifier
}

type KDFParameters interface {
	DeriveKey(password []byte, size int) (key []byte, err error)
}

var kdfs = make(map[string]func() KDFParameters)

func RegisterKDF(oid asn1.ObjectIdentifier, params func() KDFParameters) {
	kdfs[oid.String()] = params
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type Opts struct {
	Cipher  pkcs.Cipher
	KDFOpts KDFOpts
}

var (
	oidPBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
)

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

func parseKeyDerivationFunc(keyDerivationFunc pkix.AlgorithmIdentifier) (KDFParameters, error) {
	oid := keyDerivationFunc.Algorithm.String()
	newParams, ok := kdfs[oid]
	if !ok {
		return nil, fmt.Errorf("pkcs8: unsupported KDF (OID: %s)", oid)
	}
	params := newParams()
	_, err := asn1.Unmarshal(keyDerivationFunc.Parameters.FullBytes, params)
	if err != nil {
		return nil, errors.New("pkcs8: invalid KDF parameters")
	}
	return params, nil
}

func ParsePrivateKey(der []byte, password []byte) (interface{}, KDFParameters, error) {
	if len(password) == 0 {
		privateKey, err := smx509.ParsePKCS8PrivateKey(der)
		return privateKey, nil, err
	}

	var privKey encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if block, _ := pem.Decode(der); block != nil {
			return nil, nil, errors.New("pkcs8: this method just supports DER-encoded key")
		}
		return nil, nil, errors.New("pkcs8: only PKCS #5 v2.0 supported")
	}

	if !privKey.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, nil, errors.New("pkcs8: only PBES2 supported")
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(privKey.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, nil, errors.New("pkcs8: invalid PBES2 parameters")
	}

	cipher, err := pkcs.GetCipher(params.EncryptionScheme)
	if err != nil {
		return nil, nil, err
	}

	kdfParams, err := parseKeyDerivationFunc(params.KeyDerivationFunc)
	if err != nil {
		return nil, nil, err
	}

	keySize := cipher.KeySize()
	symkey, err := kdfParams.DeriveKey(password, keySize)
	if err != nil {
		return nil, nil, err
	}

	encryptedKey := privKey.EncryptedData
	decryptedKey, err := cipher.Decrypt(symkey, &params.EncryptionScheme.Parameters, encryptedKey)
	if err != nil {
		return nil, nil, err
	}

	key, err := smx509.ParsePKCS8PrivateKey(decryptedKey)
	if err != nil {
		return nil, nil, errors.New("pkcs8: incorrect password? failed to parse private key while ParsePKCS8PrivateKey: " + err.Error())
	}
	return key, kdfParams, nil
}

func MarshalPrivateKey(priv interface{}, password []byte, opts *Opts) ([]byte, error) {
	if len(password) == 0 {
		return smx509.MarshalPKCS8PrivateKey(priv)
	}

	if opts == nil {
		opts = DefaultOpts
	}

	pkey, err := smx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	encAlg := opts.Cipher
	salt := make([]byte, opts.KDFOpts.GetSaltSize())
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, kdfParams, err := opts.KDFOpts.DeriveKey(password, salt, encAlg.KeySize())
	if err != nil {
		return nil, err
	}

	encryptionScheme, encryptedKey, err := encAlg.Encrypt(key, pkey)
	if err != nil {
		return nil, err
	}

	marshalledParams, err := asn1.Marshal(kdfParams)
	if err != nil {
		return nil, err
	}
	keyDerivationFunc := pkix.AlgorithmIdentifier{
		Algorithm:  opts.KDFOpts.OID(),
		Parameters: asn1.RawValue{FullBytes: marshalledParams},
	}

	encryptionAlgorithmParams := pbes2Params{
		EncryptionScheme:  *encryptionScheme,
		KeyDerivationFunc: keyDerivationFunc,
	}
	marshalledEncryptionAlgorithmParams, err := asn1.Marshal(encryptionAlgorithmParams)
	if err != nil {
		return nil, err
	}
	encryptionAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm:  oidPBES2,
		Parameters: asn1.RawValue{FullBytes: marshalledEncryptionAlgorithmParams},
	}

	encryptedPkey := encryptedPrivateKeyInfo{
		EncryptionAlgorithm: encryptionAlgorithm,
		EncryptedData:       encryptedKey,
	}

	return asn1.Marshal(encryptedPkey)
}

func ParsePKCS8PrivateKey(der []byte, v ...[]byte) (interface{}, error) {
	var password []byte
	if len(v) > 0 {
		password = v[0]
	}
	privateKey, _, err := ParsePrivateKey(der, password)
	return privateKey, err
}

func ParsePKCS8PrivateKeyRSA(der []byte, v ...[]byte) (*rsa.PrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type RSA")
	}
	return typedKey, nil
}

func ParsePKCS8PrivateKeyECDSA(der []byte, v ...[]byte) (*ecdsa.PrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type ECDSA")
	}
	return typedKey, nil
}

func ParsePKCS8PrivateKeySM2(der []byte, v ...[]byte) (*sm2.PrivateKey, error) {
	key, err := ParsePKCS8PrivateKey(der, v...)
	if err != nil {
		return nil, err
	}
	typedKey, ok := key.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("pkcs8: key block is not of type SM2")
	}
	return typedKey, nil
}

func ConvertPrivateKeyToPKCS8(priv interface{}, v ...[]byte) ([]byte, error) {
	var password []byte
	if len(v) > 0 {
		password = v[0]
	}
	return MarshalPrivateKey(priv, password, nil)
}
