package sm2

import (
	"crypto"
	"crypto/aes"
	cph "crypto/cipher"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"io"
	"math/big"
	"reflect"
)

var (
	defaultUid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	C1C3C2     = 0
	C1C2C3     = 1
)

var (
	oidSM2               = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPBES2             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidKEYMD5            = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidKEYSHA1           = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidKEYSHA256         = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidKEYSHA512         = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

func GenerateKey(random io.Reader) (*PrivateKey, error) {
	c := P256()
	if random == nil {
		random = rand.Reader
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(random, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	k.Add(k, one)
	pri := new(PrivateKey)
	pri.PublicKey.Curve = c
	pri.D = k
	pri.PublicKey.X, pri.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return pri, nil
}

func ParsePublicKey(pemBytes []byte) (key *PublicKey, err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("sm2: pem is invalid")
	}
	p := block.Bytes

	var ppk pkixPublicKey

	if _, err = asn1.Unmarshal(p, &ppk); err != nil {
		return
	}
	if !reflect.DeepEqual(ppk.Algo.Algorithm, oidSM2) {
		return nil, errors.New("sm2: not sm2 elliptic curve")
	}
	curve := P256()
	x, y := elliptic.Unmarshal(curve, ppk.BitString.Bytes)
	key = &PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return
}

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

func (pub *PublicKey) Encode() ([]byte, error) {
	var r pkixPublicKey
	var algo pkix.AlgorithmIdentifier

	if pub.Curve.Params() != P256().Params() {
		return nil, errors.New("sm2: unsupported elliptic curve")
	}
	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}
	r.Algo = algo
	r.BitString = asn1.BitString{Bytes: elliptic.Marshal(pub.Curve, pub.X, pub.Y)}

	p, encodeErr := asn1.Marshal(r)
	if encodeErr != nil {
		return nil, encodeErr
	}
	pemBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   p,
	}

	return pem.EncodeToMemory(&pemBlock), nil
}

func (pub *PublicKey) Verify(msg []byte, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
	return Verify(pub, msg, defaultUid, r, s)
}

func (pub *PublicKey) Digest(msg, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUid
	}

	za, err := ZA(pub, uid)
	if err != nil {
		return nil, err
	}

	e, err := msgHash(za, msg)
	if err != nil {
		return nil, err
	}

	return e.Bytes(), nil
}

func (pub *PublicKey) EncryptAsn1(data []byte, random io.Reader) ([]byte, error) {
	return EncryptAsn1(pub, data, random)
}

func ParsePrivateKey(pemBytes []byte) (key *PrivateKey, err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("sm2: pem is invalid")
	}
	p := block.Bytes

	var priKey pkcs8
	if _, err = asn1.Unmarshal(p, &priKey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(priKey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("sm2: not sm2 elliptic curve")
	}
	var pk privateKey
	if _, err = asn1.Unmarshal(priKey.PrivateKey, &pk); err != nil {
		return nil, errors.New("sm2: failed to parse SM2 private key: " + err.Error())
	}
	curve := P256()
	k := new(big.Int).SetBytes(pk.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("sm2: invalid elliptic curve private key value")
	}
	key = new(PrivateKey)
	key.Curve = curve
	key.D = k
	pkp := make([]byte, (curveOrder.BitLen()+7)/8)
	for len(pk.PrivateKey) > len(pkp) {
		if pk.PrivateKey[0] != 0 {
			return nil, errors.New("sm2: invalid private key length")
		}
		pk.PrivateKey = pk.PrivateKey[1:]
	}
	copy(pkp[len(pkp)-len(pk.PrivateKey):], pk.PrivateKey)
	key.X, key.Y = curve.ScalarBaseMult(pkp)
	return
}

func ParsePrivateKeyWithPassword(pemBytes []byte, passwd []byte) (key *PrivateKey, err error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("sm2: pem is invalid")
	}
	p := pemBlock.Bytes

	var keyInfo encryptedPrivateKeyInfo
	_, err = asn1.Unmarshal(p, &keyInfo)
	if err != nil {
		err = errors.New("sm2: unknown format")
		return
	}
	if !reflect.DeepEqual(keyInfo.EncryptionAlgorithm.IdPBES2, oidPBES2) {
		return nil, errors.New("sm2: only support PBES2")
	}
	encryptionScheme := keyInfo.EncryptionAlgorithm.Pbes2Params.EncryptionScheme
	keyDerivationFunc := keyInfo.EncryptionAlgorithm.Pbes2Params.KeyDerivationFunc
	if !reflect.DeepEqual(keyDerivationFunc.IdPBKDF2, oidPBKDF2) {
		return nil, errors.New("sm2: only support PBKDF2")
	}
	pkdf2Params := keyDerivationFunc.Pkdf2Params
	if !reflect.DeepEqual(encryptionScheme.EncryAlgo, oidAES128CBC) &&
		!reflect.DeepEqual(encryptionScheme.EncryAlgo, oidAES256CBC) {
		return nil, errors.New("sm2: unknown encryption algorithm")
	}
	iv := encryptionScheme.IV
	salt := pkdf2Params.Salt
	iter := pkdf2Params.IterationCount
	encryptedKey := keyInfo.EncryptedData
	var kp []byte
	switch {
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYMD5):
		kp = pbkdf(passwd, salt, iter, 32, md5.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA1):
		kp = pbkdf(passwd, salt, iter, 32, sha1.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA256):
		kp = pbkdf(passwd, salt, iter, 32, sha256.New)
		break
	case pkdf2Params.Prf.Algorithm.Equal(oidKEYSHA512):
		kp = pbkdf(passwd, salt, iter, 32, sha512.New)
		break
	default:
		return nil, errors.New("sm2: unknown hash algorithm")
	}
	block, err := aes.NewCipher(kp)
	if err != nil {
		return nil, err
	}
	mode := cph.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedKey, encryptedKey)
	key, err = parsePKCS8PrivateKey(encryptedKey)
	if err != nil {
		err = errors.New("sm2: incorrect password")
		return
	}
	key.password = passwd
	return
}

func parsePKCS8PrivateKey(p []byte) (*PrivateKey, error) {
	var priKey pkcs8
	if _, err := asn1.Unmarshal(p, &priKey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(priKey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("sm2: not sm2 elliptic curve")
	}
	return parsePrivateKey(priKey.PrivateKey)
}

func parsePrivateKey(p []byte) (*PrivateKey, error) {
	var key privateKey
	if _, err := asn1.Unmarshal(p, &key); err != nil {
		return nil, errors.New("sm2: failed to parse SM2 private key: " + err.Error())
	}
	curve := P256()
	k := new(big.Int).SetBytes(key.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("sm2: invalid elliptic curve private key value")
	}
	pri := new(PrivateKey)
	pri.Curve = curve
	pri.D = k
	pk := make([]byte, (curveOrder.BitLen()+7)/8)
	for len(key.PrivateKey) > len(pk) {
		if key.PrivateKey[0] != 0 {
			return nil, errors.New("sm2: invalid private key length")
		}
		key.PrivateKey = key.PrivateKey[1:]
	}
	copy(pk[len(pk)-len(key.PrivateKey):], key.PrivateKey)
	pri.X, pri.Y = curve.ScalarBaseMult(pk)
	return pri, nil
}

type PrivateKey struct {
	PublicKey
	D        *big.Int
	password []byte
}

func (pri *PrivateKey) Exchange(initiator []byte, responder []byte, pub *PublicKey, sharedSecretKeyLen int, isInitiator bool) (k, s1, s2 []byte, err error) {
	k, s1, s2, err = keyExchange(sharedSecretKeyLen, initiator, responder, pri, pub, pri, pub, isInitiator)
	return
}

func (pri *PrivateKey) Public() crypto.PublicKey {
	return &pri.PublicKey
}

func (pri *PrivateKey) Encode() ([]byte, error) {
	var r pkcs8
	var pk privateKey
	var algo pkix.AlgorithmIdentifier
	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}
	pk.Version = 1
	pk.NamedCurveOID = oidNamedCurveP256SM2
	pk.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(pri.Curve, pri.X, pri.Y)}
	pk.PrivateKey = pri.D.Bytes()
	r.Version = 0
	r.Algo = algo
	r.PrivateKey, _ = asn1.Marshal(pk)
	p, encodeErr := asn1.Marshal(r)
	if encodeErr != nil {
		return nil, encodeErr
	}
	if pri.password == nil || len(pri.password) == 0 {
		pemBlock := pem.Block{
			Type:    "PRIVATE KEY",
			Headers: nil,
			Bytes:   p,
		}
		return pem.EncodeToMemory(&pemBlock), nil
	}

	iter := 2048
	salt := make([]byte, 8)
	iv := make([]byte, 16)
	_, _ = rand.Reader.Read(salt)
	_, _ = rand.Reader.Read(iv)
	key := pbkdf(pri.password, salt, iter, 32, sha1.New)
	padding := aes.BlockSize - len(p)%aes.BlockSize
	if padding > 0 {
		n := len(p)
		p = append(p, make([]byte, padding)...)
		for i := 0; i < padding; i++ {
			p[n+i] = byte(padding)
		}
	}
	encryptedKey := make([]byte, len(p))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cph.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedKey, p)
	var algorithmIdentifier pkix.AlgorithmIdentifier
	algorithmIdentifier.Algorithm = oidKEYSHA1
	algorithmIdentifier.Parameters.Tag = 5
	algorithmIdentifier.Parameters.IsCompound = false
	algorithmIdentifier.Parameters.FullBytes = []byte{5, 0}
	keyDerivationFunc := pbesKDfs{
		oidPBKDF2,
		pkdfParams{
			salt,
			iter,
			algorithmIdentifier,
		},
	}
	encryptionScheme := pbesEncs{
		oidAES256CBC,
		iv,
	}
	pbes2Algorithms := pbesAlgorithms{
		oidPBES2,
		pbesParams{
			keyDerivationFunc,
			encryptionScheme,
		},
	}
	encryptedPkey := encryptedPrivateKeyInfo{
		pbes2Algorithms,
		encryptedKey,
	}

	p, encodeErr = asn1.Marshal(encryptedPkey)
	if encodeErr != nil {
		return nil, encodeErr
	}

	pemBlock := pem.Block{
		Type:    "ENCRYPTED PRIVATE KEY",
		Headers: nil,
		Bytes:   p,
	}

	return pem.EncodeToMemory(&pemBlock), nil
}

func (pri *PrivateKey) Sign(random io.Reader, msg []byte) ([]byte, error) {
	r, s, err := Sign(pri, msg, nil, random)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

func (pri *PrivateKey) DecryptAsn1(data []byte) ([]byte, error) {
	return DecryptAsn1(pri, data)
}

func (pri *PrivateKey) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) (plaintext []byte, err error) {
	return Decrypt(pri, msg, C1C3C2)
}
