package drbg

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"github.com/aacfactory/afssl/gmsm/sm4"
	"time"
)

func NewCTR(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, securityLevel SecurityLevel, gm bool, entropy, nonce, personalization []byte) (*CTR, error) {
	hd := &CTR{}
	hd.gm = gm
	hd.setSecurityLevel(securityLevel)

	if len(entropy) == 0 || (hd.gm && len(entropy) < 32) || len(entropy) >= MaxBytes {
		return nil, errors.New("invalid entropy length")
	}

	if len(nonce) == 0 || (hd.gm && len(nonce) < 16) || len(nonce) >= MaxBytes>>1 {
		return nil, errors.New("invalid nonce length")
	}

	if len(personalization) >= MaxBytes {
		return nil, errors.New("personalization is too long")
	}

	hd.cipherProvider = cipherProvider
	hd.keyLen = keyLen
	temp := make([]byte, hd.keyLen)
	block, err := cipherProvider(temp)
	if err != nil {
		return nil, err
	}
	hd.seedLength = block.BlockSize() + keyLen
	hd.v = make([]byte, block.BlockSize())
	hd.key = make([]byte, hd.keyLen)

	seedMaterial := make([]byte, len(entropy)+len(nonce)+len(personalization))
	copy(seedMaterial, entropy)
	copy(seedMaterial[len(entropy):], nonce)
	copy(seedMaterial[len(entropy)+len(nonce):], personalization)
	seedMaterial = hd.derive(seedMaterial, hd.seedLength)
	hd.update(seedMaterial)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return hd, nil
}

func NewNistCTR(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*CTR, error) {
	return NewCTR(cipherProvider, keyLen, securityLevel, false, entropy, nonce, personalization)
}

func NewGmCTR(securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*CTR, error) {
	return NewCTR(sm4.NewCipher, 16, securityLevel, true, entropy, nonce, personalization)
}

type CTR struct {
	Base
	cipherProvider func(key []byte) (cipher.Block, error)
	key            []byte
	keyLen         int
}

func (hd *CTR) Reseed(entropy, additional []byte) error {
	if len(entropy) <= 0 || (hd.gm && len(entropy) < 32) || len(entropy) >= MaxBytes {
		return errors.New("invalid entropy length")
	}

	if len(additional) >= MaxBytes {
		return errors.New("additional input too long")
	}

	var seedMaterial []byte
	if len(additional) == 0 {
		seedMaterial = entropy
	} else {
		seedMaterial = make([]byte, len(entropy)+len(additional))
		copy(seedMaterial, entropy)
		copy(seedMaterial[len(entropy):], additional)
	}
	seedMaterial = hd.derive(seedMaterial, hd.seedLength)
	hd.update(seedMaterial)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return nil
}

func (hd *CTR) newBlockCipher(key []byte) cipher.Block {
	block, err := hd.cipherProvider(key)
	if err != nil {
		panic(err)
	}
	return block
}

func (hd *CTR) MaxBytesPerRequest() int {
	if hd.gm {
		return len(hd.v)
	}
	return MaxBytesPerGenerate
}

func (hd *CTR) Generate(b, additional []byte) error {
	if hd.NeedReseed() {
		return ErrReseedRequired
	}
	outLen := len(hd.v)
	if (hd.gm && len(b) > outLen) || (!hd.gm && len(b) > MaxBytesPerGenerate) {
		return errors.New("too many bytes requested")
	}

	if len(additional) > 0 {
		additional = hd.derive(additional, hd.seedLength)
		hd.update(additional)
	}

	block := hd.newBlockCipher(hd.key)
	temp := make([]byte, outLen)

	m := len(b)
	limit := uint64(m+outLen-1) / uint64(outLen)
	for i := 0; i < int(limit); i++ {
		addOne(hd.v, outLen)
		block.Encrypt(temp, hd.v)
		copy(b[i*outLen:], temp)
	}
	hd.update(additional)
	hd.reseedCounter++
	return nil
}

func (hd *CTR) update(seedMaterial []byte) {
	temp := make([]byte, hd.seedLength)
	block := hd.newBlockCipher(hd.key)
	outLen := block.BlockSize()
	v := make([]byte, outLen)
	output := make([]byte, outLen)
	copy(v, hd.v)
	for i := 0; i < (hd.seedLength+outLen-1)/outLen; i++ {
		addOne(v, outLen)
		block.Encrypt(output, v)
		copy(temp[i*outLen:], output)
	}
	subtle.XORBytes(temp, temp, seedMaterial)
	copy(hd.key, temp)
	copy(hd.v, temp[hd.keyLen:])
}

func (hd *CTR) derive(seedMaterial []byte, returnBytes int) []byte {
	outLen := hd.seedLength - hd.keyLen
	lenS := ((4 + 4 + len(seedMaterial) + outLen) / outLen) * outLen
	S := make([]byte, lenS+outLen)

	binary.BigEndian.PutUint32(S[outLen:], uint32(len(seedMaterial)))
	binary.BigEndian.PutUint32(S[outLen+4:], uint32(returnBytes))
	copy(S[outLen+8:], seedMaterial)
	S[outLen+8+len(seedMaterial)] = 0x80

	key := make([]byte, hd.keyLen)
	for i := 0; i < hd.keyLen; i++ {
		key[i] = byte(i)
	}
	blocks := (hd.seedLength + outLen - 1) / outLen
	temp := make([]byte, blocks*outLen)
	block := hd.newBlockCipher(key)

	for i := 0; i < blocks; i++ {
		binary.BigEndian.PutUint32(S, uint32(i))
		copy(temp[i*outLen:], hd.bcc(block, S))
	}

	key = temp[:hd.keyLen]
	X := temp[hd.keyLen:hd.seedLength]
	temp = make([]byte, returnBytes)
	block = hd.newBlockCipher(key)
	for i := 0; i < (returnBytes+outLen-1)/outLen; i++ {
		block.Encrypt(X, X)
		copy(temp[i*outLen:], X)
	}
	return temp
}

func (hd *CTR) bcc(block cipher.Block, data []byte) []byte {
	chainingValue := make([]byte, block.BlockSize())
	for i := 0; i < len(data)/block.BlockSize(); i++ {
		subtle.XORBytes(chainingValue, chainingValue, data[i*block.BlockSize():])
		block.Encrypt(chainingValue, chainingValue)
	}
	return chainingValue
}
