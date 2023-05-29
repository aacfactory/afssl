package cipher

import (
	stdCipher "crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"github.com/aacfactory/afssl/gmsm/internal/alias"
	"math"

	"errors"
)

const (
	ccmBlockSize         = 16
	ccmTagSize           = 16
	ccmMinimumTagSize    = 4
	ccmStandardNonceSize = 12
)

type ccmAble interface {
	NewCCM(nonceSize, tagSize int) (stdCipher.AEAD, error)
}

func NewCCM(cipher stdCipher.Block) (stdCipher.AEAD, error) {
	return NewCCMWithNonceAndTagSize(cipher, ccmStandardNonceSize, ccmTagSize)
}

func NewCCMWithNonceSize(cipher stdCipher.Block, size int) (stdCipher.AEAD, error) {
	return NewCCMWithNonceAndTagSize(cipher, size, ccmTagSize)
}

func NewCCMWithTagSize(cipher stdCipher.Block, tagSize int) (stdCipher.AEAD, error) {
	return NewCCMWithNonceAndTagSize(cipher, ccmStandardNonceSize, tagSize)
}

type ccm struct {
	cipher    stdCipher.Block
	nonceSize int
	tagSize   int
}

func (c *ccm) NonceSize() int {
	return c.nonceSize
}

func (c *ccm) Overhead() int {
	return c.tagSize
}

func (c *ccm) MaxLength() int {
	return maxLen(15-c.NonceSize(), c.Overhead())
}

func maxLen(l int, tagSize int) int {
	max := (uint64(1) << (8 * l)) - 1
	if m64 := uint64(math.MaxInt64) - uint64(tagSize); l > 8 || max > m64 {
		max = m64
	}
	if max != uint64(int(max)) {
		return math.MaxInt32 - tagSize
	}
	return int(max)
}

func NewCCMWithNonceAndTagSize(cipher stdCipher.Block, nonceSize, tagSize int) (stdCipher.AEAD, error) {
	if tagSize < ccmMinimumTagSize || tagSize > ccmBlockSize || tagSize&1 != 0 {
		return nil, errors.New("cipher: incorrect tag size given to CCM")
	}

	if nonceSize <= 0 {
		return nil, errors.New("cipher: the nonce can't have zero length, or the security of the key will be immediately compromised")
	}

	lenSize := 15 - nonceSize
	if lenSize < 2 || lenSize > 8 {
		return nil, errors.New("cipher: invalid ccm nonce size, should be in [7,13]")
	}

	if cipher, ok := cipher.(ccmAble); ok {
		return cipher.NewCCM(nonceSize, tagSize)
	}

	if cipher.BlockSize() != ccmBlockSize {
		return nil, errors.New("cipher: NewCCM requires 128-bit block cipher")
	}

	c := &ccm{cipher: cipher, nonceSize: nonceSize, tagSize: tagSize}

	return c, nil
}

func (c *ccm) deriveCounter(counter *[ccmBlockSize]byte, nonce []byte) {
	counter[0] = byte(14 - c.nonceSize)
	copy(counter[1:], nonce)
}

func (c *ccm) cmac(out, data []byte) {
	for len(data) >= ccmBlockSize {
		subtle.XORBytes(out, out, data)
		c.cipher.Encrypt(out, out)
		data = data[ccmBlockSize:]
	}
	if len(data) > 0 {
		var block [ccmBlockSize]byte
		copy(block[:], data)
		subtle.XORBytes(out, out, data)
		c.cipher.Encrypt(out, out)
	}
}

func (c *ccm) auth(nonce []byte, plaintext []byte, additionalData []byte, tagMask *[ccmBlockSize]byte) []byte {
	var out [ccmTagSize]byte
	if len(additionalData) > 0 {
		out[0] = 1 << 6
	}
	out[0] |= byte(c.tagSize-2) << 2
	out[0] |= byte(14 - c.nonceSize)
	binary.BigEndian.PutUint64(out[ccmBlockSize-8:], uint64(len(plaintext)))
	copy(out[1:], nonce)
	c.cipher.Encrypt(out[:], out[:])

	var block [ccmBlockSize]byte
	if n := uint64(len(additionalData)); n > 0 {
		i := 2
		if n <= 0xfeff {
			binary.BigEndian.PutUint16(block[:i], uint16(n))
		} else {
			block[0] = 0xff
			if n < uint64(1<<32) {
				block[1] = 0xfe
				i = 2 + 4
				binary.BigEndian.PutUint32(block[2:i], uint32(n))
			} else {
				block[1] = 0xff
				i = 2 + 8
				binary.BigEndian.PutUint64(block[2:i], n)
			}
		}
		i = copy(block[i:], additionalData)
		c.cmac(out[:], block[:])
		c.cmac(out[:], additionalData[i:])
	}
	if len(plaintext) > 0 {
		c.cmac(out[:], plaintext)
	}
	subtle.XORBytes(out[:], out[:], tagMask[:])
	return out[:c.tagSize]
}

func (c *ccm) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != c.nonceSize {
		panic("cipher: incorrect nonce length given to CCM")
	}
	if uint64(len(plaintext)) > uint64(c.MaxLength()) {
		panic("cipher: message too large for CCM")
	}
	ret, out := alias.SliceForAppend(dst, len(plaintext)+c.tagSize)
	if alias.InexactOverlap(out, plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	var counter, tagMask [ccmBlockSize]byte
	c.deriveCounter(&counter, nonce)
	c.cipher.Encrypt(tagMask[:], counter[:])

	counter[len(counter)-1] |= 1
	ctr := stdCipher.NewCTR(c.cipher, counter[:])
	ctr.XORKeyStream(out, plaintext)

	tag := c.auth(nonce, plaintext, data, &tagMask)
	copy(out[len(plaintext):], tag)

	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (c *ccm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != c.nonceSize {
		return nil, errors.New("cipher: incorrect nonce length given to CCM")
	}
	if c.tagSize < ccmMinimumTagSize {
		panic("cipher: incorrect CCM tag size")
	}

	if len(ciphertext) < c.tagSize {
		return nil, errOpen
	}

	if len(ciphertext) > c.MaxLength()+c.Overhead() {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-c.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-c.tagSize]

	var counter, tagMask [ccmBlockSize]byte
	c.deriveCounter(&counter, nonce)
	c.cipher.Encrypt(tagMask[:], counter[:])

	ret, out := alias.SliceForAppend(dst, len(ciphertext))
	if alias.InexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}

	counter[len(counter)-1] |= 1
	ctr := stdCipher.NewCTR(c.cipher, counter[:])
	ctr.XORKeyStream(out, ciphertext)
	expectedTag := c.auth(nonce, out, data, &tagMask)
	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}
