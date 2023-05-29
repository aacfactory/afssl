package cipher

import (
	stdCipher "crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"github.com/aacfactory/afssl/gmsm/internal/alias"
	"sync"
)

const gf128Fdbk byte = 0x87

type Creator func([]byte) (stdCipher.Block, error)

type concurrentBlocks interface {
	Concurrency() int
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
}

type XTSBlockMode interface {
	BlockSize() int
	Encrypt(dst, src []byte, sectorNum uint64)
	Decrypt(dst, src []byte, sectorNum uint64)
}

type xts struct {
	k1, k2 stdCipher.Block
}

const blockSize = 16

var tweakPool = sync.Pool{
	New: func() interface{} {
		return new([blockSize]byte)
	},
}

func NewXTS(cipherFunc Creator, key []byte) (XTSBlockMode, error) {
	k1, err := cipherFunc(key[:len(key)/2])
	if err != nil {
		return nil, err
	}
	k2, err := cipherFunc(key[len(key)/2:])
	c := &xts{
		k1,
		k2,
	}

	if c.k1.BlockSize() != blockSize {
		err = errors.New("xts: cipher does not have a block size of 16")
		return nil, err
	}
	return c, nil
}

func (c *xts) BlockSize() int {
	return blockSize
}

func (c *xts) Encrypt(ciphertext, plaintext []byte, sectorNum uint64) {
	if len(ciphertext) < len(plaintext) {
		panic("xts: ciphertext is smaller than plaintext")
	}
	if len(plaintext) < blockSize {
		panic("xts: plaintext length is smaller than the block size")
	}
	if alias.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
		panic("xts: invalid buffer overlap")
	}

	tweak := tweakPool.Get().(*[blockSize]byte)

	for i := range tweak {
		tweak[i] = 0
	}
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)
	c.k2.Encrypt(tweak[:], tweak[:])

	lastCiphertext := ciphertext

	if concCipher, ok := c.k1.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		var tweaks []byte = make([]byte, batchSize)

		for len(plaintext) >= batchSize {
			for i := 0; i < concCipher.Concurrency(); i++ {
				copy(tweaks[blockSize*i:], tweak[:])
				mul2(tweak)
			}
			subtle.XORBytes(ciphertext, plaintext, tweaks)
			concCipher.EncryptBlocks(ciphertext, ciphertext)
			subtle.XORBytes(ciphertext, ciphertext, tweaks)
			plaintext = plaintext[batchSize:]
			lastCiphertext = ciphertext[batchSize-blockSize:]
			ciphertext = ciphertext[batchSize:]
		}
	}
	for len(plaintext) >= blockSize {
		subtle.XORBytes(ciphertext, plaintext, tweak[:])
		c.k1.Encrypt(ciphertext, ciphertext)
		subtle.XORBytes(ciphertext, ciphertext, tweak[:])
		plaintext = plaintext[blockSize:]
		lastCiphertext = ciphertext
		ciphertext = ciphertext[blockSize:]
		mul2(tweak)
	}
	if remain := len(plaintext); remain > 0 {
		var x [blockSize]byte
		copy(ciphertext, lastCiphertext[:remain])
		copy(x[:], plaintext)
		copy(x[remain:], lastCiphertext[remain:blockSize])
		subtle.XORBytes(x[:], x[:], tweak[:])
		c.k1.Encrypt(x[:], x[:])
		subtle.XORBytes(lastCiphertext, x[:], tweak[:])
	}
	tweakPool.Put(tweak)
}

func (c *xts) Decrypt(plaintext, ciphertext []byte, sectorNum uint64) {
	if len(plaintext) < len(ciphertext) {
		panic("xts: plaintext is smaller than ciphertext")
	}
	if len(ciphertext) < blockSize {
		panic("xts: ciphertext length is smaller than the block size")
	}
	if alias.InexactOverlap(plaintext[:len(ciphertext)], ciphertext) {
		panic("xts: invalid buffer overlap")
	}

	tweak := tweakPool.Get().(*[blockSize]byte)
	for i := range tweak {
		tweak[i] = 0
	}
	binary.LittleEndian.PutUint64(tweak[:8], sectorNum)

	c.k2.Encrypt(tweak[:], tweak[:])

	if concCipher, ok := c.k1.(concurrentBlocks); ok {
		batchSize := concCipher.Concurrency() * blockSize
		var tweaks []byte = make([]byte, batchSize)

		for len(ciphertext) >= batchSize {
			for i := 0; i < concCipher.Concurrency(); i++ {
				copy(tweaks[blockSize*i:], tweak[:])
				mul2(tweak)
			}
			subtle.XORBytes(plaintext, ciphertext, tweaks)
			concCipher.DecryptBlocks(plaintext, plaintext)
			subtle.XORBytes(plaintext, plaintext, tweaks)
			plaintext = plaintext[batchSize:]
			ciphertext = ciphertext[batchSize:]
		}
	}

	for len(ciphertext) >= 2*blockSize {
		subtle.XORBytes(plaintext, ciphertext, tweak[:])
		c.k1.Decrypt(plaintext, plaintext)
		subtle.XORBytes(plaintext, plaintext, tweak[:])
		plaintext = plaintext[blockSize:]
		ciphertext = ciphertext[blockSize:]

		mul2(tweak)
	}

	if remain := len(ciphertext); remain >= blockSize {
		var x [blockSize]byte
		if remain > blockSize {
			var tt [blockSize]byte
			copy(tt[:], tweak[:])
			mul2(&tt)
			subtle.XORBytes(x[:], ciphertext, tt[:])
			c.k1.Decrypt(x[:], x[:])
			subtle.XORBytes(plaintext, x[:], tt[:])
			remain -= blockSize
			copy(plaintext[blockSize:], plaintext)
			copy(x[:], ciphertext[blockSize:])
			copy(x[remain:], plaintext[remain:blockSize])
		} else {
			copy(x[:], ciphertext)
		}
		subtle.XORBytes(x[:], x[:], tweak[:])
		c.k1.Decrypt(x[:], x[:])
		subtle.XORBytes(plaintext, x[:], tweak[:])
	}

	tweakPool.Put(tweak)
}

func mul2(tweak *[blockSize]byte) {
	var carryIn byte
	for j := range tweak {
		carryOut := tweak[j] >> 7
		tweak[j] = (tweak[j] << 1) + carryIn
		carryIn = carryOut
	}
	if carryIn != 0 {
		tweak[0] ^= gf128Fdbk
	}
}
