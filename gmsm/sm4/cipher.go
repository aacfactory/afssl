package sm4

import (
	"crypto/cipher"
	"fmt"

	"github.com/aacfactory/afssl/gmsm/internal/alias"
)

const BlockSize = 16

const rounds = 32

type sm4Cipher struct {
	enc []uint32
	dec []uint32
}

func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, fmt.Errorf("sm4: invalid key size %d", k)
	case 16:
		break
	}
	return newCipher(key)
}

func newCipherGeneric(key []byte) (cipher.Block, error) {
	c := sm4Cipher{make([]uint32, rounds), make([]uint32, rounds)}
	expandKeyGo(key, c.enc, c.dec)
	return &c, nil
}

func (c *sm4Cipher) BlockSize() int { return BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	encryptBlockGo(c.enc, dst, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	decryptBlockGo(c.dec, dst, src)
}
