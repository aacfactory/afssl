package cipher

import (
	goCipher "crypto/cipher"
	"github.com/aacfactory/afssl/gmsm/internal/alias"
)

type ecb struct {
	b         goCipher.Block
	blockSize int
}

func newECB(b goCipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (x *ecb) validate(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
}

type ecbEncryptor ecb

type ecbEncAble interface {
	NewECBEncryptor() goCipher.BlockMode
}

func NewECBEncryptor(b goCipher.Block) goCipher.BlockMode {
	if ecb0, ok := b.(ecbEncAble); ok {
		return ecb0.NewECBEncryptor()
	}
	return (*ecbEncryptor)(newECB(b))
}

func (x *ecbEncryptor) BlockSize() int { return x.blockSize }

func (x *ecbEncryptor) CryptBlocks(dst, src []byte) {
	(*ecb)(x).validate(dst, src)

	for len(src) > 0 {
		x.b.Encrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecryptor ecb

type ecbDecAble interface {
	NewECBDecryptor() goCipher.BlockMode
}

func NewECBDecryptor(b goCipher.Block) goCipher.BlockMode {
	if ecb, ok := b.(ecbDecAble); ok {
		return ecb.NewECBDecryptor()
	}
	return (*ecbDecryptor)(newECB(b))
}

func (x *ecbDecryptor) BlockSize() int { return x.blockSize }

func (x *ecbDecryptor) CryptBlocks(dst, src []byte) {
	(*ecb)(x).validate(dst, src)
	if len(src) == 0 {
		return
	}
	for len(src) > 0 {
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
