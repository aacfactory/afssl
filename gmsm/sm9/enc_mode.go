package sm9

import (
	"crypto/cipher"
	"crypto/subtle"
	"io"

	_cipher "github.com/aacfactory/afssl/gmsm/cipher"
	"github.com/aacfactory/afssl/gmsm/padding"
	"github.com/aacfactory/afssl/gmsm/sm4"
)

type EncrypterOpts interface {
	GetEncryptType() encryptType
	GetKeySize(plaintext []byte) int
	Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error)
	Decrypt(key, ciphertext []byte) ([]byte, error)
}

type XOREncrypterOpts struct{}

func (opts *XOREncrypterOpts) GetEncryptType() encryptType {
	return EncTypeXor
}

func (opts *XOREncrypterOpts) GetKeySize(plaintext []byte) int {
	return len(plaintext)
}

func (opts *XOREncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	subtle.XORBytes(key, key, plaintext)
	return key, nil
}

func (opts *XOREncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrDecryption
	}
	subtle.XORBytes(key, ciphertext, key)
	return key, nil
}

type newCipher func(key []byte) (cipher.Block, error)

type baseBlockEncrypterOpts struct {
	encryptType   encryptType
	newCipher     newCipher
	cipherKeySize int
}

func (opts *baseBlockEncrypterOpts) GetEncryptType() encryptType {
	return opts.encryptType
}

func (opts *baseBlockEncrypterOpts) GetKeySize(plaintext []byte) int {
	return opts.cipherKeySize
}

type CBCEncrypterOpts struct {
	baseBlockEncrypterOpts
	padding padding.Padding
}

func NewCBCEncrypterOpts(padding padding.Padding, newCipher newCipher, keySize int) EncrypterOpts {
	opts := new(CBCEncrypterOpts)
	opts.encryptType = EncTypeCbc
	opts.padding = padding
	opts.newCipher = newCipher
	opts.cipherKeySize = keySize
	return opts
}

func (opts *CBCEncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	paddedPlainText := opts.padding.Pad(plaintext)
	blockSize := block.BlockSize()
	ciphertext := make([]byte, blockSize+len(paddedPlainText))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[blockSize:], paddedPlainText)
	return ciphertext, nil
}

func (opts *CBCEncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(ciphertext) <= blockSize {
		return nil, ErrDecryption
	}
	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return opts.padding.Unpad(plaintext)
}

type ECBEncrypterOpts struct {
	baseBlockEncrypterOpts
	padding padding.Padding
}

func NewECBEncrypterOpts(padding padding.Padding, newCipher newCipher, keySize int) EncrypterOpts {
	opts := new(ECBEncrypterOpts)
	opts.encryptType = EncTypeEcb
	opts.padding = padding
	opts.newCipher = newCipher
	opts.cipherKeySize = keySize
	return opts
}

func (opts *ECBEncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	paddedPlainText := opts.padding.Pad(plaintext)
	ciphertext := make([]byte, len(paddedPlainText))
	mode := _cipher.NewECBEncryptor(block)
	mode.CryptBlocks(ciphertext, paddedPlainText)
	return ciphertext, nil
}

func (opts *ECBEncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, ErrDecryption
	}
	plaintext := make([]byte, len(ciphertext))
	mode := _cipher.NewECBDecryptor(block)
	mode.CryptBlocks(plaintext, ciphertext)
	return opts.padding.Unpad(plaintext)
}

type CFBEncrypterOpts struct {
	baseBlockEncrypterOpts
}

func NewCFBEncrypterOpts(newCipher newCipher, keySize int) EncrypterOpts {
	opts := new(CFBEncrypterOpts)
	opts.encryptType = EncTypeCfb
	opts.newCipher = newCipher
	opts.cipherKeySize = keySize
	return opts
}

func (opts *CFBEncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	ciphertext := make([]byte, blockSize+len(plaintext))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[blockSize:], plaintext)
	return ciphertext, nil
}

func (opts *CFBEncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(ciphertext) <= blockSize {
		return nil, ErrDecryption
	}
	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

type OFBEncrypterOpts struct {
	baseBlockEncrypterOpts
}

func NewOFBEncrypterOpts(newCipher newCipher, keySize int) EncrypterOpts {
	opts := new(OFBEncrypterOpts)
	opts.encryptType = EncTypeOfb
	opts.newCipher = newCipher
	opts.cipherKeySize = keySize
	return opts
}

func (opts *OFBEncrypterOpts) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	ciphertext := make([]byte, blockSize+len(plaintext))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext[blockSize:], plaintext)
	return ciphertext, nil
}

func (opts *OFBEncrypterOpts) Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := opts.newCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(ciphertext) <= blockSize {
		return nil, ErrDecryption
	}
	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

var DefaultEncrypterOpts = new(XOREncrypterOpts)

var SM4ECBEncrypterOpts = NewECBEncrypterOpts(padding.NewPKCS7Padding(sm4.BlockSize), sm4.NewCipher, sm4.BlockSize)

var SM4CBCEncrypterOpts = NewCBCEncrypterOpts(padding.NewPKCS7Padding(sm4.BlockSize), sm4.NewCipher, sm4.BlockSize)

var SM4CFBEncrypterOpts = NewCFBEncrypterOpts(sm4.NewCipher, sm4.BlockSize)

var SM4OFBEncrypterOpts = NewOFBEncrypterOpts(sm4.NewCipher, sm4.BlockSize)

func shangMiEncrypterOpts(encType encryptType) EncrypterOpts {
	switch encType {
	case EncTypeXor:
		return DefaultEncrypterOpts
	case EncTypeCbc:
		return SM4CBCEncrypterOpts
	case EncTypeEcb:
		return SM4ECBEncrypterOpts
	case EncTypeCfb:
		return SM4CFBEncrypterOpts
	case EncTypeOfb:
		return SM4OFBEncrypterOpts
	}
	return nil
}
