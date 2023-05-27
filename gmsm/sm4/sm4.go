package sm4

import (
	"crypto/cipher"
	"errors"
	"strconv"
)

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}
	c := new(Cipher)
	c.subKeys = generateSubKeys(key)
	c.block1 = make([]uint32, 4)
	c.block2 = make([]byte, 16)
	return c, nil
}

type Cipher struct {
	subKeys []uint32
	block1  []uint32
	block2  []byte
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

func (c *Cipher) Encrypt(dst, src []byte) {
	cryptBlock(c.subKeys, c.block1, c.block2, dst, src, false)
}

func (c *Cipher) Decrypt(dst, src []byte) {
	cryptBlock(c.subKeys, c.block1, c.block2, dst, src, true)
}

func CBC(key []byte, in []byte, mode bool) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, errors.New("sm4: invalid key size " + strconv.Itoa(len(key)))
	}
	var inData []byte
	if mode {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}
	iv := make([]byte, BlockSize)
	copy(iv, iv)
	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if mode {
		for i := 0; i < len(inData)/16; i++ {
			inTmp := xor(inData[i*16:i*16+16], iv)
			outTmp := make([]byte, 16)
			c.Encrypt(outTmp, inTmp)
			copy(out[i*16:i*16+16], outTmp)
			iv = outTmp
		}
	} else {
		for i := 0; i < len(inData)/16; i++ {
			inTmp := inData[i*16 : i*16+16]
			outTmp := make([]byte, 16)
			c.Decrypt(outTmp, inTmp)
			outTmp = xor(outTmp, iv)
			copy(out[i*16:i*16+16], outTmp)
			iv = inTmp
		}
		out, _ = pkcs7UnPadding(out)
	}
	return
}

func ECB(key []byte, in []byte, mode bool) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, errors.New("sm4: invalid key size " + strconv.Itoa(len(key)))
	}
	var inData []byte
	if mode {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}
	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if mode {
		for i := 0; i < len(inData)/16; i++ {
			inTmp := inData[i*16 : i*16+16]
			outTmp := make([]byte, 16)
			c.Encrypt(outTmp, inTmp)
			copy(out[i*16:i*16+16], outTmp)
		}
	} else {
		for i := 0; i < len(inData)/16; i++ {
			inTmp := inData[i*16 : i*16+16]
			outTmp := make([]byte, 16)
			c.Decrypt(outTmp, inTmp)
			copy(out[i*16:i*16+16], outTmp)
		}
		out, _ = pkcs7UnPadding(out)
	}
	return
}

func CFB(key []byte, in []byte, mode bool) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, errors.New("sm4: invalid key size " + strconv.Itoa(len(key)))
	}
	var inData []byte
	if mode {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}
	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	K := make([]byte, BlockSize)
	cipherBlock := make([]byte, BlockSize)
	plainBlock := make([]byte, BlockSize)
	if mode {
		for i := 0; i < len(inData)/16; i++ {
			if i == 0 {
				c.Encrypt(K, iv)
				cipherBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
				copy(out[i*16:i*16+16], cipherBlock)
				continue
			}
			c.Encrypt(K, cipherBlock)
			cipherBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
			copy(out[i*16:i*16+16], cipherBlock)
		}
	} else {
		var i = 0
		for ; i < len(inData)/16; i++ {
			if i == 0 {
				c.Encrypt(K, iv)
				plainBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
				copy(out[i*16:i*16+16], plainBlock)
				continue
			}
			c.Encrypt(K, inData[(i-1)*16:(i-1)*16+16])
			plainBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
			copy(out[i*16:i*16+16], plainBlock)

		}

		out, _ = pkcs7UnPadding(out)
	}

	return
}

func OFB(key []byte, in []byte, mode bool) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, errors.New("sm4: invalid key size " + strconv.Itoa(len(key)))
	}
	var inData []byte
	if mode {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}

	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}

	K := make([]byte, BlockSize)
	cipherBlock := make([]byte, BlockSize)
	plainBlock := make([]byte, BlockSize)
	shiftIV := make([]byte, BlockSize)
	if mode {
		for i := 0; i < len(inData)/16; i++ {
			if i == 0 {
				c.Encrypt(K, iv)
				cipherBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
				copy(out[i*16:i*16+16], cipherBlock)
				copy(shiftIV, K[:BlockSize])
				continue
			}
			c.Encrypt(K, shiftIV)
			cipherBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
			copy(out[i*16:i*16+16], cipherBlock)
			copy(shiftIV, K[:BlockSize])
		}

	} else {
		for i := 0; i < len(inData)/16; i++ {
			if i == 0 {
				c.Encrypt(K, iv)
				plainBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
				copy(out[i*16:i*16+16], plainBlock)
				copy(shiftIV, K[:BlockSize])
				continue
			}
			c.Encrypt(K, shiftIV)
			plainBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
			copy(out[i*16:i*16+16], plainBlock)
			copy(shiftIV, K[:BlockSize])
		}
		out, _ = pkcs7UnPadding(out)
	}

	return
}

func GCM(key []byte, iv, in, p []byte, mode bool) ([]byte, []byte, error) {
	if len(key) != BlockSize {
		return nil, nil, errors.New("sm4: invalid key size " + strconv.Itoa(len(key)))
	}
	if mode {
		C, T := GCMEncrypt(key, iv, in, p)
		return C, T, nil
	} else {
		P, _T := GCMDecrypt(key, iv, in, p)
		return P, _T, nil
	}
}

func GCMEncrypt(k, iv, p, a []byte) (c, tag []byte) {
	v := func(m, v int) (int, int) {
		if m == 0 && v != 0 {
			m = 1
			v = v * 8
		} else if m != 0 && v == 0 {
			v = BlockSize * 8
		} else if m != 0 && v != 0 {
			m = m + 1
			v = v * 8
		} else { //m==0 && v==0
			m = 1
			v = 0
		}
		return m, v
	}
	n := len(p) / BlockSize
	u := len(p) % BlockSize
	n, u = v(n, u)
	h := getH(k)
	y0 := getY0(h, iv)
	y := make([]byte, BlockSize*(n+1))
	y = incr(n+1, y0)
	cph, err := NewCipher(k)
	if err != nil {
		panic(err)
	}
	enc := make([]byte, BlockSize)
	c = make([]byte, len(p))
	for i := 1; i <= n-1; i++ {
		cph.Encrypt(enc, y[i*BlockSize:i*BlockSize+BlockSize])
		copy(c[(i-1)*BlockSize:(i-1)*BlockSize+BlockSize], addition(p[(i-1)*BlockSize:(i-1)*BlockSize+BlockSize], enc))
	}
	cph.Encrypt(enc, y[n*BlockSize:n*BlockSize+BlockSize])
	out := msb(u, enc)
	copy(c[(n-1)*BlockSize:], addition(p[(n-1)*BlockSize:], out))
	cph.Encrypt(enc, y0)
	t := 128
	tag = msb(t, addition(enc, gHASH(h, a, c)))
	return c, tag
}

func GCMDecrypt(k, iv, c, a []byte) (p, tag []byte) {
	v := func(m, v int) (int, int) {
		if m == 0 && v != 0 {
			m = 1
			v = v * 8
		} else if m != 0 && v == 0 {
			v = BlockSize * 8
		} else if m != 0 && v != 0 {
			m = m + 1
			v = v * 8
		} else { //m==0 && v==0
			m = 1
			v = 0
		}
		return m, v
	}
	h := getH(k)
	y0 := getY0(h, iv)
	enc := make([]byte, BlockSize)
	cph, err := NewCipher(k)
	if err != nil {
		panic(err)
	}
	cph.Encrypt(enc, y0)
	t := 128
	tag = msb(t, addition(enc, gHASH(h, a, c)))
	n := len(c) / BlockSize
	u := len(c) % BlockSize
	n, u = v(n, u)
	y := make([]byte, BlockSize*(n+1))
	y = incr(n+1, y0)
	p = make([]byte, BlockSize*n)
	for i := 1; i <= n; i++ {
		cph.Encrypt(enc, y[i*BlockSize:i*BlockSize+BlockSize])
		copy(p[(i-1)*BlockSize:(i-1)*BlockSize+BlockSize], addition(c[(i-1)*BlockSize:(i-1)*BlockSize+BlockSize], enc))
	}
	cph.Encrypt(enc, y[n*BlockSize:n*BlockSize+BlockSize])
	out := msb(u, enc)
	copy(p[(n-1)*BlockSize:], addition(c[(n-1)*BlockSize:], out))
	return p, tag
}
