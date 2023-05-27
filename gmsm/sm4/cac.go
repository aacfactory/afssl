package sm4

func rl(x uint32, i uint8) uint32 { return (x << (i % 32)) | (x >> (32 - (i % 32))) }

func l0(b uint32) uint32 { return b ^ rl(b, 13) ^ rl(b, 23) }

func feistel0(x0, x1, x2, x3, rk uint32) uint32 { return x0 ^ l0(p(x1^x2^x3^rk)) }

func p(a uint32) uint32 {
	return (uint32(sbox[a>>24]) << 24) ^ (uint32(sbox[(a>>16)&0xff]) << 16) ^ (uint32(sbox[(a>>8)&0xff]) << 8) ^ uint32(sbox[(a)&0xff])
}

func permuteInitialBlock(b []uint32, block []byte) {
	for i := 0; i < 4; i++ {
		b[i] = (uint32(block[i*4]) << 24) | (uint32(block[i*4+1]) << 16) |
			(uint32(block[i*4+2]) << 8) | (uint32(block[i*4+3]))
	}
}

func permuteFinalBlock(b []byte, block []uint32) {
	for i := 0; i < 4; i++ {
		b[i*4] = uint8(block[i] >> 24)
		b[i*4+1] = uint8(block[i] >> 16)
		b[i*4+2] = uint8(block[i] >> 8)
		b[i*4+3] = uint8(block[i])
	}
}

func cryptBlock(subKeys []uint32, b []uint32, r []byte, dst, src []byte, decrypt bool) {
	permuteInitialBlock(b, src)
	_ = b[3]
	if decrypt {
		for i := 0; i < 8; i++ {
			s := subKeys[31-4*i-3 : 31-4*i-3+4]
			x := b[1] ^ b[2] ^ b[3] ^ s[3]
			b[0] = b[0] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[2] ^ b[3] ^ s[2]
			b[1] = b[1] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[1] ^ b[3] ^ s[1]
			b[2] = b[2] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[1] ^ b[2] ^ b[0] ^ s[0]
			b[3] = b[3] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
		}
	} else {
		for i := 0; i < 8; i++ {
			s := subKeys[4*i : 4*i+4]
			x := b[1] ^ b[2] ^ b[3] ^ s[0]
			b[0] = b[0] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[2] ^ b[3] ^ s[1]
			b[1] = b[1] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[1] ^ b[3] ^ s[2]
			b[2] = b[2] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[1] ^ b[2] ^ b[0] ^ s[3]
			b[3] = b[3] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
		}
	}
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	permuteFinalBlock(r, b)
	copy(dst, r)
}

func generateSubKeys(key []byte) []uint32 {
	subs := make([]uint32, 32)
	b := make([]uint32, 4)
	permuteInitialBlock(b, key)
	b[0] ^= fk[0]
	b[1] ^= fk[1]
	b[2] ^= fk[2]
	b[3] ^= fk[3]
	for i := 0; i < 32; i++ {
		subs[i] = feistel0(b[0], b[1], b[2], b[3], ck[i])
		b[0], b[1], b[2], b[3] = b[1], b[2], b[3], subs[i]
	}
	return subs
}

func xor(in, iv []byte) (out []byte) {
	if len(in) != len(iv) {
		return nil
	}
	out = make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = in[i] ^ iv[i]
	}
	return
}

func addition(a, b []byte) (out []byte) {
	Len := len(a)
	if Len != len(b) {
		return nil
	}
	out = make([]byte, Len)
	for i := 0; i < Len; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func getH(key []byte) (h []byte) {
	c, err := NewCipher(key)
	if err != nil {
		panic(err)
	}
	h = make([]byte, BlockSize)
	c.Encrypt(h, make([]byte, BlockSize))
	return
}

func rightShift(v []byte) {
	n := len(v)
	for i := n - 1; i >= 0; i-- {
		v[i] = v[i] >> 1
		if i != 0 {
			v[i] = ((v[i-1] & 0x01) << 7) | v[i]
		}
	}
}

func findYi(Y []byte, index int) int {
	var temp byte
	i := uint(index)
	temp = Y[i/8]
	temp = temp >> (7 - i%8)
	if temp&0x01 == 1 {
		return 1
	} else {
		return 0
	}
}

func multiplication(x, y []byte) (z []byte) {
	r := make([]byte, BlockSize)
	r[0] = 0xe1
	z = make([]byte, BlockSize)
	V := make([]byte, BlockSize)
	copy(V, x)
	for i := 0; i <= 127; i++ {
		if findYi(y, i) == 1 {
			z = addition(z, V)
		}
		if V[BlockSize-1]&0x01 == 0 {
			rightShift(V)
		} else {
			rightShift(V)
			V = addition(V, r)
		}
	}
	return z
}

func gHASH(h []byte, a []byte, c []byte) (x []byte) {
	cv := func(m, v int) (int, int) {
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
	m := len(a) / BlockSize
	v := len(a) % BlockSize
	m, v = cv(m, v)

	n := len(c) / BlockSize
	u := len(c) % BlockSize
	n, u = cv(n, u)

	x = make([]byte, BlockSize*(m+n+2)) //X0 = 0
	for i := 0; i < BlockSize; i++ {
		x[i] = 0x00
	}

	for i := 1; i <= m-1; i++ {
		copy(x[i*BlockSize:i*BlockSize+BlockSize], multiplication(addition(x[(i-1)*BlockSize:(i-1)*BlockSize+BlockSize], a[(i-1)*BlockSize:(i-1)*BlockSize+BlockSize]), h)) //A 1-->m-1 对于数组来说是 0-->m-2
	}

	zeros := make([]byte, (128-v)/8)
	Am := make([]byte, v/8)
	copy(Am[:], a[(m-1)*BlockSize:])
	Am = append(Am, zeros...)
	copy(x[m*BlockSize:m*BlockSize+BlockSize], multiplication(addition(x[(m-1)*BlockSize:(m-1)*BlockSize+BlockSize], Am), h))

	for i := m + 1; i <= (m + n - 1); i++ {
		copy(x[i*BlockSize:i*BlockSize+BlockSize], multiplication(addition(x[(i-1)*BlockSize:(i-1)*BlockSize+BlockSize], c[(i-m-1)*BlockSize:(i-m-1)*BlockSize+BlockSize]), h))
	}

	zeros = make([]byte, (128-u)/8)
	Cn := make([]byte, u/8)
	copy(Cn[:], c[(n-1)*BlockSize:])
	Cn = append(Cn, zeros...)
	copy(x[(m+n)*BlockSize:(m+n)*BlockSize+BlockSize], multiplication(addition(x[(m+n-1)*BlockSize:(m+n-1)*BlockSize+BlockSize], Cn), h))

	var lenAB []byte
	calculateLenToBytes := func(len int) []byte {
		data := make([]byte, 8)
		data[0] = byte((len >> 56) & 0xff)
		data[1] = byte((len >> 48) & 0xff)
		data[2] = byte((len >> 40) & 0xff)
		data[3] = byte((len >> 32) & 0xff)
		data[4] = byte((len >> 24) & 0xff)
		data[5] = byte((len >> 16) & 0xff)
		data[6] = byte((len >> 8) & 0xff)
		data[7] = byte((len >> 0) & 0xff)
		return data
	}
	lenAB = append(lenAB, calculateLenToBytes(len(a))...)
	lenAB = append(lenAB, calculateLenToBytes(len(c))...)
	copy(x[(m+n+1)*BlockSize:(m+n+1)*BlockSize+BlockSize], multiplication(addition(x[(m+n)*BlockSize:(m+n)*BlockSize+BlockSize], lenAB), h))
	return x[(m+n+1)*BlockSize : (m+n+1)*BlockSize+BlockSize]
}

func getY0(h, iv []byte) []byte {
	if len(iv)*8 == 96 {
		zero31one1 := []byte{0x00, 0x00, 0x00, 0x01}
		iv = append(iv, zero31one1...)
		return iv
	} else {
		return gHASH(h, []byte{}, iv)
	}
}

func incr(n int, yi []byte) (yii []byte) {
	yii = make([]byte, BlockSize*n)
	copy(yii, yi)
	addY1 := func(yi, yii []byte) {
		copy(yii[:], yi[:])
		length := len(yi)
		var rc byte = 0x00
		for i := length - 1; i >= 0; i-- {
			if i == length-1 {
				if yii[i] < 0xff {
					yii[i] = yii[i] + 0x01
					rc = 0x00
				} else {
					yii[i] = 0x00
					rc = 0x01
				}
			} else {
				if yii[i]+rc < 0xff {
					yii[i] = yii[i] + rc
					rc = 0x00
				} else {
					yii[i] = 0x00
					rc = 0x01
				}
			}
		}
	}
	for i := 1; i < n; i++ {
		addY1(yii[(i-1)*BlockSize:(i-1)*BlockSize+BlockSize], yii[i*BlockSize:i*BlockSize+BlockSize])
	}
	return yii
}

func msb(len int, S []byte) (out []byte) {
	return S[:len/8]
}
