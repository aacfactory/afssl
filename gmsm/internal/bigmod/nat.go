package bigmod

import (
	"errors"
	"math/big"
	"math/bits"
)

const (
	_W    = bits.UintSize - 1
	_MASK = (1 << _W) - 1
)

type choice uint

func not(c choice) choice { return 1 ^ c }

const yes = choice(1)
const no = choice(0)

func ctSelect(on choice, x, y uint) uint {
	mask := -uint(on)
	return y ^ (mask & (y ^ x))
}

func ctEq(x, y uint) choice {
	_, c1 := bits.Sub(x, y, 0)
	_, c2 := bits.Sub(y, x, 0)
	return not(choice(c1 | c2))
}

func ctGeq(x, y uint) choice {
	_, carry := bits.Sub(x, y, 0)
	return not(choice(carry))
}

type Nat struct {
	limbs []uint
}

const preallocTarget = 2048
const preallocLimbs = (preallocTarget + _W - 1) / _W

func NewNat() *Nat {
	limbs := make([]uint, 0, preallocLimbs)
	return &Nat{limbs}
}

func (x *Nat) expand(n int) *Nat {
	if len(x.limbs) > n {
		panic("bigmod: internal error: shrinking nat")
	}
	if cap(x.limbs) < n {
		newLimbs := make([]uint, n)
		copy(newLimbs, x.limbs)
		x.limbs = newLimbs
		return x
	}
	extraLimbs := x.limbs[len(x.limbs):n]
	for i := range extraLimbs {
		extraLimbs[i] = 0
	}
	x.limbs = x.limbs[:n]
	return x
}

func (x *Nat) reset(n int) *Nat {
	if cap(x.limbs) < n {
		x.limbs = make([]uint, n)
		return x
	}
	for i := range x.limbs {
		x.limbs[i] = 0
	}
	x.limbs = x.limbs[:n]
	return x
}

func (x *Nat) Set(y *Nat) *Nat {
	x.reset(len(y.limbs))
	copy(x.limbs, y.limbs)
	return x
}

func (x *Nat) SetBig(n *big.Int) *Nat {
	requiredLimbs := (n.BitLen() + _W - 1) / _W
	x.reset(requiredLimbs)

	outI := 0
	shift := 0
	limbs := n.Bits()
	for i := range limbs {
		xi := uint(limbs[i])
		x.limbs[outI] |= (xi << shift) & _MASK
		outI++
		if outI == requiredLimbs {
			return x
		}
		x.limbs[outI] = xi >> (_W - shift)
		shift++ // this assumes bits.UintSize - _W = 1
		if shift == _W {
			shift = 0
			outI++
		}
	}
	return x
}

func (x *Nat) Bytes(m *Modulus) []byte {
	bytes := make([]byte, m.Size())
	shift := 0
	outI := len(bytes) - 1
	for _, limb := range x.limbs {
		remainingBits := _W
		for remainingBits >= 8 {
			bytes[outI] |= byte(limb) << shift
			consumed := 8 - shift
			limb >>= consumed
			remainingBits -= consumed
			shift = 0
			outI--
			if outI < 0 {
				return bytes
			}
		}
		bytes[outI] = byte(limb)
		shift = remainingBits
	}
	return bytes
}

func (x *Nat) SetBytes(b []byte, m *Modulus) (*Nat, error) {
	if err := x.setBytes(b, m); err != nil {
		return nil, err
	}
	if x.cmpGeq(m.nat) == yes {
		return nil, errors.New("input overflows the modulus")
	}
	return x, nil
}

func (x *Nat) SetOverflowingBytes(b []byte, m *Modulus) (*Nat, error) {
	if err := x.setBytes(b, m); err != nil {
		return nil, err
	}
	leading := _W - bitLen(x.limbs[len(x.limbs)-1])
	if leading < m.leading {
		return nil, errors.New("input overflows the modulus")
	}
	x.sub(x.cmpGeq(m.nat), m.nat)
	return x, nil
}

func (x *Nat) setBytes(b []byte, m *Modulus) error {
	outI := 0
	shift := 0
	x.resetFor(m)
	for i := len(b) - 1; i >= 0; i-- {
		bi := b[i]
		x.limbs[outI] |= uint(bi) << shift
		shift += 8
		if shift >= _W {
			shift -= _W
			x.limbs[outI] &= _MASK
			overflow := bi >> (8 - shift)
			outI++
			if outI >= len(x.limbs) {
				if overflow > 0 || i > 0 {
					return errors.New("input overflows the modulus")
				}
				break
			}
			x.limbs[outI] = uint(overflow)
		}
	}
	return nil
}

func (x *Nat) Equal(y *Nat) choice {
	// Eliminate bounds checks in the loop.
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	equal := yes
	for i := 0; i < size; i++ {
		equal &= ctEq(xLimbs[i], yLimbs[i])
	}
	return equal
}

func (x *Nat) IsZero() choice {
	size := len(x.limbs)
	xLimbs := x.limbs[:size]

	zero := yes
	for i := 0; i < size; i++ {
		zero &= ctEq(xLimbs[i], 0)
	}
	return zero
}

func (x *Nat) cmpGeq(y *Nat) choice {
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	var c uint
	for i := 0; i < size; i++ {
		c = (xLimbs[i] - yLimbs[i] - c) >> _W
	}
	return not(choice(c))
}

func (x *Nat) assign(on choice, y *Nat) *Nat {
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	for i := 0; i < size; i++ {
		xLimbs[i] = ctSelect(on, yLimbs[i], xLimbs[i])
	}
	return x
}

func (x *Nat) add(on choice, y *Nat) (c uint) {
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	for i := 0; i < size; i++ {
		res := xLimbs[i] + yLimbs[i] + c
		xLimbs[i] = ctSelect(on, res&_MASK, xLimbs[i])
		c = res >> _W
	}
	return
}

func (x *Nat) sub(on choice, y *Nat) (c uint) {
	size := len(x.limbs)
	xLimbs := x.limbs[:size]
	yLimbs := y.limbs[:size]

	for i := 0; i < size; i++ {
		res := xLimbs[i] - yLimbs[i] - c
		xLimbs[i] = ctSelect(on, res&_MASK, xLimbs[i])
		c = res >> _W
	}
	return
}

type Modulus struct {
	nat     *Nat
	leading int  // number of leading zeros in the modulus
	m0inv   uint // -nat.limbs[0]⁻¹ mod _W
	rr      *Nat // R*R for montgomeryRepresentation
}

func rr(m *Modulus) *Nat {
	rr := NewNat().ExpandFor(m)
	n := len(rr.limbs)
	rr.limbs[n-1] = 1
	for i := n - 1; i < 2*n; i++ {
		rr.shiftIn(0, m) // x = x * 2^_W mod m
	}
	return rr
}

func minusInverseModW(x uint) uint {
	y := x
	for i := 0; i < 5; i++ {
		y = y * (2 - x*y)
	}
	return (1 << _W) - (y & _MASK)
}

func NewModulusFromBig(n *big.Int) *Modulus {
	m := &Modulus{}
	m.nat = NewNat().SetBig(n)
	m.leading = _W - bitLen(m.nat.limbs[len(m.nat.limbs)-1])
	m.m0inv = minusInverseModW(m.nat.limbs[0])
	m.rr = rr(m)
	return m
}

func bitLen(n uint) int {
	var len int
	for n != 0 {
		len++
		n >>= 1
	}
	return len
}

func (m *Modulus) Size() int {
	return (m.BitLen() + 7) / 8
}

func (m *Modulus) BitLen() int {
	return len(m.nat.limbs)*_W - int(m.leading)
}

func (m *Modulus) Nat() *Nat {
	return m.nat
}

func (x *Nat) shiftIn(y uint, m *Modulus) *Nat {
	return x.shiftInNat(y, m.nat)
}

func (x *Nat) shiftInNat(y uint, m *Nat) *Nat {
	d := NewNat().reset(len(m.limbs))

	size := len(m.limbs)
	xLimbs := x.limbs[:size]
	dLimbs := d.limbs[:size]
	mLimbs := m.limbs[:size]

	needSubtraction := no
	for i := _W - 1; i >= 0; i-- {
		carry := (y >> i) & 1
		var borrow uint
		for i := 0; i < size; i++ {
			l := ctSelect(needSubtraction, dLimbs[i], xLimbs[i])

			res := l<<1 + carry
			xLimbs[i] = res & _MASK
			carry = res >> _W

			res = xLimbs[i] - mLimbs[i] - borrow
			dLimbs[i] = res & _MASK
			borrow = res >> _W
		}
		needSubtraction = ctEq(carry, borrow)
	}
	return x.assign(needSubtraction, d)
}

func (out *Nat) Mod(x *Nat, m *Modulus) *Nat {
	return out.ModNat(x, m.nat)
}

func (out *Nat) ModNat(x *Nat, m *Nat) *Nat {
	out.reset(len(m.limbs))
	i := len(x.limbs) - 1
	start := len(m.limbs) - 2
	if i < start {
		start = i
	}
	for j := start; j >= 0; j-- {
		out.limbs[j] = x.limbs[i]
		i--
	}
	for i >= 0 {
		out.shiftInNat(x.limbs[i], m)
		i--
	}
	return out
}

func (out *Nat) ExpandFor(m *Modulus) *Nat {
	return out.expand(len(m.nat.limbs))
}

func (out *Nat) resetFor(m *Modulus) *Nat {
	return out.reset(len(m.nat.limbs))
}

func (x *Nat) Sub(y *Nat, m *Modulus) *Nat {
	underflow := x.sub(yes, y)
	x.add(choice(underflow), m.nat)
	return x
}

// Add computes x = x + y mod m.
//
// The length of both operands must be the same as the modulus. Both operands
// must already be reduced modulo m.
func (x *Nat) Add(y *Nat, m *Modulus) *Nat {
	overflow := x.add(yes, y)
	underflow := not(x.cmpGeq(m.nat)) // x < m

	// Three cases are possible:
	//
	//   - overflow = 0, underflow = 0
	//
	// In this case, addition fits in our limbs, but we can still subtract away
	// m without an underflow, so we need to perform the subtraction to reduce
	// our result.
	//
	//   - overflow = 0, underflow = 1
	//
	// The addition fits in our limbs, but we can't subtract m without
	// underflowing. The result is already reduced.
	//
	//   - overflow = 1, underflow = 1
	//
	// The addition does not fit in our limbs, and the subtraction's borrow
	// would cancel out with the addition's carry. We need to subtract m to
	// reduce our result.
	//
	// The overflow = 1, underflow = 0 case is not possible, because y is at
	// most m - 1, and if adding m - 1 overflows, then subtracting m must
	// necessarily underflow.
	needSubtraction := ctEq(overflow, uint(underflow))

	x.sub(needSubtraction, m.nat)
	return x
}

// montgomeryRepresentation calculates x = x * R mod m, with R = 2^(_W * n) and
// n = len(m.nat.limbs).
//
// Faster Montgomery multiplication replaces standard modular multiplication for
// numbers in this representation.
//
// This assumes that x is already reduced mod m.
func (x *Nat) montgomeryRepresentation(m *Modulus) *Nat {
	// A Montgomery multiplication (which computes a * b / R) by R * R works out
	// to a multiplication by R, which takes the value out of the Montgomery domain.
	return x.montgomeryMul(NewNat().Set(x), m.rr, m)
}

// montgomeryReduction calculates x = x / R mod m, with R = 2^(_W * n) and
// n = len(m.nat.limbs).
//
// This assumes that x is already reduced mod m.
func (x *Nat) montgomeryReduction(m *Modulus) *Nat {
	// By Montgomery multiplying with 1 not in Montgomery representation, we
	// convert out back from Montgomery representation, because it works out to
	// dividing by R.
	t0 := NewNat().Set(x)
	t1 := NewNat().ExpandFor(m)
	t1.limbs[0] = 1
	return x.montgomeryMul(t0, t1, m)
}

// montgomeryMul calculates d = a * b / R mod m, with R = 2^(_W * n) and
// n = len(m.nat.limbs), using the Montgomery Multiplication technique.
//
// All inputs should be the same length, not aliasing d, and already
// reduced modulo m. d will be resized to the size of m and overwritten.
func (d *Nat) montgomeryMul(a *Nat, b *Nat, m *Modulus) *Nat {
	d.resetFor(m)
	if len(a.limbs) != len(m.nat.limbs) || len(b.limbs) != len(m.nat.limbs) {
		panic("bigmod: invalid montgomeryMul input")
	}

	// See https://bearssl.org/bigint.html#montgomery-reduction-and-multiplication
	// for a description of the algorithm implemented mostly in montgomeryLoop.
	// See Add for how overflow, underflow, and needSubtraction relate.
	overflow := montgomeryLoop(d.limbs, a.limbs, b.limbs, m.nat.limbs, m.m0inv)
	underflow := not(d.cmpGeq(m.nat)) // d < m
	needSubtraction := ctEq(overflow, uint(underflow))
	d.sub(needSubtraction, m.nat)

	return d
}

func montgomeryLoopGeneric(d, a, b, m []uint, m0inv uint) (overflow uint) {
	// Eliminate bounds checks in the loop.
	size := len(d)
	a = a[:size]
	b = b[:size]
	m = m[:size]

	for _, ai := range a {
		// This is an unrolled iteration of the loop below with j = 0.
		hi, lo := bits.Mul(ai, b[0])
		z_lo, c := bits.Add(d[0], lo, 0)
		f := (z_lo * m0inv) & _MASK // (d[0] + a[i] * b[0]) * m0inv
		z_hi, _ := bits.Add(0, hi, c)
		hi, lo = bits.Mul(f, m[0])
		z_lo, c = bits.Add(z_lo, lo, 0)
		z_hi, _ = bits.Add(z_hi, hi, c)
		carry := z_hi<<1 | z_lo>>_W

		for j := 1; j < size; j++ {
			// z = d[j] + a[i] * b[j] + f * m[j] + carry <= 2^(2W+1) - 2^(W+1) + 2^W
			hi, lo := bits.Mul(ai, b[j])
			z_lo, c := bits.Add(d[j], lo, 0)
			z_hi, _ := bits.Add(0, hi, c)
			hi, lo = bits.Mul(f, m[j])
			z_lo, c = bits.Add(z_lo, lo, 0)
			z_hi, _ = bits.Add(z_hi, hi, c)
			z_lo, c = bits.Add(z_lo, carry, 0)
			z_hi, _ = bits.Add(z_hi, 0, c)
			d[j-1] = z_lo & _MASK
			carry = z_hi<<1 | z_lo>>_W // carry <= 2^(W+1) - 2
		}

		z := overflow + carry // z <= 2^(W+1) - 1
		d[size-1] = z & _MASK
		overflow = z >> _W // overflow <= 1
	}
	return
}

// Mul calculates x *= y mod m.
//
// x and y must already be reduced modulo m, they must share its announced
// length, and they may not alias.
func (x *Nat) Mul(y *Nat, m *Modulus) *Nat {
	// A Montgomery multiplication by a value out of the Montgomery domain
	// takes the result out of Montgomery representation.
	xR := NewNat().Set(x).montgomeryRepresentation(m) // xR = x * R mod m
	return x.montgomeryMul(xR, y, m)                  // x = xR * y / R mod m
}

// Exp calculates out = x^e mod m.
//
// The exponent e is represented in big-endian order. The output will be resized
// to the size of m and overwritten. x must already be reduced modulo m.
func (out *Nat) Exp(x *Nat, e []byte, m *Modulus) *Nat {
	// We use a 4 bit window. For our RSA workload, 4 bit windows are faster
	// than 2 bit windows, but use an extra 12 nats worth of scratch space.
	// Using bit sizes that don't divide 8 are more complex to implement.

	table := [(1 << 4) - 1]*Nat{ // table[i] = x ^ (i+1)
		// newNat calls are unrolled so they are allocated on the stack.
		NewNat(), NewNat(), NewNat(), NewNat(), NewNat(),
		NewNat(), NewNat(), NewNat(), NewNat(), NewNat(),
		NewNat(), NewNat(), NewNat(), NewNat(), NewNat(),
	}
	table[0].Set(x).montgomeryRepresentation(m)
	for i := 1; i < len(table); i++ {
		table[i].montgomeryMul(table[i-1], table[0], m)
	}

	out.resetFor(m)
	out.limbs[0] = 1
	out.montgomeryRepresentation(m)
	t0 := NewNat().ExpandFor(m)
	t1 := NewNat().ExpandFor(m)
	for _, b := range e {
		for _, j := range []int{4, 0} {
			// Square four times.
			t1.montgomeryMul(out, out, m)
			out.montgomeryMul(t1, t1, m)
			t1.montgomeryMul(out, out, m)
			out.montgomeryMul(t1, t1, m)

			// Select x^k in constant time from the table.
			k := uint((b >> j) & 0b1111)
			for i := range table {
				t0.assign(ctEq(k, uint(i+1)), table[i])
			}

			// Multiply by x^k, discarding the result if k = 0.
			t1.montgomeryMul(out, t0, m)
			out.assign(not(ctEq(k, 0)), t1)
		}
	}

	return out.montgomeryReduction(m)
}
