// Copyright (c) 2020 UMI
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package libumi

import (
	"encoding/binary"
	"errors"
	"strings"
)

// AddressLength ...
const AddressLength = 34

const (
	prefixAlphabet = " abcdefghijklmnopqrstuvwxyz"
	bech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	verGenesis     = 0
	verUmi         = 21929
)

// ErrInvalidAddress ...
var ErrInvalidAddress = errors.New("invalid address")

// Address ...
type Address []byte

// NewAddress ...
func NewAddress() Address {
	adr := make(Address, AddressLength)
	adr.SetPrefix("umi")

	return adr
}

// NewAddressFromBech32 ...
func NewAddressFromBech32(s string) (Address, error) {
	pfx, pub, err := bech32Decode(s)
	if err != nil {
		return nil, err
	}

	adr := NewAddress()
	adr.SetPrefix(pfx)
	adr.SetPublicKey(pub)

	return adr, nil
}

// Bech32 ...
func (a Address) Bech32() string {
	return bech32Encode(a.Prefix(), a.PublicKey())
}

// Prefix ...
func (a Address) Prefix() string {
	return addressVersionToPrefix(a[0], a[1])
}

// SetPrefix ...
func (a Address) SetPrefix(s string) {
	a[0], a[1] = prefixToAddressVersion(s)
}

// PublicKey ...
func (a Address) PublicKey() []byte {
	return a[2:34]
}

// SetPublicKey ...
func (a Address) SetPublicKey(b []byte) {
	copy(a[2:34], b)
}

// Version ...
func (a Address) Version() uint16 {
	return binary.BigEndian.Uint16(a[0:2])
}

func bech32Encode(pfx string, pub []byte) string {
	data := bech32Convert8to5(pub)

	var s strings.Builder

	s.Grow(62)
	s.WriteString(pfx)
	s.WriteString("1")
	s.Write(data)
	s.Write(bech32CreateChecksum(pfx, data))

	return s.String()
}

func bech32Decode(bech string) (pfx string, data []byte, err error) {
	if len(bech) != 62 && len(bech) != 66 {
		return pfx, data, ErrInvalidAddress
	}

	bech = strings.ToLower(bech)

	sep := strings.LastIndexByte(bech, '1')
	if sep == -1 {
		return pfx, data, ErrInvalidAddress
	}

	data, err = bech32Convert5to8([]byte(bech[sep+1 : len(bech)-6]))
	if err != nil {
		return pfx, nil, err
	}

	pfx = bech[0:sep]

	if !bech32VerifyChecksum(pfx, []byte(bech[sep+1:])) {
		return pfx, nil, ErrInvalidAddress
	}

	return pfx, data[0:32], err
}

func bech32Convert5to8(data []byte) (out []byte, err error) {
	var acc, bits int

	out = make([]byte, 0, 32)

	for _, b := range data {
		v := strings.IndexByte(bech32Alphabet, b)
		if v == -1 {
			return nil, ErrInvalidAddress
		}

		acc = (acc << 5) | v
		bits += 5

		for bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits&0xff))
		}
	}

	if bits >= 5 || (acc<<(8-bits))&0xff > 0 {
		return nil, ErrInvalidAddress
	}

	return out, err
}

func bech32Convert8to5(data []byte) []byte {
	var acc, bits int

	res := make([]byte, 0, 52)

	for _, b := range data {
		acc = (acc << 8) | int(b)
		bits += 8

		for bits >= 5 {
			bits -= 5
			res = append(res, bech32Alphabet[acc>>bits&0x1f])
		}
	}

	if bits > 0 {
		res = append(res, bech32Alphabet[acc<<(5-bits)&0x1f])
	}

	return res
}

func bech32CreateChecksum(prefix string, data []byte) []byte {
	b := bech32PrefixExpand(prefix)

	for _, v := range data {
		b = append(b, strings.IndexByte(bech32Alphabet, v))
	}

	b = append(b, 0, 0, 0, 0, 0, 0)
	p := bech32PolyMod(b) ^ 1

	c := make([]byte, 6)
	for i := range c {
		c[i] = bech32Alphabet[byte((p>>uint(5*(5-i)))&31)]
	}

	return c
}

func bech32PolyMod(values []int) int {
	gen := [...]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1

	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v

		for i, g := range gen {
			if (b>>uint(i))&1 == 1 {
				chk ^= g
			}
		}
	}

	return chk
}

func bech32PrefixExpand(p string) []int {
	l := len(p)
	r := make([]int, l*2+1, l*2+59)

	for i, s := range p {
		r[i] = int(s) >> 5
		r[i+l+1] = int(s) & 31
	}

	return r
}

func bech32VerifyChecksum(prefix string, data []byte) bool {
	b := bech32PrefixExpand(prefix)

	for _, v := range data {
		b = append(b, strings.IndexByte(bech32Alphabet, v))
	}

	return bech32PolyMod(b) == 1
}

func prefixToAddressVersion(s string) (a byte, b byte) {
	if s != "genesis" {
		a = ((s[0] - 96) << 2) | ((s[1] - 96) >> 3)
		b = ((s[1] - 96) << 5) | (s[2] - 96)
	}

	return a, b
}

func addressVersionToPrefix(a, b byte) string {
	if a == 0 && b == 0 {
		return "genesis"
	}

	var s strings.Builder

	s.Grow(3)
	s.WriteByte(((a >> 2) & 31) + 96)
	s.WriteByte((((a & 3) << 3) | (b >> 5)) + 96)
	s.WriteByte((b & 31) + 96)

	return s.String()
}
