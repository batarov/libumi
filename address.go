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
	"strings"
)

// AddressLength ...
const AddressLength = 34

const (
	genesis uint16 = 0
	umi     uint16 = 21929
)

// Address ...
type Address []byte

// NewAddress ...
func NewAddress() Address {
	adr := make(Address, AddressLength)
	adr.SetVersion(umi)

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

// Version ...
func (a Address) Version() uint16 {
	return binary.BigEndian.Uint16(a[0:2])
}

// SetVersion ...
func (a Address) SetVersion(v uint16) Address {
	binary.BigEndian.PutUint16(a, v)

	return a
}

// Prefix ...
func (a Address) Prefix() string {
	return versionToPrefix(a[0], a[1])
}

// SetPrefix ...
func (a Address) SetPrefix(s string) Address {
	a[0], a[1] = prefixToVersion(s)

	return a
}

// PublicKey ...
func (a Address) PublicKey() []byte {
	return a[2:34]
}

// SetPublicKey ...
func (a Address) SetPublicKey(b []byte) Address {
	copy(a[2:34], b)

	return a
}

// VerifyAddress ...
func VerifyAddress(b []byte) error {
	return assert(b,
		lengthIs(AddressLength),
		versionIsValid,
	)
}

func prefixToVersion(s string) (a byte, b byte) {
	if s != "genesis" {
		a = ((s[0] - 96) << 2) | ((s[1] - 96) >> 3)
		b = ((s[1] - 96) << 5) | (s[2] - 96)
	}

	return a, b
}

func versionToPrefix(a, b byte) string {
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
