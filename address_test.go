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

package libumi_test

import (
	"errors"
	"testing"

	"github.com/umitop/libumi"
)

func TestBech32(t *testing.T) {
	tests := []string{
		"umi1lllllllllllllllllllllllllllllllllllllllllllllllllllsp2pfg9",
		"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5zcpj",
		"genesis1llllllllllllllllllllllllllllllllllllllllllllllllllls5c7uy0",
		"genesis1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkxaddc",
		"aaa1nfgzzgkr3nd69jes5kw87s2tuv46mhmrqpnw8ksffaujycenxx6sl48tkv",
	}

	for _, test := range tests {
		adr, err := libumi.NewAddressFromBech32(test)
		if err != nil {
			t.Fatalf("%v Expected: nil, got: %v", test, err)
		}

		if adr.Bech32() != test {
			t.Fatalf("Expected: %s, got: %s", test, adr.Bech32())
		}
	}
}

func TestBech32Error(t *testing.T) {
	tests := []string{
		"g1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwa7qv0",
		"geneziz1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwa7qv0",
		"111111qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm79fea",
		"abcde1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkkv6m4",
		"um1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj8455g",
		"+++1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2trd4a",
		"1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqugay46",
		"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5zcpf",
		"umi1iqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5zcpj",
		"umilqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5zcpj",
		"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqu5fmc9",
		"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq63dha7",
		"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlfceute",
	}

	for _, test := range tests {
		_, err := libumi.NewAddressFromBech32(test)

		if !errors.Is(err, libumi.ErrInvalidAddress) {
			t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidAddress, err)
		}
	}
}

func TestVerifyAddressInvalidLength(t *testing.T) {
	tests := [][]byte{
		nil,
		make([]byte, 149),
	}

	for _, test := range tests {
		act := libumi.VerifyAddress(test)
		exp := libumi.ErrInvalidLength

		if !errors.Is(act, exp) {
			t.Fatalf("Expected: %v, got: %v", exp, act)
		}
	}
}

func TestAddress_Version(t *testing.T) {
	act := uint16(7)
	exp := libumi.NewAddress().SetVersion(act).Version()

	if act != exp {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

/*
func TestVerifyAddressInvalidVersion(t *testing.T) {
	tests := []uint16{
		1,
	}

	for _, test := range tests {
		adr := libumi.NewAddress().SetVersion(test)

		act := libumi.VerifyAddress(adr)
		exp := libumi.ErrInvalidPrefix

		if !errors.Is(act, exp) {
			t.Fatalf("Expected: %v, got: %v", exp, act)
		}
	}
}
*/
