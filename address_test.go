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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/umitop/libumi"
)

func TestBech32(t *testing.T) {
	exp := "umi1u3dam33jaf64z4s008g7su62j4za72ljqff9dthsataq8k806nfsgrhdhg"
	adr, _ := libumi.NewAddressFromBech32(exp)
	act := adr.Bech32()

	if exp != act {
		t.Fatalf("Expected: %s, got: %s", exp, act)
	}
}

func TestKey(t *testing.T) {
	exp := make([]byte, ed25519.PublicKeySize)
	_, _ = rand.Read(exp)

	act := libumi.NewAddressFromPublicKey(exp).PublicKey()

	if !bytes.Equal(exp, act) {
		t.Fatalf("Expected: %x, got: %x", exp, act)
	}
}

func TestPrefix(t *testing.T) {
	tests := []struct {
		prefix string
	}{
		{"genesis"},
		{"aaa"},
		{"zzz"},
		{"umi"},
	}

	for _, test := range tests {
		exp := test.prefix
		act := libumi.NewAddressWithPrefix(exp).Prefix()

		if exp != act {
			t.Fatalf("Expected: %s, got: %s", exp, act)
		}
	}
}


func TestFromBech32(t *testing.T) {
	tests := []struct {
		bech32 string
	}{
		{"umi1lllllllllllllllllllllllllllllllllllllllllllllllllllsp2pfg9"},
		{"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5zcpj"},
		{"genesis1llllllllllllllllllllllllllllllllllllllllllllllllllls5c7uy0"},
		{"genesis1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkxaddc"},
		{"aaa1nfgzzgkr3nd69jes5kw87s2tuv46mhmrqpnw8ksffaujycenxx6sl48tkv"},
	}

	for _, test := range tests {
		_, err := libumi.NewAddressFromBech32(test.bech32)

		if err != nil {
			t.Fatalf("Expected: nil, got: %v", err)
		}
	}
}

func TestFromBech32Error(t *testing.T) {
	tests := []struct {
		bech32 string
		err    error
	}{
		{"geneziz1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwa7qv0", libumi.ErrAddrInvalidPrefix},
		{"111111qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm79fea", libumi.ErrAddrInvalidPrefix},
		{"abcde1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkkv6m4", libumi.ErrAddrInvalidPrefix},
		{"um1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj8455g", libumi.ErrAddrInvalidPrefix},
		{"+++1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2trd4a", libumi.ErrAddrInvalidPrefix},
		{"1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqugay46", libumi.ErrAddrInvalidPrefix},
		{"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5zcpf", libumi.ErrBechInvalidChecksum},
		{"umi1iqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5zcpj", libumi.ErrBechInvalidCharacter},
		{"umilqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqr5zcpj", libumi.ErrBechMissingSeparator},
		{"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqu5fmc9", libumi.ErrBechInvalidLength},
		{"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq63dha7", libumi.ErrBechInvalidLength},
		{"umi1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqlfceute", libumi.ErrBechInvalidData},
	}

	for _, test := range tests {
		_, err := libumi.NewAddressFromBech32(test.bech32)

		if !errors.Is(err, test.err) {
			t.Log(test.bech32)
			t.Fatalf("Expected: %v, got: %v", test.err, err)
		}
	}
}
