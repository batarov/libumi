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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/umitop/libumi"
)

type txCases struct {
	name string
	data []byte
	exp  error
}

func newTx(ver uint8, sndPfx string, rcpPfx string) libumi.Transaction {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	tx := libumi.NewTransaction().
		SetVersion(ver).
		SetSender(libumi.NewAddress().SetPrefix(sndPfx).SetPublicKey(pub)).
		SetRecipient(libumi.NewAddress().SetPrefix(rcpPfx))

	libumi.SignTransaction(tx, sec)

	return tx
}

func newTxStruct() libumi.Transaction {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	tx := libumi.NewTransaction().
		SetVersion(libumi.CreateStructure).
		SetSender(libumi.NewAddress().SetPrefix("umi").SetPublicKey(pub)).
		SetPrefix("abc").
		SetName("Hello World!").
		SetFeePercent(100).
		SetProfitPercent(500)

	libumi.SignTransaction(tx, sec)

	return tx
}

func txTestCases(t *testing.T, cases []txCases) {
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := libumi.VerifyTransaction(tc.data)
			if !errors.Is(err, tc.exp) {
				t.Fatalf("Expected: %v, got: %v", tc.exp, err)
			}
		})
	}
}

func TestTransaction_ValidGenesis(t *testing.T) {
	tx := newTx(libumi.Genesis, "genesis", "umi")

	err := libumi.VerifyTransaction(tx)
	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestTransaction_ValidBasic(t *testing.T) {
	tx := newTx(libumi.Basic, "umi", "aaa")

	err := libumi.VerifyTransaction(tx)
	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestTransaction_ValidStruct(t *testing.T) {
	tx := newTxStruct()

	err := libumi.VerifyTransaction(tx)
	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestTransaction_ValidAddress(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	tx := libumi.NewTransaction().
		SetVersion(libumi.CreateTransitAddress).
		SetSender(libumi.NewAddress().SetPrefix("umi").SetPublicKey(pub)).
		SetRecipient(libumi.NewAddress().SetPrefix("abc"))

	libumi.SignTransaction(tx, sec)

	err := libumi.VerifyTransaction(tx)
	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestTransaction_Length(t *testing.T) {
	cases := []txCases{
		{
			name: "null",
			data: nil,
			exp:  libumi.ErrInvalidLength,
		},
		{
			name: "too short",
			data: make([]byte, libumi.TxLength-1),
			exp:  libumi.ErrInvalidLength,
		},
		{
			name: "too long",
			data: make([]byte, libumi.TxLength+1),
			exp:  libumi.ErrInvalidLength,
		},
	}

	txTestCases(t, cases)
}

func TestTransaction_InvalidVersion(t *testing.T) {
	tx := libumi.NewTransaction().SetVersion(255)

	err := libumi.VerifyTransaction(tx)
	exp := libumi.ErrInvalidVersion

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestTransaction_InvalidGenesis(t *testing.T) {
	cases := []txCases{
		{
			name: "sender must be genesis",
			data: newTx(libumi.Genesis, "bbb", "umi"),
			exp:  libumi.ErrInvalidSender,
		},
		{
			name: "recipient must be umi",
			data: newTx(libumi.Genesis, "genesis", "cde"),
			exp:  libumi.ErrInvalidRecipient,
		},
	}

	txTestCases(t, cases)
}

func TestTransaction_InvalidBasic(t *testing.T) {
	cases := []txCases{
		{
			name: "sender prefix must be valid",
			data: newTx(libumi.Basic, "}}}", "umi"),
			exp:  libumi.ErrInvalidSender,
		},
		{
			name: "sender and recipient must be not equal",
			data: libumi.NewTransaction().SetSender(libumi.NewAddress()).SetRecipient(libumi.NewAddress()),
			exp:  libumi.ErrInvalidRecipient,
		},
		{
			name: "sender must be not genesis",
			data: newTx(libumi.Basic, "genesis", "qwe"),
			exp:  libumi.ErrInvalidSender,
		},
		{
			name: "recipient must be not genesis",
			data: newTx(libumi.Basic, "ghj", "genesis"),
			exp:  libumi.ErrInvalidRecipient,
		},
		{
			name: "recipient prefix must be valid",
			data: newTx(libumi.Basic, "umi", "{{{"),
			exp:  libumi.ErrInvalidRecipient,
		},
	}

	txTestCases(t, cases)
}

func TestTransaction_InvalidAddress(t *testing.T) {
	cases := []txCases{
		{
			name: "sender must be umi",
			data: newTx(libumi.CreateTransitAddress, "aaa", "asd"),
			exp:  libumi.ErrInvalidSender,
		},
		{
			name: "recipient must not be genesis",
			data: newTx(libumi.CreateTransitAddress, "umi", "genesis"),
			exp:  libumi.ErrInvalidRecipient,
		},
		{
			name: "recipient must not be umi",
			data: newTx(libumi.CreateTransitAddress, "umi", "umi"),
			exp:  libumi.ErrInvalidRecipient,
		},
		{
			name: "recipient prefix must be valid",
			data: newTx(libumi.CreateTransitAddress, "umi", "|||"),
			exp:  libumi.ErrInvalidRecipient,
		},
	}

	txTestCases(t, cases)
}

func TestTransaction_InvalidStruct(t *testing.T) {
	cases := []txCases{
		{
			name: "sender must be umi",
			data: newTxStruct().SetSender(libumi.NewAddress().SetPrefix("aaa")),
			exp:  libumi.ErrInvalidSender,
		},
		{
			name: "prefix can not be umi",
			data: newTxStruct().SetPrefix("umi"),
			exp:  libumi.ErrInvalidPrefix,
		},
		{
			name: "prefix can not be genesis",
			data: newTxStruct().SetPrefix("genesis"),
			exp:  libumi.ErrInvalidPrefix,
		},
		{
			name: "prefix must be valid",
			data: newTxStruct().SetPrefix("}}}"),
			exp:  libumi.ErrInvalidPrefix,
		},
		{
			name: "profit percent must be between 1_00 and 5_00",
			data: newTxStruct().SetProfitPercent(10_00),
			exp:  libumi.ErrInvalidProfitPercent,
		},
		{
			name: "fee percent must be between 0 and 20_00",
			data: newTxStruct().SetFeePercent(23_45),
			exp:  libumi.ErrInvalidFeePercent,
		},
		{
			name: "name length must be 35 bytes or less",
			data: newTxStruct().SetName(strings.Repeat("a", 36)),
			exp:  libumi.ErrInvalidName,
		},
		{
			name: "name must be valid UTF-8 string",
			data: newTxStruct().SetName("\xff\x01\x01\x01"),
			exp:  libumi.ErrInvalidName,
		},
	}

	txTestCases(t, cases)
}

func TestTransaction_InvalidSignature(t *testing.T) {
	tx := newTxStruct().SetPrefix("cba")

	err := libumi.VerifyTransaction(tx)
	exp := libumi.ErrInvalidSignature

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestTransaction_Value(t *testing.T) {
	exp := uint64(42)
	act := libumi.NewTransaction().SetValue(exp).Value()

	if act != exp {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTransaction_Name(t *testing.T) {
	exp := "Hello World 😊"
	act := libumi.NewTransaction().SetName(exp).Name()

	if act != exp {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTransaction_Prefix(t *testing.T) {
	exp := "zzz"
	act := libumi.NewTransaction().SetPrefix(exp).Prefix()

	if act != exp {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}
