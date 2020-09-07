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
	"testing"

	"github.com/umitop/libumi"
)

func TestNewTransaction(t *testing.T) {
	tx := libumi.NewTransaction()

	if len(tx) != libumi.TransactionLength {
		t.Fatalf("Expected: %x, got: %x", libumi.TransactionLength, len(tx))
	}
}

func TestTransaction_Hash(t *testing.T) {
	tx := libumi.NewTransaction()

	if len(tx.Hash()) != 32 {
		t.Fatalf("Expected: %x, got: %x", 32, len(tx.Hash()))
	}
}


func TestVerifyVersion(t *testing.T) {
	trx := libumi.NewTransaction()
	trx[0] = 255

	err := trx.Verify()

	if !errors.Is(err, libumi.ErrInvalidVersion) {
		t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidVersion, err)
	}
}

func TestVerifySender(t *testing.T) {
	tests := []struct {
		version uint8
		sender  libumi.Address
	}{
		{libumi.Genesis, libumi.NewAddressWithPrefix("umi")},
		{libumi.Basic, libumi.NewAddressWithPrefix("genesis")},
		{libumi.CreateStructure, libumi.NewAddressWithPrefix("www")},
	}

	for _, test := range tests {
		trx := libumi.NewTransaction()
		_ = trx.SetVersion(test.version)
		trx.SetSender(test.sender)

		err := trx.Verify()

		if errors.Is(err, libumi.ErrInvalidVersion) {
			t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidSender, err)
		}
	}
}

func TestVerifyRecipient(t *testing.T) {
	tests := []struct {
		version   uint8
		sender    libumi.Address
		recipient libumi.Address
	}{
		{libumi.Basic, libumi.NewAddressWithPrefix("umi"), libumi.NewAddressWithPrefix("umi")},
		{libumi.Basic, libumi.NewAddressWithPrefix("umi"), libumi.NewAddressWithPrefix("genesis")},
		{libumi.CreateTransitAddress, libumi.NewAddressWithPrefix("umi"),
			append(libumi.NewAddressWithPrefix("umi")[0:33], 1)},
	}

	for _, test := range tests {
		trx := libumi.NewTransaction()
		_ = trx.SetVersion(test.version)
		trx.SetSender(test.sender)
		trx.SetRecipient(test.recipient)

		err := trx.Verify()

		if !errors.Is(err, libumi.ErrInvalidRecipient) {
			t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidRecipient, err)
		}
	}
}

func TestVerifyPrefix(t *testing.T) {
	tests := []struct {
		prefix string
	}{
		{"```"}, // genesis
		{"umi"}, // umi
		{"[aa"}, // invalid
	}

	for _, test := range tests {
		trx := libumi.NewTransaction()
		_ = trx.SetVersion(libumi.CreateStructure)
		trx.SetSender(libumi.NewAddress())
		_ = trx.SetPrefix(test.prefix)

		err := trx.Verify()

		if !errors.Is(err, libumi.ErrInvalidPrefix) {
			t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidPrefix, err)
		}
	}
}

func TestVerifyNameErrorLength(t *testing.T) {
	trx := libumi.NewTransaction()
	_ = trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddressWithPrefix("umi"))
	_ = trx.SetPrefix("aaa")
	trx[41] = 42 // name length

	err := trx.Verify()

	if !errors.Is(err, libumi.ErrInvalidName) {
		t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidName, err)
	}
}

func TestVerifyNameErrorByte(t *testing.T) {
	trx := libumi.NewTransaction()
	_ = trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddressWithPrefix("umi"))
	_ = trx.SetPrefix("aaa")
	trx[41] = 1 // name length
	trx[42] = 255

	err := trx.Verify()

	if !errors.Is(err, libumi.ErrInvalidName) {
		t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidName, err)
	}
}

func TestVerifyValue(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetSender(libumi.NewAddressWithPrefix("umi"))
	trx.SetRecipient(libumi.NewAddressWithPrefix("aaa"))
	trx.SetValue(18446744073709551615)

	err := trx.Verify()

	if !errors.Is(err, libumi.ErrInvalidValue) {
		t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidValue, err)
	}
}

func TestVerifyProfitPercent(t *testing.T) {
	tests := []struct {
		percent uint16
	}{
		{99},
		{501},
	}

	for _, test := range tests {
		trx := libumi.NewTransaction()
		_ = trx.SetVersion(libumi.CreateStructure)
		trx.SetSender(libumi.NewAddressWithPrefix("umi"))
		_ = trx.SetPrefix("aaa")
		_ = trx.SetProfitPercent(test.percent)

		err := trx.Verify()

		if !errors.Is(err, libumi.ErrInvalidProfitPercent) {
			t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidProfitPercent, err)
		}
	}
}

func TestVerifyFeePercent(t *testing.T) {
	tests := []struct {
		percent uint16
	}{
		{2001},
	}

	for _, test := range tests {
		trx := libumi.NewTransaction()
		_ = trx.SetVersion(libumi.CreateStructure)
		trx.SetSender(libumi.NewAddress())
		_ = trx.SetPrefix("aaa")
		_ = trx.SetProfitPercent(100)
		_ = trx.SetFeePercent(test.percent)

		err := trx.Verify()

		if !errors.Is(err, libumi.ErrInvalidFeePercent) {
			t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidFeePercent, err)
		}
	}
}

func TestVerifySignature(t *testing.T) {
	sig := make([]byte, 64)
	_, _ = rand.Read(sig)

	pub := make(ed25519.PublicKey, 32)
	_, _ = rand.Read(pub)

	trx := libumi.NewTransaction()
	_ = trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddressFromPublicKey(pub))
	_ = trx.SetPrefix("aaa")
	_ = trx.SetProfitPercent(100)
	_ = trx.SetFeePercent(1000)
	_ = trx.SetSignature(sig)

	err := trx.Verify()

	if !errors.Is(err, libumi.ErrInvalidSignature) {
		t.Log(trx.Sender().Bech32())
		t.Fatalf("Expected: %v, got: %v", libumi.ErrInvalidSignature, err)
	}
}
