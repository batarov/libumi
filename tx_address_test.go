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
	"github.com/umitop/libumi"
	"testing"
)

func TestTxInvalidVersion(t *testing.T) {
	tx := libumi.NewTxDelTransitAddr()
	tx[0] = 255

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidVersion

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", act, exp)
	}
}

func TestTxAddressSign(t *testing.T) {
	pub, sec, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error: %s", err.Error())
	}

	snd := libumi.NewAddress()
	snd.SetPublicKey(pub)

	adr := libumi.NewAddress()
	adr.SetPrefix("aaa")

	tx := libumi.NewTxUpdProfitAddr()
	tx.SetSender(snd)
	tx.SetAddress(adr)

	libumi.SignTx(tx, sec)

	err = libumi.VerifyTx(tx)

	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestTxAddressSenderMustBeUmi(t *testing.T) {
	snd := libumi.NewAddress()
	snd.SetPrefix("aaa")

	tx := libumi.NewTxUpdFeeAddr()
	tx.SetSender(snd)

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidSender

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", act, exp)
	}
}

func TestTxAddressRecipientMustBeStructAddr(t *testing.T) {
	tx := libumi.NewTxCrtTransitAddr()
	tx.SetSender(libumi.NewAddress())
	tx.SetAddress(libumi.NewAddress())

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidRecipient

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", act, exp)
	}
}