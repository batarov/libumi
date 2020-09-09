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

func TestTxStructSign(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	snd := libumi.NewAddress()
	snd.SetPublicKey(pub)

	tx := libumi.NewTxUpdStruct()
	tx.SetSender(snd)
	tx.SetPrefix("aaa")
	tx.SetName("hello world")
	tx.SetProfitPercent(100)
	tx.SetFeePercent(1)

	libumi.SignTx(tx, sec)

	err := libumi.VerifyTx(tx)
	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestTxStructVersion(t *testing.T) {
	tx := libumi.NewTxUpdStruct()

	act := tx.Version()
	exp := libumi.UpdateStructure

	if act != exp {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxStructSenderMustBeUmi(t *testing.T) {
	snd := libumi.NewAddress()
	snd.SetPrefix("aaa")

	tx := libumi.NewTxCrtStruct()
	tx.SetSender(snd)

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidSender

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxStructPrefixMustNotBeUmi(t *testing.T) {
	tx := libumi.NewTxCrtStruct()
	tx.SetSender(libumi.NewAddress())
	tx.SetPrefix("umi")

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidPrefix

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxStructProfitPercentMustBeBetween100and500(t *testing.T) {
	tx := libumi.NewTxCrtStruct()
	tx.SetSender(libumi.NewAddress())
	tx.SetPrefix("aaa")
	tx.SetProfitPercent(99)

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidProfitPercent

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxStructFeePercentMustBeBetween0and2000(t *testing.T) {
	tx := libumi.NewTxCrtStruct()
	tx.SetSender(libumi.NewAddress())
	tx.SetPrefix("aaa")
	tx.SetProfitPercent(100)
	tx.SetFeePercent(2001)

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidFeePercent

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxStructNameLengthMustNotBeMore35Bytes(t *testing.T) {
	tx := libumi.NewTxCrtStruct()
	tx.SetSender(libumi.NewAddress())
	tx.SetPrefix("aaa")
	tx.SetProfitPercent(100)
	tx.SetFeePercent(0)
	tx[41] = 255

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidName

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxStructNameMustBeValidUtf8String(t *testing.T) {
	tx := libumi.NewTxCrtStruct()
	tx.SetSender(libumi.NewAddress())
	tx.SetPrefix("aaa")
	tx.SetProfitPercent(100)
	tx.SetFeePercent(0)
	tx.SetName("\xff\x00\x00\x00")

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidName

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}
