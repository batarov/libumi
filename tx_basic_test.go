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
	"encoding/binary"
	"errors"
	"testing"

	"github.com/umitop/libumi"
)

func TestTxLengthMustBe150Bytes(t *testing.T) {
	tx := make([]byte, 149)

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidLength

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxGenesisSign(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	snd := libumi.NewAddress()
	snd.SetPrefix("genesis")
	snd.SetPublicKey(pub)

	tx := libumi.NewTxBasic()
	tx.SetSender(snd)
	tx.SetRecipient(libumi.NewAddress())
	tx.SetValue(1)
	tx[0] = libumi.Genesis

	libumi.SignTx(tx, sec)

	err := libumi.VerifyTx(tx)
	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestTxGenesisRecipientMustBeUmi(t *testing.T) {
	adr := libumi.NewAddress()
	adr.SetPrefix("genesis")

	tx := libumi.NewTxBasic()
	tx.SetSender(adr)
	tx.SetRecipient(adr)
	tx[0] = libumi.Genesis

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidRecipient

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxGenesisSenderMustBeGenesis(t *testing.T) {
	tx := libumi.NewTxBasic()
	tx.SetSender(libumi.NewAddress())
	tx[0] = libumi.Genesis

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidSender

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxBasicValue(t *testing.T) {
	b := make([]byte, 8)

	_, _ = rand.Read(b)

	val := binary.BigEndian.Uint64(b)

	tx := libumi.NewTxBasic()
	tx.SetValue(val)

	if tx.Value() != val {
		t.Fatalf("Expected: %v, got: %v", val, tx.Value())
	}
}

func TestTxBasicInvalidSignature(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	rcp := libumi.NewAddress()
	rcp.SetPublicKey(pub)

	tx := libumi.NewTxBasic()
	tx.SetSender(libumi.NewAddress())
	tx.SetRecipient(rcp)
	tx.SetValue(1)

	libumi.SignTx(tx, sec)

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidSignature

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", act, exp)
	}
}

func TestTxBasicSenderAndRecipientMustNotBeEqual(t *testing.T) {
	tx := libumi.NewTxBasic()
	tx.SetSender(libumi.NewAddress())
	tx.SetRecipient(tx.Sender())

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidRecipient

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxBasicSenderMustNotBeGenesis(t *testing.T) {
	snd := libumi.NewAddress()
	snd.SetPrefix("genesis")

	tx := libumi.NewTxBasic()
	tx.SetSender(snd)
	tx.SetRecipient(libumi.NewAddress())

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidSender

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxBasicRecipientMustNotBeGenesis(t *testing.T) {
	rcp := libumi.NewAddress()
	rcp.SetPrefix("genesis")

	tx := libumi.NewTxBasic()
	tx.SetSender(libumi.NewAddress())
	tx.SetRecipient(rcp)

	act := libumi.VerifyTx(tx)
	exp := libumi.ErrTxInvalidRecipient

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}
