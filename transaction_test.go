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

func TestTxVerifyVersion(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(255)

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidVersion

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestTxVerifyValue(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetValue(18446744073709551615)

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidValue

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxBasicSenderRecipientEqual(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.Basic)
	trx.SetSender(libumi.NewAddress())
	trx.SetRecipient(trx.Sender())

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidRecipient

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxBasicSenderIsGenesis(t *testing.T) {
	sen := libumi.NewAddress()
	sen.SetPrefix("genesis")

	trx := libumi.NewTransaction()
	trx.SetSender(sen)
	trx.SetRecipient(libumi.NewAddress())

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidSender

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxBasicRecipientIsGenesis(t *testing.T) {
	rcp := libumi.NewAddress()
	rcp.SetPrefix("genesis")

	trx := libumi.NewTransaction()
	trx.SetSender(libumi.NewAddress())
	trx.SetRecipient(rcp)

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidRecipient

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxGenesisSenderIsNotGenesis(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.Genesis)
	trx.SetSender(libumi.NewAddress())

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidSender

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxGenesisRecipientIsNotUmi(t *testing.T) {
	sen := libumi.NewAddress()
	sen.SetPrefix("genesis")

	rcp := libumi.NewAddress()
	rcp.SetPrefix("aaa")

	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.Genesis)
	trx.SetSender(sen)
	trx.SetRecipient(rcp)

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidRecipient

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxStructureSenderIsNotUmi(t *testing.T) {
	sen := libumi.NewAddress()
	sen.SetPrefix("aaa")

	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(sen)

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidSender

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxStructurePrefixIsGenesis(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddress())
	trx.SetPrefix("genesis")

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidPrefix

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxStructurePrefixIsUmi(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddress())
	trx.SetPrefix("umi")

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidPrefix

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxStructureInvalidPrefix(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddress())
	trx.SetPrefix("~~~")

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidPrefix

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxStructureInvalidNameLength(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddress())
	trx.SetPrefix("aaa")
	trx[41] = 255

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidName

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}


func TestVerifyTxStructureInvalidNameUtf8(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddress())
	trx.SetPrefix("aaa")
	trx[41] = 1
	trx[42] = 255

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidName

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxStructureInvalidProfitPercent(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddress())
	trx.SetPrefix("aaa")
	trx.SetName("new name")
	trx.SetProfitPercent(99)

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidProfitPercent

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}


func TestVerifyTxStructureInvalidFeePercent(t *testing.T) {
	trx := libumi.NewTransaction()
	trx.SetVersion(libumi.CreateStructure)
	trx.SetSender(libumi.NewAddress())
	trx.SetPrefix("aaa")
	trx.SetName("new name")
	trx.SetProfitPercent(250)
	trx.SetFeePercent(5000)

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidFeePercent

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxInvalidSignature(t *testing.T) {
	_, sec, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	snd := libumi.NewAddress()
	_,_ = rand.Read(snd[2:])

	trx := libumi.NewTransaction()
	trx.SetSender(snd)
	trx.SetRecipient(libumi.NewAddress())
	trx.Sign(sec)

	act := libumi.VerifyTransaction(trx)
	exp := libumi.ErrInvalidSignature

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestVerifyTxSignature(t *testing.T) {
	pub, sec, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	snd := libumi.NewAddress()
	copy(snd[2:34], pub)

	trx := libumi.NewTransaction()
	trx.SetSender(snd)
	trx.SetRecipient(libumi.NewAddress())
	trx.Sign(sec)

	err = libumi.VerifyTransaction(trx)

	if err != nil {
		t.Fatalf("Expected: nil, got: %v", err)
	}
}
