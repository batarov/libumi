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
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/umitop/libumi"
)

func TestCalculateMerkleRoot(t *testing.T) {
	tests := []struct {
		count  int
		base64 string
	}{
		{1, "HYNRi4l7FOKUOZDv9lWDgkbMAgenyVpfPfzMLjlfi78="},
		{2, "5nxQuCEhLBP+XztSaepJ28qcgp/7ETPADXrqX8uZ38U="},
		{3, "304f5WJnRpBWJc8OM/GXElcq+9r4WzZB2GU3tJXrZZE="},
		{4, "0k7lgourOBJjkhrHeGVELXZbzsOaiMnnIApptve5oFc="},
		{5, "k24Xs6YvuR3cyoqKO+yBWeyaKbguywzkFTb7gG5mdGM="},
		{6, "JZRKgpSQd5p+LSJDiGzuMQ4mL9yYtBWkbpVqdUbAdk8="},
		{7, "gYekGUsQ3UdR171nY8OV8SLAf9dgNIe+yIBPErAwYnw="},
		{8, "Zn+VUCmI+ir8qmHlS+zaz9glnuJg2K3ZstWtNXzxxE0="},
	}

	for _, test := range tests {
		trx := libumi.NewTxBasic()
		blk := libumi.NewBlock()

		for i := 0; i < test.count; i++ {
			for j := 0; j < 150; j++ {
				trx[j] = uint8(i)
			}

			blk.AppendTransaction(trx)
		}

		act, _ := libumi.CalculateMerkleRoot(blk)
		exp, _ := base64.StdEncoding.DecodeString(test.base64)

		if !bytes.Equal(exp, act) {
			t.Fatalf("Expected: %x, got: %x", exp, act)
		}
	}
}

func TestCalculateMerkleRootError(t *testing.T) {
	trx := libumi.NewTxBasic()
	blk := libumi.NewBlock()

	blk.AppendTransaction(trx)
	blk.AppendTransaction(trx)

	_, act := libumi.CalculateMerkleRoot(blk)
	exp := libumi.ErrBlkNonUniqueTx

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestSignBlockMustSetCorrectPublicKey(t *testing.T) {
	exp, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	libumi.SignBlock(blk, sec)

	act := blk.PublicKey()

	if !bytes.Equal(act, exp) {
		t.Fatalf("Expected: %x, got: %x", exp, act)
	}
}

func TestBlockMustContainTxs(t *testing.T) {
	blk := libumi.NewBlock()

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidLength

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestBlockTimestamp(t *testing.T) {
	exp := uint32(time.Now().Unix())

	blk := libumi.NewBlock()
	blk.SetTimestamp(exp)

	act := blk.Timestamp()

	if act != exp {
		t.Fatalf("Expected: %v, got: %v", act, exp)
	}
}

func TestBlockMustHaveCorrectVersion(t *testing.T) {
	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTxBasic())
	blk[0] = 255

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidVersion

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestBlockMustHaveCorrectMerkleRoot(t *testing.T) {
	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTxBasic())
	blk.SetPreviousBlockHash(blk.Hash())

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidMerkle

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestBlockMustNotContainDuplicateTransactions(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTxBasic())
	blk.AppendTransaction(libumi.NewTxBasic())
	blk.SetPreviousBlockHash(blk.Hash())

	libumi.SignBlock(blk, sec)

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkNonUniqueTx

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestGenesisBlockMustBeSigned(t *testing.T) {
	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTxBasic())

	mrk, _ := libumi.CalculateMerkleRoot(blk)
	blk.SetMerkleRootHash(mrk)
	blk[0] = libumi.Genesis

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidSignature

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestBasicBlockMustBeSigned(t *testing.T) {
	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTxBasic())
	blk.SetPreviousBlockHash(blk.Hash())

	mrk, _ := libumi.CalculateMerkleRoot(blk)
	blk.SetMerkleRootHash(mrk)

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidSignature

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestGenesisBlockPrevHashMustBeEmpty(t *testing.T) {
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)

	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTxBasic())
	blk.SetPreviousBlockHash(rnd)
	blk[0] = libumi.Genesis

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidPrevHash

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestBlockMustContainValidTxs(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTxBasic())
	blk.SetPreviousBlockHash(blk.Hash())
	mrk, _ := libumi.CalculateMerkleRoot(blk)
	blk.SetMerkleRootHash(mrk)
	libumi.SignBlock(blk, sec)

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidTx

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestGenesisBlockMustContainOnlyGenesisTxs(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	snd := libumi.NewAddress()
	snd.SetPrefix("genesis")
	snd.SetPublicKey(pub)

	tx := libumi.NewTxBasic()
	tx.SetSender(snd)
	tx.SetRecipient(libumi.NewAddress())
	libumi.SignTx(tx, sec)

	blk := libumi.NewBlock()
	blk[0] = libumi.Genesis
	blk.AppendTransaction(tx)
	mrk, _ := libumi.CalculateMerkleRoot(blk)
	blk.SetMerkleRootHash(mrk)
	libumi.SignBlock(blk, sec)

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidTx

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestBasicBlockPrevHashMustBeNotEmpty(t *testing.T) {
	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTxBasic())

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidPrevHash

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestBasicBlockMustNotContainGenesisTxs(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	snd := libumi.NewAddress()
	snd.SetPrefix("genesis")
	snd.SetPublicKey(pub)

	tx := libumi.NewTxBasic()
	tx.SetSender(snd)
	tx.SetRecipient(libumi.NewAddress())
	tx[0] = libumi.Genesis
	libumi.SignTx(tx, sec)

	blk := libumi.NewBlock()
	blk.AppendTransaction(tx)
	blk.SetPreviousBlockHash(blk.Hash())
	mrk, _ := libumi.CalculateMerkleRoot(blk)
	blk.SetMerkleRootHash(mrk)

	libumi.SignBlock(blk, sec)

	act := libumi.VerifyBlock(blk)
	exp := libumi.ErrBlkInvalidTx

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}
