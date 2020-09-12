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
	"encoding/binary"
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
		trx := libumi.NewTransaction()
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

func TestCalculateMerkleNonUniqError(t *testing.T) {
	trx := libumi.NewTransaction()
	blk := libumi.NewBlock()

	blk.AppendTransaction(trx)
	blk.AppendTransaction(trx)

	_, act := libumi.CalculateMerkleRoot(blk)
	exp := libumi.ErrNonUniqueTx

	if !errors.Is(act, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}

func TestBlockGenesis(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	tx := libumi.NewTransaction().
		SetVersion(libumi.Genesis).
		SetSender(libumi.NewAddress().SetPrefix("genesis").SetPublicKey(pub)).
		SetRecipient(libumi.NewAddress())

	libumi.SignTransaction(tx, sec)

	blk := libumi.NewBlock()
	blk.SetVersion(libumi.Genesis)
	blk.AppendTransaction(tx)

	mrk, _ := libumi.CalculateMerkleRoot(blk)
	blk.SetMerkleRootHash(mrk)

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestBlockBasic(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	tx := libumi.NewTransaction().
		SetVersion(libumi.Basic).
		SetSender(libumi.NewAddress().SetPrefix("umi").SetPublicKey(pub)).
		SetRecipient(libumi.NewAddress().SetPrefix("aaa"))

	libumi.SignTransaction(tx, sec)

	blk := libumi.NewBlock()
	blk.SetVersion(libumi.Basic)
	blk.AppendTransaction(tx)

	mrk, _ := libumi.CalculateMerkleRoot(blk)
	blk.SetMerkleRootHash(mrk)
	blk.SetPreviousBlockHash(blk.Hash())

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	if err != nil {
		t.Fatalf("Expected: %v, got: %v", nil, err)
	}
}

func TestBlockLengthMustBeValid(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		exp  error
	}{
		{
			name: "data must not be null",
			data: nil,
			exp:  libumi.ErrInvalidLength,
		},
		{
			name: "length must not be less then minimal",
			data: make([]byte, libumi.HeaderLength+libumi.TxLength-1),
			exp:  libumi.ErrInvalidLength,
		},
		{
			name: "length must match transaction count",
			data: func() []byte {
				blk := make([]byte, libumi.HeaderLength+libumi.TxLength+1)
				binary.BigEndian.PutUint16(blk[69:71], 1)

				return blk
			}(),
			exp: libumi.ErrInvalidLength,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := libumi.VerifyBlock(tc.data)

			if !errors.Is(err, tc.exp) {
				t.Fatalf("Expected: %v, got: %v", tc.exp, err)
			}
		})
	}
}

func TestBlockVersionMustBeValid(t *testing.T) {
	blk := libumi.NewBlock()
	blk.SetVersion(255)
	blk.AppendTransaction(libumi.NewTransaction())

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrInvalidVersion

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockSignatureMustBeValid(t *testing.T) {
	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTransaction())

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrInvalidSignature

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockGenesisPrevBlockHashIsNull(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.SetVersion(libumi.Genesis)
	blk.AppendTransaction(libumi.NewTransaction())
	blk.SetPreviousBlockHash(blk.Hash())

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrInvalidPrevHash

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockGenesisCanContainOnlyGenesisTxs(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.SetVersion(libumi.Genesis)
	blk.AppendTransaction(libumi.NewTransaction())

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrInvalidTx

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockBasicPrevBlockHashIsNotNull(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTransaction())

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrInvalidPrevHash

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockBasicCanNotContainGenesisTxs(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTransaction().SetVersion(libumi.Genesis))
	blk.SetPreviousBlockHash(blk.Hash())

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrInvalidTx

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockMustNotContainDuplicateTxs(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTransaction())
	blk.AppendTransaction(libumi.NewTransaction())
	blk.SetPreviousBlockHash(blk.Hash())

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrNonUniqueTx

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockMustHaveValidMerkleRoot(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTransaction())
	blk.SetPreviousBlockHash(blk.Hash())

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrInvalidMerkle

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockMustContainValidTxs(t *testing.T) {
	_, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()
	blk.AppendTransaction(libumi.NewTransaction())
	blk.SetPreviousBlockHash(blk.Hash())

	mrk, _ := libumi.CalculateMerkleRoot(blk)
	blk.SetMerkleRootHash(mrk)

	libumi.SignBlock(blk, sec)

	err := libumi.VerifyBlock(blk)
	exp := libumi.ErrInvalidTx

	if !errors.Is(err, exp) {
		t.Fatalf("Expected: %v, got: %v", exp, err)
	}
}

func TestBlockSign(t *testing.T) {
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)

	blk := libumi.NewBlock()

	libumi.SignBlock(blk, sec)

	if !bytes.Equal(blk.PublicKey(), pub) {
		t.Fatalf("Expected: %x, got: %x", pub, blk.PublicKey())
	}
}

func TestBlockTimestamp(t *testing.T) {
	blk := libumi.NewBlock()

	exp := uint32(time.Now().Unix())
	act := blk.SetTimestamp(exp).Timestamp()

	if act != exp {
		t.Fatalf("Expected: %v, got: %v", exp, act)
	}
}
