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

package libumi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"unicode/utf8"
)

// Errors.
var (
	ErrInvalidLength        = errors.New("invalid length")
	ErrInvalidVersion       = errors.New("invalid version")
	ErrInvalidSender        = errors.New("invalid sender")
	ErrInvalidRecipient     = errors.New("invalid recipient")
	ErrInvalidPrefix        = errors.New("invalid prefix")
	ErrInvalidProfitPercent = errors.New("invalid profit percent")
	ErrInvalidFeePercent    = errors.New("invalid fee percent")
	ErrInvalidName          = errors.New("invalid name")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidPrevHash      = errors.New("invalid previous block hash")
	ErrInvalidMerkle        = errors.New("invalid merkle root")
	ErrInvalidTx            = errors.New("invalid transaction")
	ErrNonUniqueTx          = errors.New("non-unique transaction")
)

// ErrInvalidAddress ...
var ErrInvalidAddress = errors.New("invalid address")

func assert(b []byte, asserts ...func([]byte) error) error {
	return runAsserts(b, asserts)
}

func runAsserts(b []byte, asserts []func([]byte) error) (err error) {
	for _, assert := range asserts {
		if err = assert(b); err != nil {
			break
		}
	}

	return err
}

func ifVersionIsGenesis(asserts ...func([]byte) error) func([]byte) error {
	return func(b []byte) (err error) {
		if b[0] == Genesis {
			err = runAsserts(b, asserts)
		}

		return err
	}
}

func ifVersionIsBasic(asserts ...func([]byte) error) func([]byte) error {
	return func(b []byte) (err error) {
		if b[0] == Basic {
			err = runAsserts(b, asserts)
		}

		return err
	}
}

func ifVersionIsCreateOrUpdateStruct(asserts ...func([]byte) error) func([]byte) error {
	return func(b []byte) (err error) {
		switch b[0] {
		case CreateStructure, UpdateStructure:
			err = runAsserts(b, asserts)
		}

		return err
	}
}

func ifVersionIsUpdateAddress(asserts ...func([]byte) error) func([]byte) error {
	return func(b []byte) (err error) {
		switch b[0] {
		case UpdateProfitAddress, UpdateFeeAddress, CreateTransitAddress, DeleteTransitAddress:
			err = runAsserts(b, asserts)
		}

		return err
	}
}

func lengthIs(l int) func([]byte) error {
	return func(b []byte) (err error) {
		if b == nil || len(b) != l {
			err = ErrInvalidLength
		}

		return err
	}
}

func lengthIsValid(b []byte) error {
	if len(b) < HeaderLength+TxLength {
		return ErrInvalidLength
	}

	return nil
}

func signatureIsValid(b []byte) (err error) {
	pub, msg, sig := b[3:35], b[0:85], b[85:149]

	if len(b) != TxLength {
		pub, msg, sig = b[71:103], b[0:103], b[103:167]
	}

	if !ed25519.Verify(pub, msg, sig) {
		err = ErrInvalidSignature
	}

	return err
}

func senderPrefixIs(v uint16) func([]byte) error {
	return func(b []byte) (err error) {
		if binary.BigEndian.Uint16(b[1:3]) != v {
			err = ErrInvalidSender
		}

		return err
	}
}

func senderPrefixNot(v uint16) func([]byte) error {
	return func(b []byte) (err error) {
		if binary.BigEndian.Uint16(b[1:3]) == v {
			err = ErrInvalidSender
		}

		return err
	}
}

func senderPrefixIsValid(b []byte) error {
	return adrVersionIsValid(binary.BigEndian.Uint16(b[1:3]))
}

func senderRecipientNotEqual(b []byte) (err error) {
	if bytes.Equal(b[1:35], b[35:69]) {
		err = ErrInvalidRecipient
	}

	return err
}

func recipientPrefixIs(v uint16) func([]byte) error {
	return func(b []byte) (err error) {
		if binary.BigEndian.Uint16(b[35:37]) != v {
			err = ErrInvalidRecipient
		}

		return err
	}
}

func recipientPrefixNot(vs ...uint16) func([]byte) error {
	return func(b []byte) (err error) {
		n := binary.BigEndian.Uint16(b[35:37])
		for _, v := range vs {
			if n == v {
				err = ErrInvalidRecipient
			}
		}

		return err
	}
}

func recipientPrefixIsValid(b []byte) error {
	return adrVersionIsValid(binary.BigEndian.Uint16(b[35:37]))
}

func structPrefixNot(vs ...uint16) func([]byte) error {
	return recipientPrefixNot(vs...)
}

func structPrefixIsValid(b []byte) error {
	return recipientPrefixIsValid(b)
}

func nameIsValidUtf8(b []byte) error {
	const maxLength = 35

	if b[41] > maxLength {
		return ErrInvalidName
	}

	if !utf8.Valid(b[42:(42 + b[41])]) {
		return ErrInvalidName
	}

	return nil
}

func feePercentBetween(min, max uint16) func([]byte) error {
	return func(b []byte) (err error) {
		p := binary.BigEndian.Uint16(b[39:41])

		if p < min || p > max {
			err = ErrInvalidFeePercent
		}

		return err
	}
}

func profitPercentBetween(min, max uint16) func([]byte) error {
	return func(b []byte) (err error) {
		p := binary.BigEndian.Uint16(b[37:39])

		if p < min || p > max {
			err = ErrInvalidProfitPercent
		}

		return err
	}
}

func versionIsValid(b []byte) error {
	switch len(b) {
	case AddressLength:
		return adrVersionIsValid(binary.BigEndian.Uint16(b[0:2]))
	case TxLength:
		return txVersionIsValid(b[0])
	default:
		return blkVersionIsValid(b[0])
	}
}

func adrVersionIsValid(_ uint16) (err error) {
	return err
}

func txVersionIsValid(v uint8) (err error) {
	if v > DeleteTransitAddress {
		err = ErrInvalidVersion
	}

	return err
}

func blkVersionIsValid(v uint8) (err error) {
	if v > Basic {
		err = ErrInvalidVersion
	}

	return err
}

func merkleRootIsValid(b []byte) (err error) {
	mrk, err := CalculateMerkleRoot(b)
	if err != nil {
		return err
	}

	if !bytes.Equal(b[33:65], mrk) {
		err = ErrInvalidMerkle
	}

	return err
}

func prevBlockHashIsNull(_ []byte) error {
	return nil
}

func prevBlockHashNotNull(_ []byte) error {
	return nil
}

func allTransactionAreGenesis(_ []byte) error {
	return nil
}

func allTransactionNotGenesis(_ []byte) error {
	return nil
}

func allTransactionsAreValid(b []byte) (err error) {
	blk := (Block)(b)
	n := blk.TxCount()
	c := make(chan []byte, n)

	for i, l := uint16(0), n; i < l; i++ {
		c <- blk.Transaction(i)
	}

	close(c)

	runParallel(func() {
		for tx := range c {
			if VerifyTransaction(tx) != nil {
				err = ErrInvalidTx

				return
			}
		}
	})

	return err
}

func runParallel(f func()) {
	var wg sync.WaitGroup

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)

		go func() {
			f()
			wg.Done()
		}()
	}

	wg.Wait()
}
