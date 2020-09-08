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
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	verGenesis = 0
	verUmi     = 21929
)

// Errors.
var (
	ErrInvalidVersion       = errors.New("invalid version")
	ErrInvalidSender        = errors.New("invalid sender")
	ErrInvalidValue         = errors.New("invalid value")
	ErrInvalidRecipient     = errors.New("invalid recipient")
	ErrInvalidPrefix        = errors.New("invalid prefix")
	ErrInvalidName          = errors.New("invalid name")
	ErrInvalidFeePercent    = errors.New("invalid fee percent")
	ErrInvalidProfitPercent = errors.New("invalid profit percent")
	ErrInvalidSignature     = errors.New("invalid signature")
)

// VerifyTransaction ...
func VerifyTransaction(t Transaction) (err error) {
	a := []func(Transaction) error{
		verifyTxVersion,
		verifyTxValue,
		verifyTxBasicSenderAndRecipient,
		verifyTxGenesisSenderAndRecipient,
		verifyTxStructureSender,
		verifyTxStructurePrefix,
		verifyTxStructureName,
		verifyTxStructureProfitPercent,
		verifyTxStructureFeePercent,
		verifyTxSignature,
	}

	for _, f := range a {
		if err = f(t); err != nil {
			break
		}
	}

	return err
}

func verifyTxVersion(t Transaction) error {
	if t.Version() > DeleteStructureTransitAddress {
		return ErrInvalidVersion
	}

	return nil
}

func verifyTxGenesisSenderAndRecipient(t Transaction) error {
	if t.Version() != Genesis {
		return nil
	}

	if t.Sender().Version() != verGenesis {
		return ErrInvalidSender
	}

	if t.Recipient().Version() != verUmi {
		return ErrInvalidRecipient
	}

	return nil
}

func verifyTxBasicSenderAndRecipient(t Transaction) error {
	if t.Version() != Basic {
		return nil
	}

	if bytes.Equal(t.Sender(), t.Recipient()) {
		return ErrInvalidRecipient
	}

	if t.Sender().Version() == verGenesis {
		return ErrInvalidSender
	}

	if t.Recipient().Version() == verGenesis {
		return ErrInvalidRecipient
	}

	return nil
}

func verifyTxStructureSender(t Transaction) error {
	if t.Version() < CreateStructure {
		return nil
	}

	if t.Sender().Version() != verUmi {
		return ErrInvalidSender
	}

	return nil
}

func verifyTxStructurePrefix(t Transaction) error {
	if t.Version() < CreateStructure {
		return nil
	}

	switch t.Prefix() {
	case "umi", "genesis":
		return ErrInvalidPrefix
	}

	pfx := t.Prefix()

	for i := range pfx {
		if strings.IndexByte(prefixAlphabet, pfx[i]) == -1 {
			return ErrInvalidPrefix
		}
	}

	return nil
}

func verifyTxStructureName(t Transaction) error {
	const maxNameLength = 35

	if t.Version() != CreateStructure && t.Version() != UpdateStructure {
		return nil
	}

	if t[41] > maxNameLength {
		return ErrInvalidName
	}

	if !utf8.Valid(t[42 : 42+t[41]]) {
		return ErrInvalidName
	}

	return nil
}

func verifyTxStructureProfitPercent(t Transaction) error {
	const (
		minProfitPercent = 100
		maxProfitPercent = 500
	)

	if t.Version() != CreateStructure && t.Version() != UpdateStructure {
		return nil
	}

	prf := t.ProfitPercent()
	if prf < minProfitPercent || prf > maxProfitPercent {
		return ErrInvalidProfitPercent
	}

	return nil
}

func verifyTxStructureFeePercent(t Transaction) error {
	const maxFeePercent = 2000

	if t.Version() != CreateStructure && t.Version() != UpdateStructure {
		return nil
	}

	if t.FeePercent() > maxFeePercent {
		return ErrInvalidFeePercent
	}

	return nil
}

func verifyTxValue(t Transaction) error {
	const maxSafeValue = 90_071_992_547_409_91

	if t.Value() > maxSafeValue {
		return ErrInvalidValue
	}

	return nil
}

func verifyTxSignature(t Transaction) error {
	if !ed25519.Verify(t.Sender().PublicKey(), t[0:85], t.Signature()) {
		return ErrInvalidSignature
	}

	return nil
}
