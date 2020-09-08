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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
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

// TransactionLength ...
const TransactionLength = 150

// Transaction types.
const (
	Genesis = iota
	Basic
	CreateStructure
	UpdateStructure
	UpdateStructureProfitAddress
	UpdateStructureFeeAddress
	CreateStructureTransitAddress
	DeleteStructureTransitAddress
)

// Transaction ...
type Transaction []byte

// NewTransaction ...
func NewTransaction() Transaction {
	t := make(Transaction, TransactionLength)
	t.SetVersion(Basic)

	return t
}

// FeePercent ...
func (t Transaction) FeePercent() uint16 {
	return binary.BigEndian.Uint16(t[39:41])
}

// SetFeePercent ...
func (t Transaction) SetFeePercent(p uint16) {
	binary.BigEndian.PutUint16(t[39:41], p)
}

// Hash ...
func (t Transaction) Hash() []byte {
	h := sha256.Sum256(t)

	return h[:]
}

// Name ...
func (t Transaction) Name() string {
	return string(t[42:(42 + t[41])])
}

// SetName ...
func (t Transaction) SetName(s string) {
	t[41] = uint8(len(s))
	copy(t[42:77], s)
}

// Nonce ...
func (t Transaction) Nonce() uint64 {
	return binary.BigEndian.Uint64(t[77:85])
}

// SetNonce ...
func (t Transaction) SetNonce(v uint64) {
	binary.BigEndian.PutUint64(t[77:85], v)
}

// Prefix ...
func (t Transaction) Prefix() string {
	return addressVersionToPrefix(t[35], t[36])
}

// SetPrefix ...
func (t Transaction) SetPrefix(s string) {
	t[35], t[36] = prefixToAddressVersion(s)
}

// ProfitPercent ...
func (t Transaction) ProfitPercent() uint16 {
	return binary.BigEndian.Uint16(t[37:39])
}

// SetProfitPercent ...
func (t Transaction) SetProfitPercent(n uint16) {
	binary.BigEndian.PutUint16(t[37:39], n)
}

// Recipient ...
func (t Transaction) Recipient() Address {
	return Address(t[35:69])
}

// SetRecipient ...
func (t Transaction) SetRecipient(a Address) {
	copy(t[35:69], a)
}

// Sender ...
func (t Transaction) Sender() Address {
	return Address(t[1:35])
}

// SetSender ...
func (t Transaction) SetSender(a Address) {
	copy(t[1:35], a)
}

// Signature ...
func (t Transaction) Signature() []byte {
	return t[85:149]
}

// SetSignature ...
func (t Transaction) SetSignature(b []byte) {
	copy(t[85:149], b)
}

// Value ...
func (t Transaction) Value() uint64 {
	return binary.BigEndian.Uint64(t[69:77])
}

// SetValue ...
func (t Transaction) SetValue(n uint64) {
	binary.BigEndian.PutUint64(t[69:77], n)
}

// Version ...
func (t Transaction) Version() uint8 {
	return t[0]
}

// SetVersion ...
func (t Transaction) SetVersion(v uint8) {
	t[0] = v
}

// Sign ...
func (t Transaction) Sign(b []byte) {
	t.SetNonce(uint64(time.Now().UnixNano()))
	t.SetSignature(ed25519.Sign(b, t[0:85]))
}

// Verify ...
func (t Transaction) Verify() (err error) {
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

	if bytes.Equal(t[35:37], []byte{85, 169}) { // prefix "umi" is prohibited
		return ErrInvalidPrefix
	}

	if bytes.Equal(t[35:37], []byte{0, 0}) { // prefix "genesis" is prohibited
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
