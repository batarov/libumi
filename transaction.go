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
	"crypto/ed25519"
	"encoding/binary"
	"time"
)

// TxLength ...
const TxLength = 150

// Types.
const (
	Genesis uint8 = iota
	Basic
	CreateStructure
	UpdateStructure
	UpdateProfitAddress
	UpdateFeeAddress
	CreateTransitAddress
	DeleteTransitAddress
)

// Transaction ...
type Transaction []byte

// NewTransaction ...
func NewTransaction() Transaction {
	tx := make(Transaction, TxLength)
	tx.SetVersion(Basic)

	return tx
}

// Version ...
func (t Transaction) Version() uint8 {
	return t[0]
}

// SetVersion ...
func (t Transaction) SetVersion(n uint8) {
	t[0] = n
}

// Sender ...
func (t Transaction) Sender() Address {
	return Address(t[1:35])
}

// SetSender ...
func (t Transaction) SetSender(a Address) {
	copy(t[1:35], a)
}

// Recipient ...
func (t Transaction) Recipient() Address {
	return Address(t[35:69])
}

// SetRecipient ...
func (t Transaction) SetRecipient(a Address) {
	copy(t[35:69], a)
}

// Value ...
func (t Transaction) Value() uint64 {
	return binary.BigEndian.Uint64(t[69:77])
}

// SetValue ...
func (t Transaction) SetValue(n uint64) {
	binary.BigEndian.PutUint64(t[69:77], n)
}

// Prefix ...
func (t Transaction) Prefix() string {
	return versionToPrefix(t[35], t[36])
}

// SetPrefix ...
func (t Transaction) SetPrefix(s string) {
	t[35], t[36] = prefixToVersion(s)
}

// ProfitPercent ...
func (t Transaction) ProfitPercent() uint16 {
	return binary.BigEndian.Uint16(t[37:39])
}

// SetProfitPercent ...
func (t Transaction) SetProfitPercent(n uint16) {
	binary.BigEndian.PutUint16(t[37:39], n)
}

// FeePercent ...
func (t Transaction) FeePercent() uint16 {
	return binary.BigEndian.Uint16(t[39:41])
}

// SetFeePercent ...
func (t Transaction) SetFeePercent(p uint16) {
	binary.BigEndian.PutUint16(t[39:41], p)
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

// SignTransaction ...
func SignTransaction(t []byte, sec []byte) {
	setTxNonce(t, uint64(time.Now().UnixNano()))
	setTxSignature(t, ed25519.Sign(sec, t[0:85]))
}

// VerifyTransaction ...
func VerifyTransaction(t []byte) error {
	return assert(t,
		lengthIs(TxLength),
		versionIsValid,

		ifVersionIsGenesis(
			senderPrefixIs(genesis),
			recipientPrefixIs(umi),
		),

		ifVersionIsBasic(
			senderPrefixIsValid,
			recipientPrefixIsValid,
			senderRecipientNotEqual,
			senderPrefixNot(genesis),
			recipientPrefixNot(genesis),
		),

		ifVersionIsCreateOrUpdateStruct(
			senderPrefixIs(umi),
			structPrefixNot(genesis, umi),
			structPrefixIsValid,
			profitPercentBetween(0, 5_00),
			feePercentBetween(1_00, 20_00),
			nameIsValidUtf8,
		),

		ifVersionIsUpdateAddress(
			senderPrefixIs(umi),
			recipientPrefixNot(genesis, umi),
			recipientPrefixIsValid,
		),

		signatureIsValid,
	)
}

func setTxNonce(t []byte, n uint64) {
	binary.BigEndian.PutUint64(t[77:85], n)
}

func setTxSignature(t []byte, sig []byte) {
	copy(t[85:149], sig)
}
