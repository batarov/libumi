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
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Errors.
var (
	ErrBlkInvalidSignature = errors.New("block: invalid signature")
	ErrBlkInvalidVersion   = errors.New("block: invalid version")
	ErrBlkInvalidLength    = errors.New("block: invalid length")
	ErrBlkNonUniqueTrx     = errors.New("block: non-unique transaction")
)

// HeaderLength ...
const HeaderLength = 167

// Block ...
type Block []byte

// AppendTransaction ...
func AppendTransaction(b Block, t Transaction) Block {
	b = append(b, t...)
	binary.BigEndian.PutUint16(b[69:71], b.TxCount()+1)

	return b
}

// NewBlock ...
func NewBlock() Block {
	b := make(Block, HeaderLength)
	b.SetVersion(Basic)

	return b
}

// Hash ...
func (b Block) Hash() []byte {
	h := sha256.Sum256(b[:HeaderLength])

	return h[:]
}

// Version ...
func (b Block) Version() uint8 {
	return b[0]
}

// SetVersion ...
func (b Block) SetVersion(ver uint8) {
	b[0] = ver
}

// PreviousBlockHash ...
func (b Block) PreviousBlockHash() []byte {
	return b[1:33]
}

// SetPreviousBlockHash ...
func (b Block) SetPreviousBlockHash(h []byte) {
	copy(b[1:33], h)
}

// MerkleRootHash ...
func (b Block) MerkleRootHash() []byte {
	return b[33:65]
}

// SetMerkleRootHash ...
func (b Block) SetMerkleRootHash(h []byte) {
	copy(b[33:65], h)
}

// Timestamp ..
func (b Block) Timestamp() uint32 {
	return binary.BigEndian.Uint32(b[65:69])
}

// SetTimestamp ...
func (b Block) SetTimestamp(t uint32) {
	binary.BigEndian.PutUint32(b[65:69], t)
}

// TxCount ...
func (b Block) TxCount() uint16 {
	return binary.BigEndian.Uint16(b[69:71])
}

// PublicKey ...
func (b Block) PublicKey() []byte {
	return b[71:103]
}

// SetPublicKey ...
func (b Block) SetPublicKey(k []byte) {
	copy(b[71:103], k)
}

// Signature ...
func (b Block) Signature() []byte {
	return b[103:167]
}

// SetSignature ...
func (b Block) SetSignature(s []byte) {
	copy(b[103:167], s)
}

// Sign ...
func (b Block) Sign(k []byte) {
	b.SetPublicKey((ed25519.PrivateKey)(k).Public().(ed25519.PublicKey))
	b.SetSignature(ed25519.Sign(k, b[:103]))
}

// Transaction ...
func (b Block) Transaction(idx uint16) Transaction {
	x := HeaderLength + int(idx)*TransactionLength
	y := x + TransactionLength

	return Transaction(b[x:y])
}

// Verify ...
func (b Block) Verify() error {
	if !ed25519.Verify(b.PublicKey(), b[0:103], b.Signature()) {
		return ErrBlkInvalidSignature
	}

	return nil
}

// CalculateMerkleRoot ...
func CalculateMerkleRoot(b Block) (hsh []byte, err error) {
	c := b.TxCount()
	h := make([][32]byte, c)
	u := map[[32]byte]struct{}{}

	// step 1

	for i := uint16(0); i < c; i++ {
		h[i] = sha256.Sum256(b.Transaction(i))
		if _, ok := u[h[i]]; ok {
			return hsh, ErrBlkNonUniqueTrx
		}

		u[h[i]] = struct{}{}
	}

	// step 2

	t := make([]byte, 64)

	for n, m := next(int(c)); n > 0; n, m = next(n) {
		for i := 0; i < n; i++ {
			k1 := i * 2
			k2 := min(k1+1, m)
			copy(t[:32], h[k1][:])
			copy(t[32:], h[k2][:])
			h[i] = sha256.Sum256(t)
		}
	}

	hsh = make([]byte, 32)
	copy(hsh, h[0][:])

	return hsh, err
}

func min(a, b int) int {
	if a > b {
		return b
	}

	return a
}

func next(count int) (nextCount, maxIdx int) {
	maxIdx = count - 1

	if count > 2 {
		count += count % 2
	}

	nextCount = count / 2

	return nextCount, maxIdx
}
