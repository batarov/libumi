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
)

// VerifyBlock ...
func VerifyBlock(b Block) error {
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
