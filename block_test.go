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
	"encoding/base64"
	"errors"
	"testing"

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
		exp, _ := base64.StdEncoding.DecodeString(test.base64)

		trx := libumi.NewTransaction()
		blk := libumi.NewBlock()

		for i := 0; i < test.count; i++ {
			for j := 0; j < 150; j++ {
				trx[j] = uint8(i)
			}

			blk.AppendTransaction(trx)
		}

		act, _ := blk.CalculateMerkleRoot()

		if !bytes.Equal(exp, act) {
			t.Fatalf("Expected: %x, got: %x", exp, act)
		}
	}
}

func TestCalculateMerkleRootError(t *testing.T) {
	trx := libumi.NewTransaction()
	blk := libumi.NewBlock()

	blk.AppendTransaction(trx)
	blk.AppendTransaction(trx)

	_, err := blk.CalculateMerkleRoot()

	if !errors.Is(err, libumi.ErrBlkNonUniqueTrx) {
		t.Fatalf("Expected: %v, got: %v", libumi.ErrBlkNonUniqueTrx, err)
	}
}
