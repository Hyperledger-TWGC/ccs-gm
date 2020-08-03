// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sm3

import (
	"fmt"
	"testing"
)

type sm3Test struct {
	out string
	in  string
}

var testTable = []sm3Test{
	{"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", ""},
	{"623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88", "a"},
	{"e07d8ee6e54586a459e30eb8d809e02194558e2b0b235a31f3226a3687faab88", "ab"},
	{"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc"},
	{"44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88", "hello world"},
	{"7c4b960e0fe034f670a8937636474b19b35724883b58da4dac37bb0675ec4d84", "sm3 test"},
	{"3c28cfd2e1861b8e479013a7d078fe8ef4f14fd1f8b549ca53d58fffdedd912c", "sm3 hash"},
	{"7a9a924ff292e09e72cd815b606357a796ac4351fe6de2ff59cd2967eb9a5c16", "sm3sm3sm3sm3sm3sm3sm3sm3sm3sm3sm3sm3"},
}

func TestSM3(t *testing.T) {
	for i := 0; i < len(testTable); i++ {
		table := testTable[i]
		s := fmt.Sprintf("%x", SumSM3([]byte(table.in)))
		if s != table.out {
			t.Fatalf("SumSM3 function: SM3(%s) = %s want %s", table.in, s, table.out)
		}
	}
}

func TestSize(t *testing.T) {
	c := New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
}

func TestBlockSize(t *testing.T) {
	c := New()
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d want %d", got, BlockSize)
	}
}

var bench = New()
var buf = make([]byte, 8192)

func benchmarkSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192)
}