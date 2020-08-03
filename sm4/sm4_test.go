// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package sm4

import (
	"bytes"
	"testing"
)

func TestSm4Ecb(t *testing.T) {
	key := []byte("0123456789abcdef")
	msg := []byte("0123456789abcdef012345678")
	encMsg, err := Sm4Ecb(key, msg, ENC)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
		return
	}
	dec, err := Sm4Ecb(key, encMsg, DEC)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	if !bytes.Equal(msg, dec) {
		t.Errorf("sm4 self enc and dec failed")
	}
}

var buf = make([]byte, 8192)

func benchmarkSizeEcb(b *testing.B, size int) {
	b.SetBytes(int64(size))
	key := []byte("1234567890abcdef")
	for i := 0; i < b.N; i++ {
		Sm4Ecb(key, buf[:size], ENC)
	}
}

func BenchmarkSm4Ecb8Bytes(b *testing.B) {
	benchmarkSizeEcb(b, 8)
}

func BenchmarkSm4Ecb1K(b *testing.B) {
	benchmarkSizeEcb(b, 1024)
}

func BenchmarkSm4Ecb8K(b *testing.B) {
	benchmarkSizeEcb(b, 8192)
}

func TestSm4CipherEncAndDec(t *testing.T) {
	msg := []byte("0123456789abcdef")
	key := []byte("0123456789abcdef")
	c, err := NewCipher(key)
	if err != nil {
		t.Errorf("cipher error:%s", err)
		return
	}

	encMsg := make([]byte, 16)
	c.Encrypt(encMsg, msg)

	plain := make([]byte, 16)
	c.Decrypt(plain, encMsg)

	if !bytes.Equal(msg, plain) {
		t.Error("sm4 self enc and dec failed")
	}
}

func BenchmarkSm4Cipher_Encrypt(b *testing.B) {
	msg := []byte("0123456789abcdef")
	key := []byte("0123456789abcdef")
	c, _ := NewCipher(key)
	encMsg := make([]byte, 16)

	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(encMsg, msg)
	}
}

func BenchmarkSm4Cipher_Decrypt(b *testing.B) {
	msg := []byte("0123456789abcdef")
	key := []byte("0123456789abcdef")
	c, _ := NewCipher(key)
	encMsg := make([]byte, 16)
	plain := make([]byte, 16)
	c.Encrypt(encMsg, msg)

	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(plain, encMsg)
	}
}

func TestSm4Cbc(t *testing.T) {
	msg := []byte("0123456789abcdef012345678")
	key := []byte("0123456789abcdef")

	c, err := Sm4Cbc(key, msg, ENC)
	if err != nil {
		t.Errorf("sm4 cbc enc err:%s", err)
		return
	}

	plain, err := Sm4Cbc(key, c, DEC)
	if err != nil {
		t.Errorf("sm4 cbc dec err:%s", err)
		return
	}

	if !bytes.Equal(msg, plain) {
		t.Error("sm4 encryption is invalid")
		return
	}
}

func benchmarkSizeCbc(b *testing.B, size int) {
	b.SetBytes(int64(size))
	key := []byte("1234567890abcdef")
	for i := 0; i < b.N; i++ {
		Sm4Cbc(key, buf[:size], ENC)
	}
}

func BenchmarkSm4Cbc8Bytes(b *testing.B) {
	benchmarkSizeCbc(b, 8)
}

func BenchmarkSm4Cbc1K(b *testing.B) {
	benchmarkSizeCbc(b, 1024)
}

func BenchmarkSm4Cbc8K(b *testing.B) {
	benchmarkSizeCbc(b, 8192)
}