// Copyright 2020 cetc-30. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// license that can be found in the LICENSE file.

// Package sm4 implements the sm4 algorithms

package sm4

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"strconv"
)

type KeySizeError int

// Cipher is an instance of SM4 encryption.
type Sm4Cipher struct {
	rk []uint32
}

//sbox，(b0,b1,b2,b3)=τ(A)=(sBox(a0),sBox(a1),sBox(a2),sBox(a3))
func scSbox(in byte) byte {
	var x, y int
	x = (int)(in >> 4 & 0x0f)
	y = (int)(in & 0x0f)
	return sbox[x][y]
}

//linear transformation L，C=L(B)=B^(B<<<2)^(B<<<10)^(B<<<18)^(B<<<24)
func l(in uint32) uint32 {
	return in ^ leftRotate(in, 2) ^ leftRotate(in, 10) ^ leftRotate(in, 18) ^ leftRotate(in, 24)
}

//linear transformation L'，C=L'(B)=B^(B<<<13)^(B<<<23)
func key_l(in uint32) uint32 {
	return in ^ leftRotate(in, 13) ^ leftRotate(in, 23)
}

func rightRotate(x uint32, r int) uint32 {
	var rr uint32 = uint32(r)
	return ((x >> rr) | (x << (32 - rr))) & 0xffffffff
}

func leftRotate(x uint32, r int) uint32 {
	var rr uint32 = uint32(r)
	return ((x << rr) | (x >> (32 - rr))) & 0xffffffff
}

//linear transformation τ()
func tt(in uint32) uint32 {
	var tmp [4]byte
	var re uint32
	tmp[0] = byte(in>>24) & 0xff
	tmp[1] = byte(in>>16) & 0xff
	tmp[2] = byte(in>>8) & 0xff
	tmp[3] = byte(in) & 0xff
	re = uint32(scSbox(tmp[3])) |
		(uint32(scSbox(tmp[2])) << 8) |
		(uint32(scSbox(tmp[1])) << 16) |
		(uint32(scSbox(tmp[0])) << 24)
	return re
}

//T
func t3(in uint32) uint32 {
	return l(tt(in))
}

//T'
func key_t(in uint32) uint32 {
	return key_l(tt(in))
}

//key expansion
func keyExp(key [4]uint32) []uint32 {
	var k [36]uint32
	var rk [32]uint32
	for i := 0; i < 4; i++ {
		k[i] = uint32(key[i]) ^ fk[i]
	}
	for i := 0; i < 32; i++ {
		k[i+4] = k[i] ^ key_t(k[i+1]^k[i+2]^k[i+3]^ck[i])
		rk[i] = k[i+4]
	}
	return rk[:]
}

//crypt block,F(X0,X1,X2,X3)=X0^T(X1^X2^X3^rk)
func cryptBlock(rk []uint32, dst, src []byte, mode cryptMode) {
	var x uint32
	b := make([]uint32, 4)
	r := make([]byte, 16)
	//byte to uint32
	for i := 0; i < 4; i++ {
		b[i] = (uint32(src[i*4]) << 24) | (uint32(src[i*4+1]) << 16) |
			(uint32(src[i*4+2]) << 8) | (uint32(src[i*4+3]))
	}

	if mode == ENC {
		for i := 0; i < 8; i++ {
			x = b[1] ^ b[2] ^ b[3] ^ rk[4*i]
			b[0] = b[0] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[2] ^ b[3] ^ rk[4*i+1]
			b[1] = b[1] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[1] ^ b[3] ^ rk[4*i+2]
			b[2] = b[2] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[1] ^ b[2] ^ b[0] ^ rk[4*i+3]
			b[3] = b[3] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
		}
	} else {
		for i := 0; i < 8; i++ {
			x = b[1] ^ b[2] ^ b[3] ^ rk[31-4*i]
			b[0] = b[0] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[2] ^ b[3] ^ rk[31-4*i-1]
			b[1] = b[1] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[1] ^ b[3] ^ rk[31-4*i-2]
			b[2] = b[2] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[1] ^ b[2] ^ b[0] ^ rk[31-4*i-3]
			b[3] = b[3] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
		}
	}
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]

	//uint32 to byte
	for i := 0; i < 4; i++ {
		r[i*4] = uint8(b[i] >> 24)
		r[i*4+1] = uint8(b[i] >> 16)
		r[i*4+2] = uint8(b[i] >> 8)
		r[i*4+3] = uint8(b[i])
	}
	copy(dst, r)
}

func (k KeySizeError) Error() string {
	return "SM4: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, KeySizeError(len(key))
	}
	c := new(Sm4Cipher)
	var k [4]uint32
	for i := 0; i < 4; i++ {
		k[i] = (uint32(key[i*4]) << 24) | (uint32(key[i*4+1]) << 16) |
			(uint32(key[i*4+2]) << 8) | (uint32(key[i*4+3]))
	}
	c.rk = keyExp(k)
	return c, nil
}

func (c *Sm4Cipher) BlockSize() int {
	return BlockSize
}

func (c *Sm4Cipher) Encrypt(dst, src []byte) {
	cryptBlock(c.rk, dst, src, ENC)
}

func (c *Sm4Cipher) Decrypt(dst, src []byte) {
	cryptBlock(c.rk, dst, src, DEC)
}

func pkcs7Padding(src []byte) []byte {
	padding := BlockSize - len(src)%BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

//sm4 ecb mode
func Sm4Ecb(key []byte, in []byte, mode cryptMode) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, KeySizeError(len(key))
	}
	var inData []byte
	if mode == ENC {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}
	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		panic(err)
	}
	if mode == ENC {
		for i := 0; i < len(inData)/16; i++ {
			in_tmp := inData[i*16 : i*16+16]
			out_tmp := make([]byte, 16)
			c.Encrypt(out_tmp, in_tmp)
			copy(out[i*16:i*16+16], out_tmp)
		}
	} else {
		for i := 0; i < len(inData)/16; i++ {
			in_tmp := inData[i*16 : i*16+16]
			out_tmp := make([]byte, 16)
			c.Decrypt(out_tmp, in_tmp)
			copy(out[i*16:i*16+16], out_tmp)
		}
		out, _ = pkcs7UnPadding(out)
	}

	return out, nil
}

func xor(in, iv []byte) (out []byte) {
	if len(in) != len(iv) {
		return nil
	}

	out = make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = in[i] ^ iv[i]
	}
	return
}

//sm4 cbc mode
func Sm4Cbc(key []byte, in []byte, mode cryptMode) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, KeySizeError(len(key))
	}
	var inData []byte
	if mode == ENC {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}

	iv := make([]byte, BlockSize)

	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		panic(err)
	}
	if mode == ENC {
		for i := 0; i < len(inData)/16; i++ {
			in_tmp := xor(inData[i*16:i*16+16], iv)
			out_tmp := make([]byte, 16)
			c.Encrypt(out_tmp, in_tmp)
			copy(out[i*16:i*16+16], out_tmp)
			iv = out_tmp
		}
	} else {
		for i := 0; i < len(inData)/16; i++ {
			in_tmp := inData[i*16 : i*16+16]
			out_tmp := make([]byte, 16)
			c.Decrypt(out_tmp, in_tmp)
			out_tmp = xor(out_tmp, iv)
			copy(out[i*16:i*16+16], out_tmp)
			iv = in_tmp
		}
		out, _ = pkcs7UnPadding(out)
	}

	return out, nil
}
