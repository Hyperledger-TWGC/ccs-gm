// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sm2 implements china crypto standards.
package sm2

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"errors"
	"github.com/cetcxinlian/cryptogm/sm3"
	"io"
	"math"
	"math/big"
)

//sm2 enc structure in asn1
type EncData struct {
	X *big.Int
	Y *big.Int
	Hash []byte
	C2  []byte
}

var EncryptionErr = errors.New("sm2: encryption error")
var DecryptionErr = errors.New("sm2: decryption error")

func keyDerivation(Z []byte, klen int) []byte{
	var ct  = 1
	if klen%8 != 0 {
		return nil
	}

	K := make([]byte, int(math.Ceil(float64(klen)/(sm3.Size*8))*sm3.Size))
	v := sm3.Size * 8

	l := int(math.Ceil(float64(klen)/float64(v)))

	var m = make([]byte, len(Z) + 4)
	var vBytes = make([]byte, 4)
	copy(m, Z)

	for ;ct<=l;ct++ {
		vBytes[0] = uint8(ct>>24)
		vBytes[1] = uint8(ct>>16)
		vBytes[2] = uint8(ct>>8)
		vBytes[3] = uint8(ct)
		copy(m[len(Z):], vBytes)

		hash :=sm3.SumSM3(m)
		copy(K[(ct-1)*sm3.Size:],hash[:])
	}
	return K[:klen/8]
}

func Encrypt(rand io.Reader, key *PublicKey, msg []byte) (der []byte, err error) {
	x,y,c2,c3,err := doEncrypt(rand, key, msg)
	if err != nil {
		return nil, err
	}
	ret := EncData{
		X:x,
		Y:y,
		C2: c2,
		Hash:c3,
	}

	return asn1.Marshal(ret)
}

func doEncrypt(rand io.Reader, key *PublicKey, msg[]byte,) (x,y *big.Int,c2, c3 []byte, err error) {
	k := generateRandK(rand, key.Curve)

regen:
	x1, y1 := key.Curve.ScalarBaseMult(k.Bytes())
	//c1 := elliptic.Marshal(key.Curve, x1, y1)
	//sx,sy := key.Curve.ScalarMult(key.X, key.Y, k.Bytes())
	//if sx.Cmp(big.NewInt(0)) == 0 && sy.Cmp(big.NewInt(0)) == 0 {
	//	return nil, EncryptionErr
	//}

	x2,y2 := key.Curve.ScalarMult(key.X, key.Y, k.Bytes())
	Z := make([]byte, len(x2.Bytes())+len(y2.Bytes()))
	copy(Z, x2.Bytes())
	copy(Z[len(x2.Bytes()):], y2.Bytes())

	t := keyDerivation(Z, len(msg)*8)
	if t == nil {
		return nil,nil,nil, nil, EncryptionErr
	}
	for i,v := range t {
		if v != 0 {
			break
		}
		if i == len(t) - 1 {
			goto regen
		}
	}

	//M^t
	for i,v := range t {
		t[i] = v ^ msg[i]
	}

	m3 := make([]byte, len(x2.Bytes()) + len(y2.Bytes()) + len(msg))
	copy(m3, x2.Bytes())
	copy(m3[len(x2.Bytes()):], msg)
	copy(m3[len(x2.Bytes()) + len(msg):], y2.Bytes())

	c3 = sm3.SumSM3(m3)

	//ret := make([]byte, len(c1) + len(t) + len(c3))
	//copy(ret, c1)
	//copy(ret[len(c1):], c3[:])
	//copy(ret[len(c1) + len(c3):], t)
	return x1, y1, t, c3, nil
}

func (key *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	return Decrypt(msg, key)
}

func Decrypt(c []byte, key *PrivateKey) ([]byte, error) {
	// to do check
	//c1Len := 1 + 2*((key.Curve.Params().BitSize + 7) >> 3)
	//klen := (len(c) - c1Len - sm3.Size)*8
	//x1, y1 := elliptic.Unmarshal(key.Curve, c[:c1Len])
	//if x1 == nil {
	//	return nil, DecryptionErr
	//}

	sm2enc := new(EncData)
	_, err := asn1.Unmarshal(c, sm2enc)
	if err != nil {
		return nil, errors.New("sm2 decryption error: input do not have correct format")
	}
	klen := len(sm2enc.C2)*8

	//dB*C1
	x2,y2 := key.Curve.ScalarMult(sm2enc.X, sm2enc.Y, key.D.Bytes())

	Z := make([]byte, len(x2.Bytes())+len(y2.Bytes()))
	copy(Z, x2.Bytes())
	copy(Z[len(x2.Bytes()):], y2.Bytes())

	t := keyDerivation(Z, klen)
	if t == nil {
		return nil, EncryptionErr
	}
	for i,v := range t {
		if v != 0 {
			break
		}
		if i == len(t) - 1 {
			return nil, DecryptionErr
		}
	}

	// m` = c2 ^ t
	c2 := c[len(c)-(klen/8):]
	for i,v := range t {
		t[i] = v ^ c2[i]
	}

	//validate
	_u := make([]byte, len(x2.Bytes()) + len(y2.Bytes()) + len(t))
	copy(_u, x2.Bytes())
	copy(_u[len(x2.Bytes()):], t)
	copy(_u[len(x2.Bytes())+ len(t):], y2.Bytes())
	u := sm3.SumSM3(_u)
	if !bytes.Equal(u[:], sm2enc.Hash){
		return nil, DecryptionErr
	}

	return t,nil
}