// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sm2 implements china crypto standards.
package sm2

import (
	"crypto"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"github.com/cetcxinlian/cryptogm/sm3"
	"io"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type sm2Signature struct {
	R, S *big.Int
}

var generateRandK  = _generateRandK

// combinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sign(rand, priv, msg)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
}

func (priv *PrivateKey) SignWithDigest(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := SignWithDigest(rand, priv, digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	var sm2Sign sm2Signature
	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return false
	}
	return Verify(pub, msg, sm2Sign.R, sm2Sign.S)
}

func (pub *PublicKey) VerifyWithDigest(digest []byte, sign []byte) bool {
	var sm2Sign sm2Signature
	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return false
	}
	return VerifyWithDigest(pub, digest, sm2Sign.R, sm2Sign.S)
}

var one = new(big.Int).SetInt64(1)

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

var errZeroParam = errors.New("zero parameter")

func _generateRandK(rand io.Reader, c elliptic.Curve) (k *big.Int) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func zeroByteSlice() []byte{
	return []byte{0,0,0,0,
		0,0,0,0,
		0,0,0,0,
		0,0,0,0,
		0,0,0,0,
		0,0,0,0,
		0,0,0,0,
		0,0,0,0,
	}
}

//公钥坐标（横坐标）长度小于32字节时，在前面补0
func getZById(pub *PublicKey, id []byte) []byte{
	var lena = uint16(len(id) * 8) //bit len of IDA
	var ENTLa = []byte{byte(lena>>8), byte(lena)}
	var z = make([]byte, 0, 1024)

	//判断公钥x,y坐标长度是否小于32字节，若小于则在前面补0
	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()
	if n := len(xBuf); n < 32 {
		xBuf = append(zeroByteSlice()[:32-n], xBuf...)
	}

	if n := len(yBuf); n < 32 {
		yBuf = append(zeroByteSlice()[:32-n], yBuf...)
	}

	z = append(z, ENTLa...)
	z = append(z, id...)
	z = append(z, SM2PARAM_A.Bytes()...)
	z = append(z, P256Sm2().Params().B.Bytes()...)
	z = append(z, P256Sm2().Params().Gx.Bytes()...)
	z = append(z, P256Sm2().Params().Gy.Bytes()...)
	z = append(z, xBuf...)
	z = append(z, yBuf...)
	return sm3.SumSM3(z)
}
//Za = sm3(ENTL||IDa||a||b||Gx||Gy||Xa||Xy)
func getZ(pub *PublicKey) []byte {
	return getZById(pub, []byte("1234567812345678"))
}

func Sign(rand io.Reader, priv *PrivateKey, msg []byte) (r, s *big.Int, err error) {
	var one = new(big.Int).SetInt64(1)
	//if len(hash) < 32 {
	//	err = errors.New("The length of hash has short than what SM2 need.")
	//	return
	//}

	var m = make([]byte, 32+len(msg))
	copy(m, getZ(&priv.PublicKey))
	copy(m[32:], msg)

	e := new(big.Int).SetBytes(sm3.SumSM3(m))
	k := generateRandK(rand, priv.PublicKey.Curve)

	x1, _ := priv.PublicKey.Curve.ScalarBaseMult(k.Bytes())

	n := priv.PublicKey.Curve.Params().N

	r = new(big.Int).Add(e, x1)

	r.Mod(r, n)

	s1 := new(big.Int).Mul(r, priv.D)
	s1.Mod(s1, n)
	s1.Sub(k, s1)
	s1.Mod(s1, n)

	s2 := new(big.Int).Add(one, priv.D)
	s2.Mod(s2, n)
	s2.ModInverse(s2, n)
	s = new(big.Int).Mul(s1, s2)
	s.Mod(s, n)

	return
}

func SignWithDigest(rand io.Reader,priv *PrivateKey, digest []byte) (r, s *big.Int, err error) {
	var one = new(big.Int).SetInt64(1)
	//if len(hash) < 32 {
	//	err = errors.New("The length of hash has short than what SM2 need.")
	//	return
	//}

	e := new(big.Int).SetBytes(digest)
	k := generateRandK(rand, priv.PublicKey.Curve)

	x1, _ := priv.PublicKey.Curve.ScalarBaseMult(k.Bytes())

	n := priv.PublicKey.Curve.Params().N

	r = new(big.Int).Add(e, x1)

	r.Mod(r, n)

	s1 := new(big.Int).Mul(r, priv.D)
	s1.Mod(s1, n)
	s1.Sub(k, s1)
	s1.Mod(s1, n)

	s2 := new(big.Int).Add(one, priv.D)
	s2.Mod(s2, n)
	s2.ModInverse(s2, n)
	s = new(big.Int).Mul(s1, s2)
	s.Mod(s, n)

	return
}

func VerifyById(pub *PublicKey, msg,id []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	n := pub.Curve.Params().N

	var m = make([]byte, 32+len(msg))
	copy(m, getZById(pub, id))
	copy(m[32:], msg)
	e := new(big.Int).SetBytes(sm3.SumSM3(m))

	t := new(big.Int).Add(r, s)
	x11, y11 := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x12, y12 := pub.Curve.ScalarBaseMult(s.Bytes())
	x1, _ := pub.Curve.Add(x11, y11, x12, y12)
	x := new(big.Int).Add(e, x1)
	x = x.Mod(x, n)

	return x.Cmp(r) == 0
}

func Verify(pub *PublicKey, msg []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	n := pub.Curve.Params().N

	var m = make([]byte, 32+len(msg))
	copy(m, getZ(pub))
	copy(m[32:], msg)
	e := new(big.Int).SetBytes(sm3.SumSM3(m))

	t := new(big.Int).Add(r, s)
	//x11, y11 := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	//x12, y12 := pub.Curve.ScalarBaseMult(s.Bytes())
	//x1, _ := pub.Curve.Add(x11, y11, x12, y12)

	// Check if implements S1*g + S2*p
	//Using fast multiplication CombinedMult.
	var x1 *big.Int
	if opt,ok := c.(combinedMult);ok {
		x1,_ = opt.CombinedMult(pub.X, pub.Y,s.Bytes(),t.Bytes())
	} else {
		x11, y11 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
		x12, y12 := c.ScalarBaseMult(s.Bytes())
		x1, _ = c.Add(x11, y11, x12, y12)
	}

	x := new(big.Int).Add(e, x1)
	x = x.Mod(x, n)

	return x.Cmp(r) == 0
}

func VerifyWithDigest(pub *PublicKey, digest []byte, r, s *big.Int) bool  {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	n := pub.Curve.Params().N

	e := new(big.Int).SetBytes(digest)

	t := new(big.Int).Add(r, s)
	// Check if implements S1*g + S2*p
	//Using fast multiplication CombinedMult.
	var x1 *big.Int
	if opt, ok := c.(combinedMult); ok {
		x1, _ = opt.CombinedMult(pub.X, pub.Y, s.Bytes(), t.Bytes())
	} else {
		x11, y11 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
		x12, y12 := c.ScalarBaseMult(s.Bytes())
		x1, _ = c.Add(x11, y11, x12, y12)
	}
	x := new(big.Int).Add(e, x1)
	x = x.Mod(x, n)

	return x.Cmp(r) == 0
}

type zr struct {
	io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}