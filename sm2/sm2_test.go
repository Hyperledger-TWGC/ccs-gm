// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package sm2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"github.com/Hyperledger-TWGC/ccs-gm/sm3"
	"math/big"
	"testing"
)

func TestKeyGen(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}

	if !priv.PublicKey.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key is invalid: %s", err)
		return
	}
}

func TestSignAndVer(t *testing.T) {
	msg := []byte("sm2 message111")
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateKey failed")
	}

	//hfunc := sm3.New()
	//hfunc.Write(msg)
	//hash := hfunc.Sum(nil)
	hash := sm3.SumSM3(msg)

	r, s, err := Sign(rand.Reader, priv, hash[:])

	if err != nil {
		panic(err)
	}

	if !Verify(&priv.PublicKey, hash[:], r, s) {
		t.Error("signature is invalid!")
		return
	}
}

func TestSignAndVerWithDigest(t *testing.T) {
	msg := []byte("sm2 message")
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("GenerateKey failed:%s", err)
		return
	}

	var m = make([]byte, 32+len(msg))
	copy(m, getZ(&priv.PublicKey))
	copy(m[32:], msg)
	digest := sm3.SumSM3(m)
	r, s, err := SignWithDigest(rand.Reader, priv, digest[:])
	if err != nil {
		t.Errorf("sign with digest failed:%s", err)
		return
	}

	if !VerifyWithDigest(&priv.PublicKey, digest[:], r, s) {
		t.Error("sig is invalid!")
		return
	}
}

func TestSignAndVerWithAsn1(t *testing.T) {
	msg := []byte("sm2 message")
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("GenerateKey failed:%s", err)
		return
	}

	sig, err := priv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Errorf("sm2 sign failed:%s", err)
		return
	}

	if !(&priv.PublicKey).Verify(msg, sig) {
		t.Error("sig is invalid!")
		return
	}
}

func BenchmarkSign(b *testing.B) {
	hashed := []byte("testing")
	priv, _ := GenerateKey(rand.Reader)

	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed)
	}
}

func BenchmarkVerify(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testing")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)

	sig, _ := priv.Sign(rand.Reader, hashed, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		(&priv.PublicKey).Verify(hashed, sig)
	}
}

func BenchmarkSignWithDigest(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testing")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = SignWithDigest(rand.Reader, priv, hashed)
	}
}

func BenchmarkVerifyWithDigest(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testing")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)

	r, s, _ := SignWithDigest(rand.Reader, priv, hashed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyWithDigest(&priv.PublicKey, hashed, r, s)
	}
}

func BenchmarkSignWithASN1(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	msg := []byte("message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.Sign(rand.Reader, msg, nil)
	}
}

func BenchmarkVerifyWithASN1(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	msg := []byte("message")

	sig, _ := priv.Sign(rand.Reader, msg, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		(&priv.PublicKey).Verify(msg, sig)
	}
}
func TestEncAndDec(t *testing.T) {
	msg := []byte("sm2 encryption standard")

	sk, _ := GenerateKey(rand.Reader)
	pk := sk.PublicKey

	//test encryption
	cipher, err := Encrypt(rand.Reader, &pk, msg)
	if err != nil {
		t.Errorf("enc err:%s", err)
		return
	}

	//test decryption
	plain, err := Decrypt(cipher, sk)
	if err != nil {
		t.Errorf("dec err:%s", err)
		return
	}

	if !bytes.Equal(msg, plain) {
		t.Error("sm2 encryption is invalid")
		return
	}
}

func TestDecrypt(t *testing.T) {
	c, _ := hex.DecodeString("04c03f6661e748ca80880af89237981a6ec80155971d41a0f128e7edef0ba332daf4d804d0d0df33f" +
		"90928a8bce36d41bbd89313978ec706775a7045f58866715e511257c5b91b5f30f8cfcf55cf4b6228dbd91288e5a36a63a4b37e0a" +
		"dc7c758d95f6c6cabc1e1f6db87715948452070d915d02f58b8abec4e1972ae431274dfcd5e9d955db04f2eb5f48d9db15df968cf" +
		"ea53cfff8c00063ff204e99207b734c170230")
	msg, _ := hex.DecodeString("f4de77e8488e0076893b438d9d053d870abf3deeb55cd53e58e763f411c8a60b95e8e8d205c533fc9e3d5016fb7d4a1c0ae1197703edda64d69b4d0532be23c3e3239e")

	sk, _ := new(big.Int).SetString("14616ccf33a996453b4c7e8b03027af00d84a0fd89ceff38effac1595c68433a", 16)

	pkx, pky := P256().ScalarBaseMult(sk.Bytes())

	priv := PrivateKey{PublicKey{P256(), pkx, pky, nil}, sk, nil}

	plain, err := Decrypt(c, &priv)
	if err != nil {
		t.Errorf("dec err:%s", err)
		return
	}

	if !bytes.Equal(msg, plain) {
		t.Error("decryption is invalid")
		return
	}
}
