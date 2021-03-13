// Copyright 2020 cetc-30. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// license that can be found in the LICENSE file.
package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/Hyperledger-TWGC/ccs-gm/sm3"
)

func TestKeyGen(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if !priv.PublicKey.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Fatalf("public key is invalid: %s", err)
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
		t.Fatalf("signature is invalid!")
	}
}

func TestSignAndVerWithDigest(t *testing.T) {
	msg := []byte("sm2 message")
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed:%s", err)
	}

	var m = make([]byte, 32+len(msg))
	copy(m, getZ(&priv.PublicKey))
	copy(m[32:], msg)
	digest := sm3.SumSM3(m)
	r, s, err := SignWithDigest(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign with digest failed:%s", err)
	}

	if !VerifyWithDigest(&priv.PublicKey, digest[:], r, s) {
		t.Fatal("sig is invalid!")
	}
}

func TestSignAndVerWithAsn1(t *testing.T) {
	msg := []byte("sm2 message")
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed:%s", err)
	}

	sig, err := priv.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatalf("sm2 sign failed:%s", err)
	}

	if !(&priv.PublicKey).Verify(msg, sig) {
		t.Fatalf("sig is invalid!")
	}
}

func BenchmarkSign(b *testing.B) {
	hashed := []byte("testing")
	priv, _ := GenerateKey(rand.Reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed)
	}
}

func BenchmarkEcdsaSign(b *testing.B) {
	hashed := []byte("testing")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ecdsa.Sign(rand.Reader, priv, hashed)
	}
}

func BenchmarkVerify(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testing")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)

	sig, _ := priv.Sign(rand.Reader, hashed, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		(&priv.PublicKey).Verify(hashed, sig)
	}
}

func BenchmarkEcdsaVerify(b *testing.B) {
	hashed := []byte("testing")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hashed)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ecdsa.Verify(&priv.PublicKey, hashed, r, s)
	}
}

func BenchmarkSignWithDigest(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testing")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)
	b.ReportAllocs()
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

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyWithDigest(&priv.PublicKey, hashed, r, s)
	}
}

func BenchmarkSignWithASN1(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	msg := []byte("message")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.Sign(rand.Reader, msg, nil)
	}
}

func BenchmarkVerifyWithASN1(b *testing.B) {
	priv, _ := GenerateKey(rand.Reader)

	msg := []byte("message")

	sig, _ := priv.Sign(rand.Reader, msg, nil)

	b.ReportAllocs()
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
		t.Fatalf("enc err:%s", err)
	}

	//test decryption
	plain, err := Decrypt(cipher, sk)
	if err != nil {
		t.Fatalf("dec err:%s", err)
	}

	if !bytes.Equal(msg, plain) {
		t.Fatal("sm2 encryption is invalid")
	}
}