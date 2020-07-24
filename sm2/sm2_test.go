// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sm2 implements china crypto standards.
package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"github.com/Hyperledger-TWGC/cryptogm/sm3"
	"io"
	"math/big"
	"reflect"
	"testing"
)

type Assert struct{}

func (a *Assert) Equal(t *testing.T, expect, actual interface{}) {
	if reflect.TypeOf(expect) != reflect.TypeOf(actual) {
		t.Error("assert failed not equal", expect, actual)
		return
	}
	var buf1 bytes.Buffer
	enc1 := gob.NewEncoder(&buf1)
	enc1.Encode(expect)
	var buf2 bytes.Buffer
	enc2 := gob.NewEncoder(&buf2)
	enc2.Encode(expect)
	if bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Log("true")
	} else {
		t.Error("assert failed not equal", expect, actual)
	}
}
func (a *Assert) True(t *testing.T, value bool) {
	if value == true {
		t.Log("true")
	} else {
		t.Error("assert failed %i is false", value)
	}
}

var assert Assert

func TestSignVerify(t *testing.T) {
	msg := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateKey failed")
	}

	hfunc := sm3.New()
	hfunc.Write(msg)
	hash := hfunc.Sum(nil)

	r, s, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}

	ret := Verify(&priv.PublicKey, hash, r, s)
	fmt.Println(ret)
}

func TestBase(t *testing.T) {
	msg := []byte{1, 2, 3, 4}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateKey failed")
	}
	//fmt.Printf("D:%s\n", priv.D.Text(16))
	//fmt.Printf("X:%s\n", priv.X.Text(16))
	//fmt.Printf("Y:%s\n", priv.Y.Text(16))
	//fmt.Printf("p:%s\n", priv.Curve.Params().P.Text(16))
	//fmt.Printf("n:%s\n", priv.Curve.Params().N.Text(16))
	//fmt.Printf("b:%s\n", priv.Curve.Params().B.Text(16))
	//fmt.Printf("gx:%s\n", priv.Curve.Params().Gx.Text(16))
	//fmt.Printf("gy:%s\n", priv.Curve.Params().Gy.Text(16))

	hfunc := sm3.New()
	hfunc.Write(msg)
	hash := hfunc.Sum(nil)
	fmt.Printf("hash:%02X\n", hash)

	r, s, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}

	fmt.Printf("R:%s\n", r.Text(16))
	fmt.Printf("S:%s\n", s.Text(16))

	ret := Verify(&priv.PublicKey, hash, r, s)
	fmt.Println(ret)
}

func TestKeyGeneration(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}

	if !priv.PublicKey.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func BenchmarkSign(b *testing.B) {
	b.ResetTimer()
	origin := []byte("testing")
	hashed := sm3.SumSM3(origin)
	priv, _ := GenerateKey(rand.Reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed[:])
	}
}

func TestSignAndVerify(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testintestintestintestintestintestinggggggtesting")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf(" error signing: %s", err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf(" Verify failed")
	}

	//hashed[0] ^= 0xff
	hashed[0] = 0x53
	for i := 0; i < len(hashed); i++ {
		hashed[i] = byte(i)
	}
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}

func TestKDF(t *testing.T) {
	x2, err := hex.DecodeString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	y2, err := hex.DecodeString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expect, err := hex.DecodeString("006E30DAE231B071DFAD8AA379E90264491603")
	klen := 152
	actual := keyDerivation(append(x2, y2...), klen)
	assert.Equal(t, expect, actual)

}

func TestCryptoToolCompare(t *testing.T) {
	generateRandK = func(rand io.Reader, c elliptic.Curve) (k *big.Int) {
		k, _ = new(big.Int).SetString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3", 16)
		return
	}
	priv := &PrivateKey{}
	priv.PublicKey.Curve = P256Sm2()
	priv.D, _ = new(big.Int).SetString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3", 16)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.ScalarBaseMult(priv.D.Bytes())

	msg, _ := hex.DecodeString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3")
	Encrypt(rand.Reader, &priv.PublicKey, msg)
}

func TestEnc(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	var msg = "asdfasdf"

	enc, err := Encrypt(rand.Reader, &priv.PublicKey, []byte(msg))
	if err != nil {
		t.Fatalf("encrypt failed : %s", err.Error())
	}
	dec, err := Decrypt(enc, priv)
	if err != nil {
		t.Fatalf("dec failed : %s", err.Error())
	}

	if !bytes.Equal([]byte(msg), dec) {
		t.Error("enc-dec failed")
	}
}
