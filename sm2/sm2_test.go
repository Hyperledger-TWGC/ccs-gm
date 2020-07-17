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
	"github.com/cetcxinlian/crypto/sm/sm3"
	"io"
	"math/big"
	"reflect"
	"testing"
)

type Assert struct {}

func (a *Assert)Equal(t *testing.T, expect, actual interface{}) {
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
	if bytes.Equal(buf1.Bytes(),buf2.Bytes()) {
		t.Log("true")
	} else {
		t.Error("assert failed not equal", expect, actual)
	}
}
func (a *Assert)True(t *testing.T, value bool) {
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
	msg := []byte{1,2,3,4}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateKey failed")
	}
	fmt.Printf("D:%s\n" , priv.D.Text(16))
	fmt.Printf("X:%s\n" , priv.X.Text(16))
	fmt.Printf("Y:%s\n" , priv.Y.Text(16))

	hfunc := sm3.New()
	hfunc.Write(msg)
	hash := hfunc.Sum(nil)
	fmt.Printf("hash:%02X\n", hash)
	var done  = make(chan struct{})
	go func(){
		for i:=0;;i+=1 {
			sig, err := priv.Sign(rand.Reader, hash, nil)
			if err != nil {
				panic(err)
			}
			if len(sig) == 73 {
				fmt.Println("found it")
				done <- struct{}{}
				break
			}
			if i%100 == 0 {
				break
			}
		}
	}()

	r, s, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}

	fmt.Printf("R:%s\n" , r.Text(16))
	fmt.Printf("S:%s\n" , s.Text(16))


	ret := Verify(&priv.PublicKey, hash, r, s)
	fmt.Println(ret)
	<-done
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
	hashed  := sm3.SumSM3(origin)
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
	x2,err := hex.DecodeString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	y2,err := hex.DecodeString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expect,err := hex.DecodeString("006E30DAE231B071DFAD8AA379E90264491603")
	klen := 152
	actual := keyDerivation(append(x2, y2...), klen)
	assert.Equal(t, expect, actual)

}

func TestENC_GMT_EX1(t *testing.T) {
	p256Sm2ParamsTest := &elliptic.CurveParams{Name: "SM2-P-256-TEST"} // 注明为SM2
	//SM2椭	椭 圆 曲 线 公 钥 密 码 算 法 推 荐 曲 线 参 数
	p256Sm2ParamsTest.P, _ = new(big.Int).SetString("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16)
	p256Sm2ParamsTest.N, _ = new(big.Int).SetString("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16)
	p256Sm2ParamsTest.B, _ = new(big.Int).SetString("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16)
	p256Sm2ParamsTest.Gx, _ = new(big.Int).SetString("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16)
	p256Sm2ParamsTest.Gy, _ = new(big.Int).SetString("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16)
	p256Sm2ParamsTest.BitSize = 256

	p256sm2CurveTest := p256Curve{p256Sm2ParamsTest}

	generateRandK = func (rand io.Reader, c elliptic.Curve) (k *big.Int) {
		k,_ =  new(big.Int).SetString("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16)
		return k
	}
	expectA,_ := new(big.Int).SetString("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16)
	Gy2 := p256sm2CurveTest.Gy.Mul(p256sm2CurveTest.Gy,p256sm2CurveTest.Gy)
	gx := new(big.Int).SetBytes(p256sm2CurveTest.Gx.Bytes())
	Gx2 := gx.Mul(p256sm2CurveTest.Gx,p256sm2CurveTest.Gx)
	Gx3 := gx.Mul(Gx2,p256sm2CurveTest.Gx)
	A := Gy2.Sub(Gy2,Gx3)
	A = A.Sub(A,p256sm2CurveTest.B)
	A = A.Div(A,p256sm2CurveTest.Gx)
	assert.Equal(t,expectA.Bytes(), A.Bytes())


	expectX,_ := new(big.Int).SetString("435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A", 16)
	expectY,_ := new(big.Int).SetString("75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42", 16)
	priv := &PrivateKey{}
	priv.PublicKey.Curve = p256sm2CurveTest
	priv.D,_ = new(big.Int).SetString("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16)
	priv.PublicKey.X,priv.PublicKey.Y = p256sm2CurveTest.ScalarBaseMult(priv.D.Bytes())
	assert.True(t,p256sm2CurveTest.IsOnCurve(expectX,expectY))

	//assert.Equal(t, expectX.Bytes(), priv.PublicKey.X.Bytes())
	//assert.Equal(t, expectY.Bytes(), priv.PublicKey.Y.Bytes())
}

func TestCryptoToolCompare(t *testing.T) {
	generateRandK = func(rand io.Reader, c elliptic.Curve) (k *big.Int) {
		k,_ = new(big.Int).SetString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3", 16)
		return
	}
	priv := &PrivateKey{}
	priv.PublicKey.Curve = P256Sm2()
	priv.D,_ = new(big.Int).SetString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3", 16)
	priv.PublicKey.X,priv.PublicKey.Y = priv.PublicKey.ScalarBaseMult(priv.D.Bytes())

	msg,_ := hex.DecodeString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3")
	Encrypt(rand.Reader, &priv.PublicKey, msg)
}

func TestEnc(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	var msg = "asdfasdf"

	enc, err := Encrypt(rand.Reader, &priv.PublicKey, []byte(msg))
	if err != nil {
		t.Fatalf("encrypt failed : %s", err.Error())
	}
	dec,err := Decrypt(enc, priv)
	if err != nil {
		t.Fatalf("dec failed : %s", err.Error())
	}

	if !bytes.Equal([]byte(msg), dec){
		t.Error("enc-dec failed")
	}
}