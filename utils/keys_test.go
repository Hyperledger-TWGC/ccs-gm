package utils

import (
	"bytes"
	"crypto/rand"
	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"testing"
)

func TestPEM2Key(t *testing.T) {
	iniSk, _ := sm2.GenerateKey(rand.Reader)
	iniPk := iniSk.PublicKey

	pemSk, err := PrivateKeyToPEM(iniSk, nil)
	if err != nil {
		t.Errorf("private key to pem error %t", err)
	}

	pemPk, err := PublicKeyToPEM(&iniPk, nil)
	if err != nil {
		t.Errorf("public key to pem error %t", err)
	}

	normalSk, err := PEMtoPrivateKey(pemSk, nil)
	if err != nil {
		t.Errorf("pem to private key error %t", err)
	}
	
	normalPk, err := PEMtoPublicKey(pemPk, nil)
	if err != nil {
		t.Errorf("pem to public key error %t", err)
	}
	testMsg := []byte("123456")
	signedData, _ := normalSk.Sign(rand.Reader, testMsg, nil)
	ok := normalPk.Verify(testMsg, signedData)
	if !ok {
		t.Error("key verify error")
	}
}

func TestEncryptPEMBlock(t *testing.T) {
	sm2priv,err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("sm2 gen key err:%s",err)
		return
	}

	pem,err := PrivateKeyToEncryptedPEM(sm2priv,[]byte("123"))
	if err != nil {
		t.Errorf("priv to pem err :%s",err)
		return
	}

	priv,err := PEMtoPrivateKey(pem,[]byte("123"))
	if err != nil {
		t.Errorf("pem tp priv err: %s",err)
		return
	}

	if !bytes.Equal(sm2priv.D.Bytes(),priv.D.Bytes()) {
		t.Error("pem err")
		return
	}

	pubpem,err := PublicKeyToEncryptedPEM(&priv.PublicKey,[]byte("123"))
	if err != nil {
		t.Errorf("pubkey to pem err: %s",err)
		return
	}

	pk,err := PEMtoPublicKey(pubpem,[]byte("123"))
	if err != nil {
		t.Errorf("pem to pk err:%s",err)
		return
	}

	if !bytes.Equal(priv.X.Bytes(),pk.X.Bytes()) {
		t.Error("pk pem err")
		return
	}

}