package utils

import (
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
