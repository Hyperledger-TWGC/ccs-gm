package x509

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"testing"
)

func TestEncAndDecPem(t *testing.T) {
	sm2Priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("sm2 gen key err: %s", err)
		return
	}
	plainDer := base64.StdEncoding.EncodeToString(sm2Priv.D.Bytes())
	//encrypt pem block
	block, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", []byte(plainDer), []byte("asdf"), PEMCipherAES256)
	if err != nil {
		t.Errorf("encrypt pem block err: %s", err)
		return
	}
	//decrypt
	privKey, err := DecryptPEMBlock(block, []byte("asdf"))
	if err != nil {
		t.Errorf("decrypt pem block err: %s", err)
		return
	}
	buf := make([]byte, len(plainDer))
	_, err = base64.StdEncoding.Decode(buf, privKey)
	if err != nil {
		t.Errorf("base64 decode err: %s", err)
		return
	}
	if !bytes.Equal([]byte(plainDer), privKey) {
		t.Error("decrypt pem invalid!")
		return
	}
}
