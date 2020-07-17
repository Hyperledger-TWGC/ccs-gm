package tls

import (
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/cetcxinlian/crypto/x509"
)

func TestServer(t *testing.T) {
	_, err := Dial("tcp", "www.baidu.com:443", nil)
	if err != nil {
		t.Errorf("failed to dail to www.baidu.com:443, ret:%s\n", err.Error())
	}
}

func TestParsePKCS8(t *testing.T) {
	var pemkey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqMuzV7443wbxPvJddt4SsM0R5tPVKlYO6KJxZsUkW4oAoGCCqBHM9V
AYItoUQDQgAEHe77T5o6nfpiXgDcAdJp0ypCMWQWtig8yZWSRX3lFGcf+/Tgm646
XwhaYpM3rcEtTr8hFkIQQpztF70xXNdhIA==
-----END EC PRIVATE KEY-----`

	keyBlock, _ := pem.Decode([]byte(pemkey))
	if keyBlock == nil {
		t.Errorf("failed to decode pem key")
	}
	derKey := keyBlock.Bytes
	privKey, err := x509.ParseECPrivateKey(derKey)
	if err != nil {
		t.Errorf("failed to parse ec private key, err : %s\n", err.Error())
	}
	fmt.Printf("%+v\n", privKey)
}

func TestHaha(t *testing.T) {
	a := 1
	fmt.Printf("asdfasdf")
	fmt.Printf("asdfasdf%d", a)
	fmt.Printf("asdfasdf")
}
