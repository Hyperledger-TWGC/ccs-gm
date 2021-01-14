package main

import (
	"fmt"
	"github.com/Hyperledger-TWGC/ccs-gm/tls"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
	"io/ioutil"
	"log"
)

func main() {
	const address = "127.0.0.1:6443"
	const caFile = "../asserts/sm2-double-cert/CA.crt"
	const signCertFile = "../asserts/sm2-double-cert/CS.crt"
	const signKeyFile = "../asserts/sm2-double-cert/CS.key"
	const encCertFile = "../asserts/sm2-double-cert/CE.crt"
	const encKeyFile = "../asserts/sm2-double-cert/CE.key"

	clientRun(address, caFile, signCertFile, signKeyFile, encCertFile, encKeyFile)
}

func clientRun(address, caFile, signCertFile, signKeyFile, encCertFile, encKeyFile string) {
	signCert, err := tls.LoadX509KeyPair(signCertFile, signKeyFile)
	if err != nil {
		log.Fatalf("Failed to load LoadX509KeyPair: %v", err)
	}
	encCert, err := tls.LoadX509KeyPair(encCertFile, encKeyFile)
	if err != nil {
		log.Fatalf("Failed to load LoadX509KeyPair: %v", err)
	}
	certBytes, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		log.Fatalln("Failed to parse root certificate")
	}
	conf := &tls.Config{
		RootCAs:            clientCertPool,
		Certificates:       []tls.Certificate{signCert, encCert},
		InsecureSkipVerify: true,
		GMSupport:          &tls.GMSupport{},
	}
	conn, err := tls.Dial("tcp", address, conf)
	if err != nil {
		log.Fatalf("Cannot to connect: %v", err)
	} else {
		log.Printf("Connecting to %s\n", address)
	}
	defer conn.Close()
	n, err := conn.Write([]byte("client hello\n"))
	if err != nil {
		log.Fatalf("Failed to write num: %v, err:%v", n, err)
	}
	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("Failed to read num: %v, err:%v", n, err)
	}
	fmt.Printf("Receive server message: %s\n", string(buf[:n]))
}
