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
	const certFile = "../asserts/sm2-cert/client.crt"
	const keyFile = "../asserts/sm2-cert/client.key"
	const caFile = "../asserts/sm2-cert/ca.crt"
	clientRun(address, caFile, certFile, keyFile)
}

func clientRun(address , caFile , certFile , keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
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
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		GMSupport: &tls.GMSupport{},
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
