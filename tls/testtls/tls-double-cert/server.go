package main

import (
	"bufio"
	"fmt"
	"github.com/Hyperledger-TWGC/ccs-gm/tls"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
	"io/ioutil"
	"log"
	"net"
)

func main() {
	const address = "127.0.0.1:6443"
	const caFile = "../asserts/sm2-double-cert/CA.crt"
	const signCertFile = "../asserts/sm2-double-cert/SS.crt"
	const signKeyFile = "../asserts/sm2-double-cert/SS.key"
	const encCertFile = "../asserts/sm2-double-cert/SE.crt"
	const encKeyFile = "../asserts/sm2-double-cert/SE.key"

	serverRun(address, caFile, signCertFile, signKeyFile, encCertFile, encKeyFile)
}

func serverRun(address, caFile, signCertFile, signKeyFile, encCertFile, encKeyFile string) {
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
	config := &tls.Config{
		Certificates: []tls.Certificate{signCert, encCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
		GMSupport:    &tls.GMSupport{},
	}
	ln, err := tls.Listen("tcp", address, config)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	} else {
		log.Println("Starting server...")
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Printf("Receive client message:%s\n", msg)
		n, err := conn.Write([]byte("server hello\n"))
		if err != nil {
			log.Fatalf("Failed to Write num: %v, err: %v", n, err)
		}
	}
}
