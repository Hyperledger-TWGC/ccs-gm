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
	const certFile = "../asserts/sm2-cert/server.crt"
	const keyFile = "../asserts/sm2-cert/server.key"
	const caFile = "../asserts/sm2-cert/ca.crt"

	serverRun(address, caFile, certFile, keyFile)
}

func serverRun(address , caFile , certFile , keyFile string) {
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
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
		GMSupport: &tls.GMSupport{},
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
