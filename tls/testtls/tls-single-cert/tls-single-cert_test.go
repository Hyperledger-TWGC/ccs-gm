package main

import (
	"bufio"
	"github.com/Hyperledger-TWGC/ccs-gm/tls"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"
)

var end chan bool

const (
	address = "127.0.0.1:6443"
	caFile = "../asserts/sm2-cert/ca.crt"
	serverCertFile = "../asserts/sm2-cert/server.crt"
	serverKeyFile = "../asserts/sm2-cert/server.key"
    clientCertFile = "../asserts/sm2-cert/client.crt"
    clientKeyFile = "../asserts/sm2-cert/client.key"
)

func Test(t *testing.T)  {
	end = make(chan bool, 64)
	go testServerRun()
	time.Sleep(1000000)
	go testClientChanRun()
	<-end
}

func testClientChanRun() {
	testClientRun()
	end <- true
}

func testClientRun() {
	cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
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
		InsecureSkipVerify: false,
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

func testServerRun() {
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
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
		go handleServerConn(conn)
	}
}

func handleServerConn(conn net.Conn) {
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



