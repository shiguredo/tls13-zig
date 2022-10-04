package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"log"
	"net"
)

func main() {
	log.SetFlags(log.Lshortfile)

	cer, err := tls.LoadX509KeyPair("./cert.pem", "./key.pem")
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		buf := make([]byte, 4)
		_, err := r.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		msg_len := binary.BigEndian.Uint32(buf)
		msg := make([]byte, msg_len)
		_, err = conn.Read(msg)
		if err != nil {
			log.Println(err)
			return
		}

		_, err = conn.Write(buf)
		if err != nil {
			log.Println(err)
			return
		}

		_, err = conn.Write(msg)
		if err != nil {
			log.Println(err)
			return
		}
	}
}
