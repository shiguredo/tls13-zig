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
	msg := make([]byte, 32768)
	for {
		buf := make([]byte, 8)
		_, err := r.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		msg_len := binary.BigEndian.Uint64(buf)

		_, err = conn.Write(buf)
		if err != nil {
			log.Println(err)
			return
		}
		cur_idx := uint64(0)
		for cur_idx < msg_len {
			end_idx := cur_idx + uint64(len(msg))
			if end_idx > msg_len {
				end_idx = msg_len
			}

			recv_size, err := conn.Read(msg[0 : end_idx-cur_idx])
			if err != nil {
				log.Println(err)
				return
			}
			_, err = conn.Write(msg[0:recv_size])
			if err != nil {
				log.Println(err)
				return
			}
			cur_idx += uint64(recv_size)
		}
	}
}
