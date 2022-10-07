package main

import (
	"crypto/tls"
	"encoding/binary"
	"log"
	"os"
	"strconv"
)

func main() {
	start_n, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	end_n, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}

	log.Printf("start=%d end=%d", start_n, end_n)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "localhost:8443", conf)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	msg := make([]byte, 32768)

	size := start_n
	for size <= end_n {
		if (size-start_n)%100 == 0 {
			log.Printf("size = %d", size)
		}
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(size))
		_, err = conn.Write(buf)
		if err != nil {
			panic(err)
		}

		cur_idx := 0
		for cur_idx < size {
			end_idx := cur_idx + len(msg)
			if end_idx > size {
				end_idx = size
			}

			for i := 0; i < end_idx-cur_idx; i++ {
				msg[i] = byte((cur_idx + i) & 0xFF)
			}
			conn.Write(msg[0 : end_idx-cur_idx])

			cur_idx = end_idx
		}

		_, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}
		recv_msg_len := binary.BigEndian.Uint64(buf)
		if recv_msg_len != uint64(size) {
			log.Printf("expected = %d actual = %d", size, recv_msg_len)
			panic("unexpected message length")
		}

		cur_idx = 0
		for cur_idx < size {
			end_idx := cur_idx + len(msg)
			if end_idx > size {
				end_idx = size
			}

			recv_size, err := conn.Read(msg[0 : end_idx-cur_idx])
			if err != nil {
				panic(err)
			}

			for i := 0; i < recv_size; i++ {
				if msg[i] != byte((cur_idx+i)&0xFF) {
					log.Printf("expected = %d actual = %d", (cur_idx+i)&0xFF, msg[i])
					panic("unexpected message")
				}
			}

			cur_idx += recv_size
		}
		size += 1
	}
}
