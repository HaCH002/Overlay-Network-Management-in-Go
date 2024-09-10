package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

type peerInfo struct {
	Address   *net.UDPAddr
	PublicKey string
}

var (
	clients = make(map[string]peerInfo)
	mutex   = &sync.Mutex{}
	num     = int32(0)
)

func Server() {
	localAddress := "192.168.100.11:8080"

	if len(os.Args) > 2 {
		localAddress = os.Args[2]
	}

	addr, err := net.ResolveUDPAddr("udp", localAddress)
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	port := strings.Split(localAddress, ":")[1]
	fmt.Printf("STUN server listening on port %s\n", port)

	buffer := make([]byte, 64)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			continue
		}

		peerKey := string(buffer[:n])
		fmt.Printf("[INCOMING PEER KEY from %s] %s\n", clientAddr, peerKey)

		mutex.Lock()
		var buf bytes.Buffer

		for _, tup := range clients {
			err = binary.Write(&buf, binary.BigEndian, num)
			if err != nil {
				fmt.Println("binary.Write failed:", err)
				panic(err)
			}

			err = binary.Write(&buf, binary.BigEndian, int32(len(clientAddr.String())))
			if err != nil {
				fmt.Println("binary.Write failed:", err)
				panic(err)
			}
			buf.WriteString(clientAddr.String())

			err = binary.Write(&buf, binary.BigEndian, int32(len(peerKey)))
			if err != nil {
				fmt.Println("binary.Write failed:", err)
				panic(err)
			}
			buf.Write([]byte(peerKey))

			_, err = conn.WriteToUDP(buf.Bytes(), tup.Address)
			if err != nil {
				fmt.Println("Error sending data:", err)
				panic(err)
			}

			buf.Reset()
			num++

			err = binary.Write(&buf, binary.BigEndian, num)
			if err != nil {
				fmt.Println("binary.Write failed:", err)
				panic(err)
			}

			err = binary.Write(&buf, binary.BigEndian, int32(len(tup.Address.String())))
			if err != nil {
				fmt.Println("binary.Write failed:", err)
				panic(err)
			}
			buf.WriteString(tup.Address.String())

			err = binary.Write(&buf, binary.BigEndian, int32(len(tup.PublicKey)))
			if err != nil {
				fmt.Println("binary.Write failed:", err)
				panic(err)
			}
			buf.Write([]byte(tup.PublicKey))

			_, err = conn.WriteToUDP(buf.Bytes(), clientAddr)
			if err != nil {
				fmt.Println("Error sending data:", err)
				panic(err)
			}

			buf.Reset()
			num++
		}

		mutex.Unlock()

		mutex.Lock()
		clients[clientAddr.String()] = peerInfo{clientAddr, peerKey}
		mutex.Unlock()

	}
}
