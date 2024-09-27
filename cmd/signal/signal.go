package signal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type peerInfo struct {
	Address   *net.UDPAddr
	PublicKey string
}

var (
	clients = make(map[string]peerInfo)
	mutex   = &sync.Mutex{}
	num     = int32(0)
	addr    *net.UDPAddr
	conn    *net.UDPConn
	err     error
	mng     string
	db      *gorm.DB
)

func init() {
	db, err = gorm.Open(sqlite.Open("../management/management.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
}

func Signal() {
	localAddress := "192.168.100.11:8080"

	if len(os.Args) > 2 {
		localAddress = os.Args[2]
	}

	addr, err = net.ResolveUDPAddr("udp", localAddress)
	if err != nil {
		panic(err)
	}

	conn, err = net.ListenUDP("udp", addr)
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

func ListenPeer(conn *net.UDPConn) {
	buffer := make([]byte, 64)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			continue
		}

		data := buffer[:n]
		reader := bytes.NewReader(data)

		var userLen int32
		err = binary.Read(reader, binary.BigEndian, &userLen)
		if err != nil {
			fmt.Println("binary.Read failed: ", err)
			panic(err)
		}

		userBytes := make([]byte, userLen)
		_, err = reader.Read(userBytes)
		if err != nil {
			fmt.Println("failed to read initiator's username: ", err)
			panic(err)
		}
		userUsername := string(userBytes)

		var keyLen int32
		err = binary.Read(reader, binary.BigEndian, &keyLen)
		if err != nil {
			fmt.Println("binary.Read failed: ", err)
			panic(err)
		}

		keyBytes := make([]byte, keyLen)
		_, err = reader.Read(keyBytes)
		if err != nil {
			fmt.Println("failed to read initiator's Keycloak key: ", err)
			panic(err)
		}
		userKey := string(keyBytes)

		var peerLen int32
		err = binary.Read(reader, binary.BigEndian, &peerLen)
		if err != nil {
			fmt.Println("binary.Read failed: ", err)
			panic(err)
		}

		peerBytes := make([]byte, peerLen)
		_, err = reader.Read(peerBytes)
		if err != nil {
			fmt.Println("failed to read peer's username: ", err)
			panic(err)
		}
		peerUsername := string(peerBytes)

		fmt.Printf("[INCOMING CONNECTION REQUEST from %s to %s]\n", userUsername, peerUsername)
		go ExchangeInfo(userUsername, peerUsername)
	}
}

func ExchangeInfo(user, peer string) {

}
