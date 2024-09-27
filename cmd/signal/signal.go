package signal

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Nerzal/gocloak/v13"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Peer struct {
	Id         string `gorm:"column:id;primaryKey"`
	Username   string `gorm:"column:username;unique"`
	Ip_address string `gorm:"column:ip_address"`
	Wg_pubkey  string `gorm:"column:wg_pubkey"`
	Created_at string `gorm:"column:created_at"`
	Privilege  int32  `gorm:"column:privilege"`
}

var (
	mutex = &sync.Mutex{}
	num   = int32(0)
	addr  *net.UDPAddr
	conn  *net.UDPConn
	err   error
	mng   string
	db    *gorm.DB

	kcClient    *gocloak.GoCloak
	kcUrl       string
	realm       string
	clientID    string
	kcSecret    string
	admin       string
	admin_psw   string
	admin_token *gocloak.JWT
)

func init() {
	db, err = gorm.Open(sqlite.Open("../management/management.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	kcUrl = os.Getenv("KC_URL")
	realm = os.Getenv("REALM")
	clientID = os.Getenv("CLIENT_ID")
	kcSecret = os.Getenv("KC_SECRET")
	admin = os.Getenv("ADMIN")
	admin_psw = os.Getenv("ADMIN_PSW")

	kcClient = gocloak.NewClient(kcUrl)
	log.Println("[KEYCLOAK CONNECTED]")
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

	ListenPeer(conn)
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

		if !validateToken(userKey) {
			log.Fatalln("User Token not authenticated")
		}

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

func validateToken(userToken string) bool {
	ctx := context.Background()
	admin_token, err = kcClient.LoginAdmin(ctx, admin, admin_psw, realm)
	if err != nil {
		log.Fatalf("Failed to authenticate admin: %v", err)
	}

	result, err := kcClient.RetrospectToken(ctx, userToken, clientID, kcSecret, realm)
	if err != nil {
		log.Fatalf("Failed to introspect token: %v", err)
	}

	if *result.Active {
		fmt.Println("Token is valid")
		return true
	} else {
		fmt.Println("Token is invalid")
		return false
	}

}

func ExchangeInfo(user, peer string) {
	var qUser, qPeer Peer
	if err := db.Where("username = ?", user).First(&qUser).Error; err != nil {
		fmt.Println("User not found:", err)
	} else {
		fmt.Println("User found:", qUser)
	}

	if err := db.Where("username = ?", peer).First(&qPeer).Error; err != nil {
		fmt.Println("User not found:", err)
	} else {
		fmt.Println("User found:", qPeer)
	}

	mutex.Lock()
	var buf bytes.Buffer

	err = binary.Write(&buf, binary.BigEndian, num)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		panic(err)
	}

	err = binary.Write(&buf, binary.BigEndian, int32(len(qUser.Ip_address)))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		panic(err)
	}
	buf.WriteString(qUser.Ip_address)

	err = binary.Write(&buf, binary.BigEndian, int32(len(qUser.Wg_pubkey)))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		panic(err)
	}
	buf.Write([]byte(qUser.Wg_pubkey))

	_, err = conn.WriteToUDP(buf.Bytes(), resolveUDPAddr(qPeer.Ip_address))
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

	err = binary.Write(&buf, binary.BigEndian, int32(len(qPeer.Ip_address)))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		panic(err)
	}
	buf.WriteString(qPeer.Ip_address)

	err = binary.Write(&buf, binary.BigEndian, int32(len(qPeer.Wg_pubkey)))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		panic(err)
	}
	buf.Write([]byte(qPeer.Wg_pubkey))

	_, err = conn.WriteToUDP(buf.Bytes(), resolveUDPAddr(qUser.Ip_address))
	if err != nil {
		fmt.Println("Error sending data:", err)
		panic(err)
	}

	mutex.Unlock()
}

func resolveUDPAddr(endpoint string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		panic(err)
	}
	return addr
}
