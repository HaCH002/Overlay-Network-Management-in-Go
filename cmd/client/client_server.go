package client

import (
	"bytes"
	"encoding/binary"
	"fmt"

	//"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	privateKey      wgtypes.Key
	publicKey       wgtypes.Key
	local           *net.UDPAddr
	connMutex       = &sync.Mutex{}
	peerConnections = make(map[string]*net.UDPAddr)
	wgCounter       int32
)

func Client() {
	signalAddress := os.Args[2]

	localAddress := ":8080"
	if len(os.Args) > 3 {
		localAddress = os.Args[3]
	}

	remote := resolveUDPAddr(signalAddress)

	local := resolveUDPAddr(localAddress)

	conn, err := net.DialUDP("udp", local, remote)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	publicKey = privateKey.PublicKey()

	fmt.Printf("Generated WireGuard keys with Public Key: %s\n", publicKey.String())

	_, err = conn.Write([]byte(publicKey.String()))
	if err != nil {
		panic(err)
	}

	go listen(conn)

	select {}

}

func listen(conn *net.UDPConn) {

	buf := make([]byte, 1024)
	for {
		//fmt.Println("[Listening]")
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("[ERROR]", err)
			continue
		}

		data := buf[:n]
		reader := bytes.NewReader(data)

		err = binary.Read(reader, binary.BigEndian, &wgCounter)
		if err != nil {
			fmt.Println("binary.Read failed: ", err)
			panic(err)
		}
		//fmt.Println(wgCounter)

		var addrLen int32
		err = binary.Read(reader, binary.BigEndian, &addrLen)
		if err != nil {
			fmt.Println("binary.Read failed: ", err)
			panic(err)
		}

		addrBytes := make([]byte, addrLen)
		_, err = reader.Read(addrBytes)
		if err != nil {
			fmt.Println("failed to read UDP address: ", err)
			panic(err)
		}
		addr := resolveUDPAddr(string(addrBytes))

		var keyLen int32
		err = binary.Read(reader, binary.BigEndian, &keyLen)
		if err != nil {
			fmt.Println("binary.Read failed: ", err)
			panic(err)
		}

		peerKey := make([]byte, keyLen)
		_, err = reader.Read(peerKey)
		if err != nil {
			fmt.Println("failed to read peer public key: ", err)
			panic(err)
		}

		peerPublicKey, err := wgtypes.ParseKey(string(peerKey))
		if err != nil {
			fmt.Println("failed to convert bytes to wgtypes.Key: ", err)
			panic(err)
		}

		//fmt.Println("[Received Message]")
		fmt.Printf("[INCOMING PubKey from %s]\n", addr.String())

		connMutex.Lock()
		peerConnections[addr.String()] = addr
		connMutex.Unlock()

		go handlePeer(addr, peerPublicKey)
	}
}

func handlePeer(peerUDPAddr *net.UDPAddr, peerPublicKey wgtypes.Key) {
	conn, err := net.DialUDP("udp", local, peerUDPAddr)
	if err != nil {
		fmt.Println("Error connecting to peer: ", err)
		return
	}
	defer conn.Close()
	//fmt.Println("[Connected to peer]")

	//delay := time.Duration(rand.Intn(500)) * time.Millisecond
	//time.Sleep(delay)
	go setupWg(privateKey, peerPublicKey, peerUDPAddr.String())
}

func setupWg(privateKey wgtypes.Key, peerPublicKey wgtypes.Key, peerAddr string) {
	//fmt.Println("Initialising WG tunnel creation")
	client, err := wgctrl.New()
	if err != nil {
		fmt.Printf("Failed to create WireGuard client: %v\n", err)
		panic(err)
	}
	defer client.Close()

	ifaceName := strings.Join([]string{"wg", strconv.FormatInt(int64(wgCounter), 10)}, "")
	fmt.Println(ifaceName)
	peerEndpoint := resolveUDPAddr(peerAddr)

	cfg := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   nil,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   peerPublicKey,
				Endpoint:                    peerEndpoint,
				PersistentKeepaliveInterval: &[]time.Duration{25 * time.Second}[0],
				AllowedIPs:                  []net.IPNet{parseCIDR("0.0.0.0/0")},
			},
		},
	}

	err = client.ConfigureDevice(ifaceName, cfg)
	if err != nil {
		fmt.Printf("Failed to configure WireGuard interface: %v\n", err)
		panic(err)
	}

	fmt.Printf("WireGuard tunnel established with %s\n", peerAddr)
}

func resolveUDPAddr(endpoint string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		panic(err)
	}
	return addr
}

func parseCIDR(cidr string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("Failed to parse CIDR: %v", err)
	}
	return *ipNet
}
