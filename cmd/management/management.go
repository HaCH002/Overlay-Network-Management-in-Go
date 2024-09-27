package management

import (
	"github.com/joho/godotenv"

	//"bytes"
	//"encoding/binary"
	"fmt"
	//"net"
	//"os"
	//"strings"
	//"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

type authReq struct {
	Username string `json:"username"`
	Psw      string `json:"psw"`
}

type response struct {
	AccessToken string `json:"access_token"`
	ExpireIn    int    `json:"expiry"`
	Error       string `json:"error,omitempty"`
}

var (
	clients   []string
	mutex     = &sync.Mutex{}
	kcClient  *gocloak.GoCloak
	kcUrl     string
	realm     string
	clientID  string
	kcSecret  string
	admin     string
	admin_psw string
	signal    string
)

func init() {
	openDb("test.db")
	migrateSchema(Peer{})
	fmt.Println("[DATABASE CONNECTED]")
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
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

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var req authReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	token, err := kcClient.LoginAdmin(r.Context(), admin, admin_psw, realm)
	if err != nil {
		http.Error(w, "Keycloak authentication failed", http.StatusInternalServerError)
		return
	}

	userID, err := RegisterKeycloakUser(r, kcClient, token.AccessToken, req.Username, req.Psw)
	if err != nil {
		http.Error(w, "Failed to register user with Keycloak", http.StatusInternalServerError)
		return
	}

	newPeer := Peer{
		Id:         userID,
		Username:   req.Username,
		Created_at: time.Now().String(),
		Privilege:  0,
	}

	createPeer(&newPeer)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User %s successfully registered", req.Username)

	mutex.Lock()
	clients = append(clients, req.Username)
	mutex.Unlock()

}

func RegisterKeycloakUser(r *http.Request, client *gocloak.GoCloak, accessToken, username, password string) (string, error) {
	user := gocloak.User{
		Username: gocloak.StringP(username),
		Enabled:  gocloak.BoolP(true),
		Credentials: &[]gocloak.CredentialRepresentation{
			{
				Type:      gocloak.StringP("password"),
				Value:     gocloak.StringP(password),
				Temporary: gocloak.BoolP(false),
			},
		},
	}

	userID, err := client.CreateUser(r.Context(), accessToken, realm, user)
	if err != nil {
		return "", err
	}

	return userID, nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq authReq

	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	token, err := kcClient.Login(r.Context(), clientID, kcSecret, realm, loginReq.Username, loginReq.Psw)
	if err != nil {
		log.Printf("Failed to login: %v", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	response := response{
		AccessToken: token.AccessToken,
		ExpireIn:    token.ExpiresIn,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	mutex.Lock()
	clients = append(clients, loginReq.Username)
	mutex.Unlock()
}

func PeersOnlineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(clients)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func SetSignal(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	var data struct {
		IP string `json:"ip"`
	}

	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	signal = data.IP
	fmt.Printf("Received STUN server IP: %s\n", signal)
	w.WriteHeader(http.StatusOK)
}

func GetSignal(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	if signal == "" {
		http.Error(w, "STUN server IP not available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ip": signal})
}

func Management() {
	ip, err := getLocalIP()
	if err != nil {
		log.Fatalf("Could not get local IP address: %v", err)
	}
	fmt.Printf("Server will start on %s:8080\n", ip)
	address := fmt.Sprintf("%s:8080", ip)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/signup", SignUpHandler)
	http.HandleFunc("/peers", PeersOnlineHandler)
	http.HandleFunc("/set-signal", SetSignal)
	http.HandleFunc("/get-signal", GetSignal)

	log.Fatal(http.ListenAndServe(address, nil))
}
