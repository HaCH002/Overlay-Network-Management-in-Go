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
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

type SignUp struct {
	Username string `json:"username"`
	Psw      string `json:"psw"`
	Ip       string `json:"ip_address"`
	WgPubKey string `json:"wg_pubkey"`
	Priv     int32  `json:"privileges"`
}

type login struct {
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
	// Parse the incoming JSON request
	var req SignUp
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Initialize Keycloak client
	token, err := kcClient.LoginAdmin(r.Context(), admin, admin_psw, realm)
	if err != nil {
		http.Error(w, "Keycloak authentication failed", http.StatusInternalServerError)
		return
	}

	// Register the user with Keycloak
	userID, err := RegisterKeycloakUser(r, kcClient, token.AccessToken, req.Username, req.Psw)
	if err != nil {
		http.Error(w, "Failed to register user with Keycloak", http.StatusInternalServerError)
		return
	}

	// Store user data in SQLite database
	newPeer := Peer{
		Id:         userID,
		Username:   req.Username,
		Ip_address: req.Ip,
		Wg_pubkey:  req.WgPubKey,
		Created_at: time.Now().String(),
		Privilege:  req.Priv,
	}

	createPeer(&newPeer)

	// Respond with success
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

	// Create the user in Keycloak
	userID, err := client.CreateUser(r.Context(), accessToken, realm, user)
	if err != nil {
		return "", err
	}

	return userID, nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq login

	// Decode the JSON body
	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Authenticate with Keycloak
	token, err := kcClient.Login(r.Context(), clientID, kcSecret, realm, loginReq.Username, loginReq.Psw)
	if err != nil {
		log.Printf("Failed to login: %v", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Send the token to the agent
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

func management() {
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/signup", LoginHandler)
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
