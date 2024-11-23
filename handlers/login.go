package handlers

import (
	"JakeOAuth/clients"
	"JakeOAuth/util"
	"log"
	"net/http"
)

// TODO: make this not static...in a database or something
var usersSlice map[string]clients.User

func init() {
	usersSlice = clients.ReadUsers("clients/users.json")
}

func HandleLogin(w http.ResponseWriter, req *http.Request) bool {
	encodedStr := req.Header.Get("Authorization")

	if encodedStr == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("request sent in bad format; use Authorization Header with username:password base64url encoded"))
		log.Println("error: Authorization header missing or empty")
	}

	username, password, err := util.DecodeBase64(encodedStr)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("authorization header unable to be decoded"))
		log.Printf("error: authorization header unable to be decoded %v\n", err)
	}

	// check username and password against database...for now hardcoded af
	var user clients.User
	if u, ok := usersSlice[username]; !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("user " + username + " does not exist"))
		log.Printf("error: username does not exist %s\n", user)
	} else {
		user = u
	}

	if user.Password != password {
		w.WriteHeader(http.StatusForbidden)
		// don't ever log passwords...this is for education purposes only
		w.Write([]byte("password " + password + " is the wrong password"))
		log.Printf("error: username and password combo does not match %s:%s\n", user, password)
	}
	// maybe handle verification (OIDC?) that you accept what the application is going to do on
	// your behalf
	return true
}
