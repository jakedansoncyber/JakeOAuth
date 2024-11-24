package handlers

import (
	"JakeOAuth/clients"
	"JakeOAuth/util"
	"fmt"
	"log"
	"net/http"
)

// TODO: make this not static...in a database or something
var usersSlice map[string]clients.User

func init() {
	usersSlice = clients.ReadUsers("clients/users.json")
}

func HandleInitRedirect(w http.ResponseWriter, req *http.Request) {
	url := fmt.Sprintf("http://localhost:5173?state=%s&client_id=%s&grant_type=authorization_code", "state", "f3bf97cd-91c0-494a-8c91-5ec6b14375d5")
	http.Redirect(w, req, url, http.StatusFound)
	return
}

func HandleLogin(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	err := req.ParseForm()
	if err != nil {
		log.Println("error: AuthorizationEndpointHandler, failed to parse form")
		w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
		log.Println(err)
		return
	}

	formVals := req.Form

	encodedStr := req.Header.Get("Authorization")

	if encodedStr == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("request sent in bad format; use Authorization Header with username:password base64url encoded"))
		log.Println("error: Authorization header missing or empty")
		return
	}

	username, password, err := util.DecodeBase64(encodedStr)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("authorization header unable to be decoded"))
		log.Printf("error: authorization header unable to be decoded %v\n", err)
		return
	}

	// check username and password against database...for now hardcoded af
	var user clients.User
	if u, ok := usersSlice[username]; !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("user " + username + " does not exist"))
		log.Printf("error: username does not exist %s\n", user)
		return
	} else {
		user = u
	}

	if user.Password != password {
		w.WriteHeader(http.StatusForbidden)
		// don't ever log passwords...this is for education purposes only
		w.Write([]byte("password " + password + " is the wrong password"))
		log.Printf("error: username and password combo does not match %s:%s\n", username, password)
		return
	}
	// maybe handle verification (OIDC?) that you accept what the application is going to do on
	// your behalf
	// TODO: Grab from query string parameters to fill out below redirect url
	url := fmt.Sprintf("http://localhost:8080/authorizationendpoint?client_id=%s&response_type=%s&code_challenge=%s&code_challenge_method=%s&state=%s", formVals.Get("client_id"),
		formVals.Get("response_type"), formVals.Get("code_challenge"), formVals.Get("code_challenge_method"), formVals.Get("state"))
	http.Redirect(w, req, url, http.StatusFound)
	return
}
