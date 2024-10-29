package handlers

import (
	"errors"
	"log"
	"net/http"
)

// AuthorizationEndpointHandler used by the client to obtain
// authorization from the resource owner via user-agent redirection.
// Used by authorization code and implicit grant types.
func AuthorizationEndpointHandler(w http.ResponseWriter, req *http.Request) {

	defer req.Body.Close()
	err := req.ParseForm()
	if err != nil {
		log.Fatal("failed to parse form")
	}

	formVals := req.Form

	if !formVals.Has("username") || !formVals.Has("password") {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("please login using url encoded form username and password")
		return
	}

	// really should use something like saml to authenticate here. but that's another day for another dollar
	err = authenticate(formVals.Get("username"), formVals.Get("password"))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Print(err.Error())
		return
	}

	// need to implement scopes, and state. probably no redirect uri, that seems weird
	if !formVals.Has("response_type") && !formVals.Has("client_id") {
		w.WriteHeader(http.StatusBadRequest)
		log.Print(w.Write([]byte("invalid_request=The request is missing a required parameter,includes an\ninvalid parameter value, includes a parameter more than\nonce, or is otherwise malformed.")))
		return
	}

	switch formVals.Get("response_type") {
	case "code":
		http.Redirect(w, req, "https://oauth.pstmn.io/v1/callback", http.StatusTemporaryRedirect)
		// do something for authorization code grant
	case "token":
		// do something for implicit grant type

	default:

	}

	return
}

func authenticate(username, password string) error {
	log.Printf("username: %s, password: %s", username, password)
	if username != "jake" && password != "josh" {
		return errors.New("failed to authenticate")
	}
	return nil
}

// TokenEndpointHandler used by the client to exchange an authorization
// grant for an access token, typically with client authentication
func TokenEndpointHandler() {}

// RedirectionEndpointHandler used by the authorization server to return
// responses containing authorization credentials to the client via the
// resource owner user-agent
func RedirectionEndpointHandler() {}
