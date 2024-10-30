package handlers

import (
	"JakeOAuth/auth"
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type AuthEndpointResponse struct {
	AuthCode string `json:"code"`
	PkceCode string `json:"state"`
}

// AuthorizationEndpointHandler used by the client to obtain
// authorization from the resource owner via user-agent redirection.
// Used by authorization code and implicit grant types.
func AuthorizationEndpointHandler(w http.ResponseWriter, req *http.Request) {

	defer req.Body.Close()
	err := req.ParseForm()
	if err != nil {
		log.Println("error: AuthorizationEndpointHandler, failed to parse form")
		log.Println(w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")))
		log.Println(err)
		return
	}

	formVals := req.Form

	if !formVals.Has("username") || !formVals.Has("password") {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("unauthorized_client:The client is not authorized to request an authorization code using this method.")
		log.Println(err)
		return
	}

	// really should use something like saml to authenticate here. but that's another day for another dollar
	err = authenticate(formVals.Get("username"), formVals.Get("password"))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println(w.Write([]byte("unauthorized_client:The client is not authorized to request an authorization code using this method.")))
		log.Print(err)
		return
	}

	// need to implement scopes, and state. probably no redirect uri, that seems weird
	if !formVals.Has("response_type") && !formVals.Has("client_id") {
		w.WriteHeader(http.StatusBadRequest)
		log.Println(w.Write([]byte("invalid_request:The request is missing a required parameter,includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.")))
		log.Println("error: response_type or client_id missing from client request")
		return
	}

	code := auth.NewAuthorizationCode()

	var resp = &AuthEndpointResponse{
		AuthCode: code.Code,
		PkceCode: code.Pkce,
	}

	bytes, err := json.Marshal(resp)

	if err != nil {
		log.Println("error: AuthorizationEndpointHandler, failed to parse form")
		log.Println(w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")))
		return
	}

	switch formVals.Get("response_type") {
	case "code":
		log.Println(w.Write(bytes))
		http.Redirect(w, req, "https://oauth.pstmn.io/v1/callback", http.StatusFound)
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
