package handlers

import (
	"JakeOAuth/auth"
	"JakeOAuth/clients"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

type AuthEndpointResponse struct {
	AuthCode string `json:"code"`
	PkceCode string `json:"state"`
}

type AuthHandler struct {
	CodeStore *auth.AuthorizationCodeStore
}

func NewAuthHandler(acs *auth.AuthorizationCodeStore) *AuthHandler {
	return &AuthHandler{
		CodeStore: acs,
	}
}

// AuthorizationEndpointHandler used by the client to obtain
// authorization from the resource owner via user-agent redirection.
// Used by authorization code and implicit grant types.
func (h *AuthHandler) AuthorizationEndpointHandler(w http.ResponseWriter, req *http.Request) {

	defer req.Body.Close()
	err := req.ParseForm()
	if err != nil {
		log.Println("error: AuthorizationEndpointHandler, failed to parse form")
		w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
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
	err = authenticateAuthCodeFlow(formVals.Get("username"), formVals.Get("password"))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized_client:The client is not authorized to request an authorization code using this method."))
		log.Print(err)
		return
	}

	// need to implement scopes, and state. probably no redirect uri, that seems weird
	if !formVals.Has("response_type") && !formVals.Has("client_id") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request:The request is missing a required parameter,includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."))
		log.Println("error: response_type or client_id missing from client request")
		return
	}

	//TODO check if client id is in list of clients

	code := auth.NewAuthorizationCode()

	var resp = &AuthEndpointResponse{
		AuthCode: code.Code,
		PkceCode: code.Pkce,
	}

	//_, err = json.Marshal(resp)
	//
	//if err != nil {
	//	log.Println("error: AuthorizationEndpointHandler, failed to parse form")
	//	w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
	//	return
	//}

	h.CodeStore.Add(code)

	switch formVals.Get("response_type") {
	case "code":
		url := fmt.Sprintf("https://oauth.pstmn.io/v1/callback?code=%s,state=%s", resp.AuthCode, resp.PkceCode)
		http.Redirect(w, req, url, http.StatusFound)
		// do something for authorization code grant
	case "token":
		// do something for implicit grant type

	default:

	}

	return
}

func authenticateAuthCodeFlow(username, password string) error {
	log.Printf("username: %s, password: %s", username, password)
	if username != "jake" && password != "josh" {
		return errors.New("failed to authenticate")
	}
	return nil
}

type AccessTokenResponse struct {
	AccessToken   string `json:"access_token"`
	TokenType     string `json:"token_type"`
	ExpiresIn     string `json:"expires_in"`
	RefreshToken  string `json:"refresh_token"`
	TodoParameter string `json:"todo_parameter"`
}

// TokenEndpointHandler used by the client to exchange an authorization
// grant for an access token, typically with client authentication
func (h *AuthHandler) TokenEndpointHandler(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	err := req.ParseForm()
	if err != nil {
		log.Println("error: AuthorizationEndpointHandler, failed to parse form")
		w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
		log.Println(err)
		return
	}

	formVals := req.Form

	if !formVals.Has("grant_type") || !formVals.Has("code") || !formVals.Has("client_id") || !formVals.Has("state") {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("unauthorized_client:The client is not authorized to request an authorization code using this method.")
		log.Println(err)
		return
	}

	//TODO if token is client credentials grant, authenticate against from a list of clients
	authenticateClientCredentialsFlow()

	if isValid, err := h.CodeStore.CheckTokenWithPkce(formVals.Get("code"), formVals.Get("state")); !isValid {
		if err != nil {
			fmt.Println("Error checking token with pkce")
		}
		fmt.Println("Auth code is invalid or Pkce code is invalid")
		w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
		return
	}

	m := clients.ReadClients("clients.json")
	if _, ok := m[formVals.Get("client_id")]; ok {
		token, err := auth.CreateJWT()

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Println("error: TokenEndpointHandler failed to create jwt")
			return
		}

		resp := &AccessTokenResponse{
			AccessToken:   token.Raw,
			TokenType:     "code", // TODO make this dynamic
			ExpiresIn:     time.Now().Add(auth.CodeExpiration).String(),
			RefreshToken:  "TODO",
			TodoParameter: "TODO",
		}

		bytes, err := json.Marshal(resp)

		if err != nil {
			fmt.Println("error: TokenEndpointHandler failed to marshal access token response")
		}

		w.Write(bytes)
		w.WriteHeader(http.StatusOK)
		return
	}

}

func authenticateClientCredentialsFlow() {
	// TODO
	// authenticate client credentials grant
	// need to pull list from clients.json from clients package
}

// RedirectionEndpointHandler used by the authorization server to return
// responses containing authorization credentials to the client via the
// resource owner user-agent
func RedirectionEndpointHandler() {}
