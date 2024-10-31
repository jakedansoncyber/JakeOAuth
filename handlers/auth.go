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
		log.Println("username and password not present")
		w.Write([]byte("unauthorized_client:The client is not authorized to request an authorization code using this method."))
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
	if !formVals.Has("response_type") && !formVals.Has("client_id") && !formVals.Has("code_challenge") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request:The request is missing a required parameter,includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."))
		log.Println("error: response_type or client_id missing from client request")
		return
	}
	codeChallengeMethod := ""
	if formVals.Has("code_challenge_method") {
		switch formVals.Get("code_challenge_method") {
		case "plain":
			codeChallengeMethod = "plain"
		case "S256":
			codeChallengeMethod = "S256"
		}
	}

	state := ""
	if formVals.Has("state") {
		state = formVals.Get("state")
	}

	//TODO check if client id is in list of clients

	code := auth.NewAuthorizationCode(formVals.Get("code_challenge"), codeChallengeMethod, state)

	h.CodeStore.Add(code)

	switch formVals.Get("response_type") {
	case "code":
		url := fmt.Sprintf("https://oauth.pstmn.io/v1/callback?code=%s&state=%s&client_id=%s&grant_type=authorization_code", code.Code, state, formVals.Get("client_id"))
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
	ExpiresIn     int64  `json:"expires_in"`
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
	if !formVals.Has("grant_type") || !formVals.Has("code") {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("TokenEndpointHandler: grant_type, code, state or client_id missing")
		w.Write([]byte("unauthorized_client:The client is not authorized to request an authorization code using this method."))
		return
	}
	m := clients.ReadClients("clients/clients.json")
	if formVals.Get("grant_type") == "client_credentials" {

		if app, ok := m[formVals.Get("client_id")]; ok {
			if !formVals.Has("client_secret") {
				w.WriteHeader(http.StatusUnauthorized)
				log.Println("TokenEndpointHandler: client_secret param was not included in request")
				w.Write([]byte("unauthorized_client:The client is not authorized to request an authorization code using this method."))
				return
			}

			if app.ClientSecret != formVals.Get("client_secret") {
				w.WriteHeader(http.StatusUnauthorized)
				log.Println("unauthorized_client:The client credentials grant did not have the correct secret.")
				return
			}
		}
	}

	if formVals.Get("grant_type") == "authorization_code" {
		if !formVals.Has("code_verifier") {
			fmt.Println("TokenEndpointHandler: code_verifier not included in request")
			w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
			return
		}

		if isValid, err := h.CodeStore.CheckTokenWithPkce(formVals.Get("code"), formVals.Get("code_verifier")); !isValid {
			if err != nil {
				fmt.Println("TokenEndpointHandler: error while checking token with pkce")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
				return
			}
			fmt.Println("Auth code is invalid or Pkce code is invalid")
			w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
			return
		}
	}

	token, err := auth.CreateJWT()

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("error: TokenEndpointHandler failed to create jwt")
		return
	}

	resp := &AccessTokenResponse{
		AccessToken:   token.Raw,
		TokenType:     "Bearer", // TODO make this dynamic
		ExpiresIn:     time.Now().Add(auth.CodeExpiration).Unix(),
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

func authenticateClientCredentialsFlow(clientId string) {
	// TODO
	// authenticate client credentials grant
	// need to pull list from clients.json from clients package
	// need to also see if request has a client id

}

// RedirectionEndpointHandler used by the authorization server to return
// responses containing authorization credentials to the client via the
// resource owner user-agent
func RedirectionEndpointHandler() {}
