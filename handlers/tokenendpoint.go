package handlers

import (
	"JakeOAuth/auth"
	"JakeOAuth/clients"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

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
