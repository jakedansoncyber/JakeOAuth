package handlers

import (
	"JakeOAuth/auth"
	"JakeOAuth/clients"
	"JakeOAuth/util"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// TODO: make this not static...in a database or something
var clientsSlice map[string]clients.Client
var hasHeaderWritten = false
var headerWrittenResponse = ""

func init() {
	clientsSlice = clients.ReadClients("clients/clients.json")
}

type AccessTokenResponse struct {
	AccessToken   string `json:"access_token"`
	TokenType     string `json:"token_type"`
	ExpiresIn     int64  `json:"expires_in"`
	RefreshToken  string `json:"refresh_token"`
	TodoParameter string `json:"todo_parameter"`
}

func writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	hasHeaderWritten = true
	headerWrittenResponse = message
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(message))
	if err != nil {
		fmt.Println("Error writing response:", err)
	}
}

func (h *AuthHandler) TokenEndpointHandler(w http.ResponseWriter, req *http.Request) {
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println("TokenEndpointHandler: failed to close body")
		}
	}(req.Body)
	err := req.ParseForm()
	if err != nil {
		log.Println("error: AuthorizationEndpointHandler, failed to parse form:", err)
		writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
		return
	}

	formVals := req.Form
	if !formVals.Has("grant_type") {
		writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The client is not authorized to request an authorization code using this method.")
		return
	}

	grantType := formVals.Get("grant_type")

	switch grantType {
	case "authorization_code":
		handleAuthCodeGrantErr := handleAuthorizationCodeGrant(h, formVals, w)
		if handleAuthCodeGrantErr != nil {
			log.Println("error handling authorization code grant")
			return
		}

	case "client_credentials":
		handleCcErr := handleClientCredentialsGrant(formVals, req, w)
		if handleCcErr != nil {
			log.Println("error handling client credentials grant:", err)
			return
		}
	default:
		writeErrorResponse(w, http.StatusBadRequest, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
		return
	}

	token, createJwtErr := auth.CreateJWT(jwt.SigningMethodRS256, "")
	if createJwtErr != nil {
		log.Println("error: TokenEndpointHandler failed to create jwt:", createJwtErr)
		writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
		return
	}

	resp := &AccessTokenResponse{
		AccessToken:   token.Raw,
		TokenType:     "Bearer",
		ExpiresIn:     time.Now().Add(auth.CodeExpiration).Unix(),
		RefreshToken:  "TODO",
		TodoParameter: "TODO",
	}

	bytes, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		log.Println("error: TokenEndpointHandler failed to marshal access token response:", marshalErr)
		writeErrorResponse(w, http.StatusInternalServerError, "internal_server_error:Failed to marshal access token response.")
		return
	}

	if hasHeaderWritten {
		log.Println("WARNING!!! HEADER HAS ALREADY BEEN WRITTEN!!!!")
		log.Println(hasHeaderWritten)
		log.Println(headerWrittenResponse)
	}
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(bytes)

	if err != nil {
		fmt.Println("TokenEndpointHandler: error writing response:", err)
	}
	return
}

func handleAuthorizationCodeGrant(h *AuthHandler, formVals url.Values, w http.ResponseWriter) error {
	if !formVals.Has("code_verifier") || !formVals.Has("code") {
		writeErrorResponse(w, http.StatusUnauthorized, "code verifier or code does not exist in request")
		return errors.New("code verifier or code does not exist in request")
	}

	if isValid, err := h.CodeStore.CheckTokenWithPkce(formVals.Get("code"), formVals.Get("code_verifier")); !isValid {
		if err != nil {
			log.Println("error while checking token with pkce:", err)
		}
		writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
		return errors.New("code and code verifier do not match")
	}
	return nil
}

func handleClientCredentialsGrant(formVals url.Values, req *http.Request, w http.ResponseWriter) error {
	var clientId, clientSecret string

	if header := req.Header.Get("Authorization"); header != "" {
		var err error
		clientId, clientSecret, err = util.DecodeBasicAuth(header)
		if err != nil {
			writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
			return err
		}
	} else {
		if !formVals.Has("client_secret") {
			writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The client is not authorized to request an authorization code using this method.")
			return fmt.Errorf("client_secret param was not included in request")
		}
		clientId = formVals.Get("client_id")
		clientSecret = formVals.Get("client_secret")
	}

	if app, ok := clientsSlice[clientId]; ok {
		if app.ClientSecret != clientSecret {
			writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The client credentials grant did not have the correct secret.")
			return fmt.Errorf("client credentials grant did not have the correct secret")
		}
	} else {
		writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The client is not authorized to request an authorization code using this method.")
		return fmt.Errorf("client id not matched or something went wrong %s", clientId)
	}

	return nil
}
