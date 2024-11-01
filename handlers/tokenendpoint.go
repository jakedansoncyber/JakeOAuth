package handlers

import (
	"JakeOAuth/auth"
	"JakeOAuth/clients"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var clientsSlice map[string]clients.Client

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
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}

func (h *AuthHandler) TokenEndpointHandler(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
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
		handleAuthorizationCodeGrant(h, formVals, w)
	case "client_credentials":
		_, handleCcErr := handleClientCredentialsGrant(formVals, req, w)
		if handleCcErr != nil {
			log.Println("error handling client credentials grant:", err)
			return
		}
	default:
		writeErrorResponse(w, http.StatusBadRequest, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
		return
	}

	token, createJwtErr := auth.CreateJWT()
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

	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

func decodeBasicAuth(header string) (string, string, error) {
	if encoded, found := strings.CutPrefix(header, "Basic "); found {
		decodedHeaderBytes, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode basic auth header: %w", err)
		}
		clientId, clientSecret, found := strings.Cut(string(decodedHeaderBytes), ":")
		if !found {
			return "", "", fmt.Errorf("basic token not in correct format clientId:clientSecret")
		}
		return clientId, clientSecret, nil
	}
	return "", "", fmt.Errorf("authorization header not found")
}

func handleAuthorizationCodeGrant(h *AuthHandler, formVals url.Values, w http.ResponseWriter) {
	if !formVals.Has("code_verifier") || !formVals.Has("code") {
		writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
		return
	}

	if isValid, err := h.CodeStore.CheckTokenWithPkce(formVals.Get("code"), formVals.Get("code_verifier")); !isValid {
		if err != nil {
			log.Println("error while checking token with pkce:", err)
		}
		writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
		return
	}
}

func handleClientCredentialsGrant(formVals url.Values, req *http.Request, w http.ResponseWriter) (string, error) {
	var clientId, clientSecret string

	if header := req.Header.Get("Authorization"); header != "" {
		var err error
		clientId, clientSecret, err = decodeBasicAuth(header)
		if err != nil {
			writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
			return "", err
		}
	} else {
		if !formVals.Has("client_secret") {
			writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The client is not authorized to request an authorization code using this method.")
			return "", fmt.Errorf("client_secret param was not included in request")
		}
		clientId = formVals.Get("client_id")
		clientSecret = formVals.Get("client_secret")
	}

	if app, ok := clientsSlice[clientId]; ok {
		if app.ClientSecret != clientSecret {
			writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The client credentials grant did not have the correct secret.")
			return "", fmt.Errorf("client credentials grant did not have the correct secret")
		}
	} else {
		writeErrorResponse(w, http.StatusUnauthorized, "unauthorized_client:The client is not authorized to request an authorization code using this method.")
		return "", fmt.Errorf("client id not matched or something went wrong %s", clientId)
	}

	return clientId, nil
}
