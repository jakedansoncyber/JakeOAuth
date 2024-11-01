package handlers

import (
	"JakeOAuth/auth"
	"JakeOAuth/clients"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	if !formVals.Has("grant_type") {
		w.WriteHeader(http.StatusUnauthorized)
		log.Println("TokenEndpointHandler: grant_type, code, state or client_id missing")
		w.Write([]byte("unauthorized_client:The client is not authorized to request an authorization code using this method."))
		return
	}

	grantType := formVals.Get("grant_type")

	switch grantType {
	case "authorization_code":
		if !formVals.Has("code_verifier") || !formVals.Has("code") {
			fmt.Println("TokenEndpointHandler: code or code_verifier not included in request")
			w.WriteHeader(http.StatusUnauthorized)
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
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
			return
		}
	case "client_credentials":
		var clientId string //:=formVals.Get("client_id")
		var clientSecret string

		if header := req.Header.Get("Authorization"); header != "" {
			// try to decode basic header
			if encoded, found := strings.CutPrefix(header, "Basic "); found {
				decodedHeaderBytes, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
				fmt.Println(string(decodedHeaderBytes))
				if decodeErr != nil {
					fmt.Printf("TokenEndpointHandler: failed to get token from Authorization header")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
					return
				}
				if clientId, clientSecret, found = strings.Cut(string(decodedHeaderBytes), ":"); !found {
					fmt.Printf("TokenEndpointHandler: Basic token not sent in correct format clientId:clientSecret")
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))
					return
				}
			}

		} else {
			if !formVals.Has("client_secret") {
				w.WriteHeader(http.StatusUnauthorized)
				log.Println("TokenEndpointHandler: client_secret param was not included in request")
				w.Write([]byte("unauthorized_client:The client is not authorized to request an authorization code using this method."))
				return
			}
			clientId = formVals.Get("client_id")
			clientSecret = formVals.Get("client_secret")
		}

		if app, ok := clientsSlice[clientId]; ok {

			if app.ClientSecret != clientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				log.Println("unauthorized_client:The client credentials grant did not have the correct secret.")
				return
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("TokenEndpointHandler: client id not matched or something went wrong %s\n", clientId)
			w.Write([]byte("unauthorized_client:The client is not authorized to request an authorization code using this method."))
			return
		}
	default:
		fmt.Printf("TokenEndpointHandler: unsupported grant type %s\n", grantType)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request."))

		return
	}

	token, createJwtErr := auth.CreateJWT()

	if createJwtErr != nil {
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

	bytes, marshalErr := json.Marshal(resp)

	if marshalErr != nil {
		fmt.Println("error: TokenEndpointHandler failed to marshal access token response")
	}

	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
	return
}

//func clientCredentialsGrant(formVal url.Values, w http.ResponseWriter, req *http.Request) {
//	if err := requiredFormVals(formVal, "client_secret"); err != nil {
//		log.Println("error: clientCredentialsGrant failed to provide client_secret")
//		writeWrapper(w.Write([]byte("unauthorized_client:The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")))
//		log.Println(err)
//		return
//	}
//}

func writeWrapper(_ int, err error) {
	if err != nil {
		log.Println("failed to write header correctly!")
	}
}
