package handlers

import (
	"JakeOAuth/auth"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

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

	state := ""
	if formVals.Has("state") {
		state = formVals.Get("state")
	}

	//TODO check if client id is in list of clients
	responseType := formVals.Get("response_type")
	switch formVals.Get(responseType) {
	case "code":
		h.authCodeGrantRequirementsFlow(formVals, w, req, state)
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid_request:The request is missing a required parameter,includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."))
		log.Printf("error: this request type is not supported %s\n", responseType)
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

func (h *AuthHandler) authCodeGrantRequirementsFlow(formVals url.Values, w http.ResponseWriter, req *http.Request, state string) {

	// really should use something like saml to authenticate here. but that's another day for another dollar
	err := authenticateAuthCodeFlow(formVals.Get("username"), formVals.Get("password"))
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

	code := auth.NewAuthorizationCode(formVals.Get("code_challenge"), codeChallengeMethod, state)
	h.CodeStore.Add(code)
	url := fmt.Sprintf("https://oauth.pstmn.io/v1/callback?code=%s&state=%s&client_id=%s&grant_type=authorization_code", code.Code, state, formVals.Get("client_id"))
	http.Redirect(w, req, url, http.StatusFound)
}

func requiredFormVals(formVal url.Values, reqs ...string) error {
	for _, r := range reqs {

		if !formVal.Has(r) {
			return errors.New("requiredFormValue " + r + "not present") // maybe map custom errors to each thingy thang here?
		}
	}
	return nil
}
