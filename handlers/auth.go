package handlers

import (
	"JakeOAuth/auth"
)

type AuthHandler struct {
	CodeStore *auth.AuthorizationCodeStore
}

func NewAuthHandler(acs *auth.AuthorizationCodeStore) *AuthHandler {
	return &AuthHandler{
		CodeStore: acs,
	}
}

// RedirectionEndpointHandler used by the authorization server to return
// responses containing authorization credentials to the client via the
// resource owner user-agent
func RedirectionEndpointHandler() {}
