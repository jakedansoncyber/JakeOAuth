package auth

import (
	"crypto/sha256"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewAuthorizationCode(t *testing.T) {
	code, _ := generateASCII(45)
	ac := NewAuthorizationCode(code, "plain", "")
	fmt.Println(ac)
	assert.NotNil(t, ac.Code)
	assert.NotNil(t, ac.Pkce)
	assert.Greater(t, ac.Exp, time.Now().Add(CodeExpiration-(1*time.Minute)))
}

func TestNewAuthCodeStore(t *testing.T) {
	code, _ := generateASCII(45)
	CodeExpiration = 1 * time.Second // this is a global var set in memory.go
	acs := NewAuthCodeStore()
	go acs.ListenExpiration()
	for i := 0; i <= 200; i++ {
		ac := NewAuthorizationCode(code, "S256", "")
		acs.Add(ac)
	}

	time.Sleep(3 * time.Second)
	assert.Equal(t, 0, len(acs.tokenStore))
	assert.Equal(t, 0, acs.tokenHeap.Len())
}

func TestAuthorizationCodeStore_CheckTokenWithPkce_Valid(t *testing.T) {
	code, _ := generateASCII(45)
	shaBytes := sha256.Sum256([]byte(code))

	CodeExpiration = 5 * time.Minute
	acs := NewAuthCodeStore()
	go acs.ListenExpiration()

	ac := NewAuthorizationCode(string(shaBytes[:]), "S256", "")
	acs.Add(ac)

	isValid, err := acs.CheckTokenWithPkce(ac.Code, ac.Pkce)

	assert.Nil(t, err)
	assert.True(t, isValid)
}

func TestAuthorizationCodeStore_CheckTokenWithPkce_Expired(t *testing.T) {
	CodeExpiration = 1 * time.Microsecond // this is a global var set in memory.go
	code, _ := generateASCII(45)
	shaBytes := sha256.Sum256([]byte(code))
	acs := NewAuthCodeStore()
	go acs.ListenExpiration()

	ac := NewAuthorizationCode(string(shaBytes[:]), "S256", "")
	acs.Add(ac)
	time.Sleep(20 * time.Microsecond)
	isValid, err := acs.CheckTokenWithPkce(ac.Code, ac.Pkce)

	assert.Error(t, err)
	assert.False(t, isValid)
}

func TestAuthorizationCodeStore_CheckTokenWithPkce_NotInCodeStore(t *testing.T) {
	CodeExpiration = 5 * time.Minute
	code, _ := generateASCII(45)
	shaBytes := sha256.Sum256([]byte(code))
	acs := NewAuthCodeStore()
	go acs.ListenExpiration()

	ac := NewAuthorizationCode(string(shaBytes[:]), "S256", "")
	time.Sleep(20 * time.Microsecond)
	isValid, err := acs.CheckTokenWithPkce(ac.Code, ac.Pkce)

	if assert.Error(t, err) {
		assert.Equal(t, "token not found in code store", err.Error())
	}
	assert.False(t, isValid)
}

func TestAuthorizationCodeStore_CheckTokenWithPkce_InvalidPkce(t *testing.T) {
	CodeExpiration = 5 * time.Minute
	code, _ := generateASCII(45)
	shaBytes := sha256.Sum256([]byte(code))
	acs := NewAuthCodeStore()
	go acs.ListenExpiration()

	ac := NewAuthorizationCode(string(shaBytes[:]), "S256", "")
	acs.Add(ac)

	code2, _ := generateASCII(45)
	shaBytes2 := sha256.Sum256([]byte(code2))
	acBadCode := NewAuthorizationCode(string(shaBytes2[:]), "S256", "")
	acBadCode.Code = ac.Code
	isValid, err := acs.CheckTokenWithPkce(acBadCode.Code, acBadCode.Pkce)

	if assert.Error(t, err) {
		assert.Equal(t, "pkce code was not the same", err.Error())
	}
	assert.False(t, isValid)
}
