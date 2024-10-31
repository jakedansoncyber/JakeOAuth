package auth

import (
	"container/heap"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"sync"
	"time"
)

var (
	CodeExpiration = 5 * time.Minute
	asciiCharset   = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
)

type AuthorizationCode struct {
	Exp        int64
	Code       string
	Pkce       string
	HashMethod string
	State      string
}

func NewAuthorizationCode(pkceCode, hashMethod, state string) *AuthorizationCode {
	code, err := generateASCII(42)
	if err != nil {
		log.Printf("NewAuthorizationCode: failed to generate code")
	}
	return &AuthorizationCode{
		Exp:        time.Now().Add(CodeExpiration).Unix(),
		Code:       code,
		Pkce:       pkceCode,
		HashMethod: hashMethod,
		State:      state,
	}
}

func generateASCII(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	l := len(asciiCharset)

	// Map bytes to the asciiCharset
	// modulus operation here will give a random character a true
	// value (one of the ascii characters available)
	for i := 0; i < n; i++ {
		bytes[i] = asciiCharset[bytes[i]%byte(l)]
	}

	return string(bytes), nil
}

type TokenHeap []*AuthorizationCode

//goland:noinspection GoMixedReceiverTypes
func (h TokenHeap) Len() int { return len(h) }

//goland:noinspection GoMixedReceiverTypes
func (h TokenHeap) Less(i, j int) bool { return time.Unix(h[i].Exp, 0).Before(time.Unix(h[j].Exp, 0)) }

//goland:noinspection GoMixedReceiverTypes
func (h TokenHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

//goland:noinspection GoMixedReceiverTypes
func (h *TokenHeap) Push(x interface{}) { *h = append(*h, x.(*AuthorizationCode)) }

//goland:noinspection GoMixedReceiverTypes
func (h *TokenHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// AuthorizationCodeStore used to store auth code after authorization endpoint
type AuthorizationCodeStore struct {
	heapMu    *sync.Mutex
	tokenHeap TokenHeap

	tokenMu    *sync.Mutex
	tokenStore map[string]*AuthorizationCode

	ch chan *AuthorizationCode
}

func NewAuthCodeStore() (acs *AuthorizationCodeStore) {
	acs = &AuthorizationCodeStore{
		tokenHeap:  make(TokenHeap, 0),
		heapMu:     &sync.Mutex{},
		tokenMu:    &sync.Mutex{},
		tokenStore: make(map[string]*AuthorizationCode),
		ch:         make(chan *AuthorizationCode),
	}
	heap.Init(&acs.tokenHeap)
	go acs.startExpirationTimer()
	return
}

func (acs *AuthorizationCodeStore) startExpirationTimer() {
	for {
		if acs.tokenHeap.Len() == 0 {
			time.Sleep(time.Second)
			continue
		}

		acs.heapMu.Lock()
		nextExpiration := acs.tokenHeap[0].Exp
		now := time.Now()
		if time.Unix(nextExpiration, 0).After(time.Now()) {
			acs.heapMu.Unlock()
			time.Sleep(time.Unix(nextExpiration, 0).Sub(now))
			continue
		}

		acs.tokenMu.Lock()
		expiredToken := acs.tokenHeap.Pop().(*AuthorizationCode)
		delete(acs.tokenStore, expiredToken.Code)
		acs.ch <- expiredToken
		acs.heapMu.Unlock()
		acs.tokenMu.Unlock()
	}
}

func (acs *AuthorizationCodeStore) ListenExpiration() {
	for expCode := range acs.ch {
		log.Printf("Code %s expired\n", expCode.Code)
	}

}

// Add adds an authorization code to the store with expiration & pkce requirements
func (acs *AuthorizationCodeStore) Add(code *AuthorizationCode) {
	acs.heapMu.Lock()
	acs.tokenMu.Lock()
	acs.tokenHeap.Push(code)
	acs.tokenStore[code.Code] = code
	acs.heapMu.Unlock()
	acs.tokenMu.Unlock()
}

func (acs *AuthorizationCodeStore) CheckTokenWithPkce(authCode, pkceCode string) (bool, error) {
	val, ok := acs.tokenStore[authCode]

	if !ok {
		return false, errors.New("token not found in code store")
	}

	if time.Unix(val.Exp, 0).Before(time.Now()) {
		// should never get here because the token gets removed as soon as it is expired...
		return false, errors.New("token is expired")
	}

	if val.HashMethod != "S256" {
		if val.Pkce != pkceCode && val.Pkce != "" {
			return false, errors.New("pkce code was not the same")
		}
		return true, nil
	}

	hashedPkce := sha256.Sum256([]byte(pkceCode))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hashedPkce[:])

	if codeChallenge != val.Pkce {
		return false, errors.New("pkce code was not the same")
	}

	return true, nil
}
