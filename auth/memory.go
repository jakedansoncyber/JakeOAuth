package auth

import (
	"container/heap"
	"crypto/rand"
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
	Code string
	Exp  time.Time
	Pkce string
}

func NewAuthorizationCode() *AuthorizationCode {
	//codeBytes := generateASCII(32) // need to make these ASCII characters only
	//pBytes := make([]byte, 20)    // need to make these ASCII characters only
	codeBytes, codeErr := generateASCII(32)
	pBytes, pErr := generateASCII(20)
	if codeErr != nil {
		log.Fatalf("failed to create authorization code %s\n", codeErr)
	}
	if pErr != nil {
		log.Fatalf("failed to create pkce code %s\n", pErr)
	}
	return &AuthorizationCode{
		Code: codeBytes,
		Exp:  time.Now().Add(CodeExpiration),
		Pkce: pBytes,
	}
}

// generateASCII generates a random ASCII string of the specified length.
func generateASCII(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Map bytes to the asciiCharset
	for i := 0; i < n; i++ {
		bytes[i] = asciiCharset[bytes[i]%byte(len(asciiCharset))]
	}

	return string(bytes), nil
}

type TokenHeap []*AuthorizationCode

//goland:noinspection GoMixedReceiverTypes
func (h TokenHeap) Len() int { return len(h) }

//goland:noinspection GoMixedReceiverTypes
func (h TokenHeap) Less(i, j int) bool { return h[i].Exp.Before(h[j].Exp) }

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
		if nextExpiration.After(time.Now()) {
			acs.heapMu.Unlock()
			time.Sleep(nextExpiration.Sub(now))
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

func (acs *AuthorizationCodeStore) CheckTokenWithPkce(code *AuthorizationCode) (bool, error) {
	val, ok := acs.tokenStore[code.Code]

	if !ok {
		return false, errors.New("token not found in code store")
	}

	if val.Exp.Before(time.Now()) {
		// should never get here because the token gets removed as soon as it is expired...
		return false, errors.New("token is expired")
	}

	if val.Pkce != code.Pkce {
		return false, errors.New("pkce code was not the same")
	}

	return true, nil
}
