package auth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
)

var (
	PathToPrivateKey = "keys/private.pem"
	PathToPublicKey  = "keys/public.pub"
)

type Claims struct {
	foo string
	jwt.RegisteredClaims
}

func CreateJWT(method jwt.SigningMethod, scope ...string) (token *jwt.Token, err error) {
	//TODO create JWT based off of client id
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "http://jakeoauth",
			Subject:   "",
			Audience:  jwt.ClaimStrings{},
			ExpiresAt: nil,
			NotBefore: nil,
			IssuedAt:  nil,
			ID:        "",
		},
	})
	b, err := os.ReadFile(PathToPrivateKey)

	if err != nil {
		fmt.Printf("failed to read private key file error: %s\n", err)
		panic(err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(b)

	if err != nil {
		fmt.Printf("failed to parse private key: %s\n", err)
		panic(err)
	}

	tokenString, err := token.SignedString(key)

	if err != nil {
		fmt.Printf("failed to sign string %s\n", err)
		panic(err)
	}

	token.Raw = tokenString

	fmt.Println("token string: " + tokenString)

	return
}

func ValidateToken(tokenString string) (bool, error) {
	b, err := os.ReadFile(PathToPublicKey)

	if err != nil {
		fmt.Printf("failed to read public key file %s\n", err)
		return false, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(b)

	if err != nil {
		fmt.Printf("failed to parse pub key %s\n", err)
		return false, err
	}

	methods := jwt.WithValidMethods([]string{"RS256"})

	token, err := jwt.NewParser(methods).Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})

	if err != nil {
		fmt.Printf("error while parsing, %s\n", err)
		return false, err
	}

	if token == nil {
		fmt.Printf("token is nil")
		return false, nil
	}

	return true, nil
}
