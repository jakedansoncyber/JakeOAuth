package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	PathToPrivateKey = "/keys/private.pem"
	PathToPublicKey = "/keys/public.pub"
}

var rsaTestData = []struct {
	name        string
	tokenString string
	alg         string
	valid       bool
}{
	{
		"Basic RS256",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.GCxi9tythh3-UiopPr6Hv422OK6MVX5mXbt2bM2AyokOwxbvjTo4SzgSQ1E0D1DGiez2AtbHpzAmh8G-8Sv1Ln4iuhVRx6hfuzp7TYS8-nJNvCt2gj6siZpq_XcvVvg2WbJ4PrRbvCPK083_EU2uA-S4a5wwJGHtfUSPZR_roknMr2z_QW7lalRAQGwsYG5o9r4iV_vzoucl53j8YDQ-GtwaJXh-dbD3fKQvtlgS2IL0jovWlPNkqX2SBHlKRAtNLPx6qPwdGdmSB7FMF645cOS7nd_RT85ERd9FQVXZ--eK7W8TZMbAIKVqNq3Rrpb9SYlJoq3xaY1D6Tn0LZBSIw",
		"RS256",
		true,
	},
	{
		"Trash Bin",
		"ey.ey.yuayayuayayayaayayuay",
		"NAH SON",
		false,
	},
	{
		"Trash Bin",
		"yuayayuayayayaayayuay",
		"NAH SON",
		false,
	},
	{
		"HS256 Not Valid",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"HS256",
		false,
	},
	{
		"RS256 invalid signature",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ",
		"RS256",
		false,
	},
}

func TestCreateJWT(t *testing.T) {

	token, err := CreateJWT()

	assert.Nilf(t, err, "failed to create JWT: %s", err)
	assert.NotNil(t, token)
	assert.Equal(t, "RS256", token.Method.Alg())

}

func TestValidateToken(t *testing.T) {
	for _, datum := range rsaTestData {
		valid, err := ValidateToken(datum.tokenString)

		assert.Equal(t, datum.valid, valid)
		if datum.valid == false {
			assert.Error(t, err)
		} else {
			assert.Nil(t, err)
		}

	}
}

//func TestRSAVerify(t *testing.T) {
//	keyData, _ := os.ReadFile("../keys/public.pub")
//	key, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)
//
//	for _, data := range rsaTestData {
//		parts := strings.Split(data.tokenString, ".")
//
//		fmt.Println(strings.Join(parts[0:2], "."))
//		fmt.Println(parts[2])
//
//		method := jwt.GetSigningMethod(data.alg)
//		err := method.Verify(strings.Join(parts[0:2], "."), decodeSegment(t, parts[2]), key)
//		if data.valid && err != nil {
//			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
//		}
//		if !data.valid && err == nil {
//			t.Errorf("[%v] Invalid key passed validation", data.name)
//		}
//	}
//}
//
//func decodeSegment(t interface{ Fatalf(string, ...any) }, signature string) (sig []byte) {
//	var err error
//	sig, err = jwt.NewParser().DecodeSegment(signature)
//	if err != nil {
//		t.Fatalf("could not decode segment: %v", err)
//	}
//
//	return
//}
