package util

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func DecodeBase64(encodedStr string) (val1, val2 string, err error) {
	decodedHeaderBytes, decodeErr := base64.StdEncoding.DecodeString(encodedStr)
	if decodeErr != nil {
		return "", "", fmt.Errorf("failed to decode basic auth header: %w", err)
	}
	val1, val2, found := strings.Cut(string(decodedHeaderBytes), ":")
	if !found {
		return "", "", fmt.Errorf("basic token not in correct format clientId:clientSecret")
	}
	return val1, val2, nil
}
