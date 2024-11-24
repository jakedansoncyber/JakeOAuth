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

func DecodeBasicAuth(header string) (val1, val2 string, err error) {
	if encoded, found := strings.CutPrefix(header, "Basic "); found {
		decodedHeaderBytes, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil {
			return "", "", fmt.Errorf("failed to decode basic auth header: %w", err)
		}
		val1, val2, found = strings.Cut(string(decodedHeaderBytes), ":")
		if !found {
			return "", "", fmt.Errorf("basic token not in correct format clientId:clientSecret")
		}
		return val1, val2, nil
	}
	return "", "", fmt.Errorf("authorization header not found")
}
