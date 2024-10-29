package clients

import (
	"encoding/json"
	"os"
)

type Client struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Description  string `json:"description"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func ReadClients(filename string) map[string]Client {
	b, err := os.ReadFile(filename)
	if err != nil {
		panic("Unable to read clients file, error: " + err.Error())
	}

	clients := make(map[string]Client)
	err = json.Unmarshal(b, &clients)
	if err != nil {
		panic("Failed to unmarshal data, error: " + err.Error())
	}

	return clients
}
