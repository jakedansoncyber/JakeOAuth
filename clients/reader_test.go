package clients

import (
	"fmt"
	"github.com/google/uuid"
	"testing"
)

func TestReadClients(t *testing.T) {
	c := ReadClients("clients_test.json")
	expectedName := "test_cc_grant"
	expectedType := "client_credentials"
	expectedDescription := "The first test client :)"

	if c["test_cc_grant"].Name != expectedName {
		t.Errorf("Expected %v, Got %v", expectedName, c["test_cc_grant"].Name)
	}
	if c["test_cc_grant"].Type != expectedType {
		t.Errorf("Expected %v, Got %v", expectedType, c["test_cc_grant"].Type)
	}
	if c["test_cc_grant"].Description != expectedDescription {
		t.Errorf("Expected %v, Got %v", expectedDescription, c["test_cc_grant"].Description)
	}
	fmt.Println(uuid.New())
}
