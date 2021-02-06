package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Check if a value is in a string slice
func inSlice(v string, s []string) bool {
	for _, scope := range s {
		if scope == v {
			return true
		}
	}

	return false
}

// Decode a json or return an error
func jsonDecode(js []byte) (map[string]interface{}, error) {
	var decoded map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(js)))
	decoder.UseNumber()

	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}

	return decoded, nil
}

// Generate a random token
func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
