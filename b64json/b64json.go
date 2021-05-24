package b64json

import (
	"encoding/base64"
	"encoding/json"
)

func Encode(v interface{}) (*string, error) {
	// Note: []byte values are encoded as base64-encoded strings
	//       (see: https://golang.org/pkg/encoding/json/#Marshal)
	jsonToken, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Struct fields are marshalled in order of declaration, but we can't easily change the order
	// Map fields are always marshalled alphabetically, so bounce through a map to force the order
	var objmap map[string]interface{}
	err = json.Unmarshal(jsonToken, &objmap)
	if err != nil {
		return nil, err
	}
	orderedJson, err := json.Marshal(objmap)
	if err != nil {
		return nil, err
	}

	b64Token := base64.StdEncoding.EncodeToString(orderedJson)
	return &b64Token, nil
}

func Decode(b64 string, v interface{}) error {
	str, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	err = json.Unmarshal(str, v)
	if err != nil {
		return err
	}
	return nil
}
