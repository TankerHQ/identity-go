package identity

import (
	"encoding/base64"
	"encoding/json"
	"github.com/iancoleman/orderedmap"
)

func jsonSort(a *orderedmap.Pair, b *orderedmap.Pair) bool {
	jsonOrder := map[string]int{
		"trustchain_id": 1,
		"target": 2,
		"value": 3,
		"delegation_signature": 4,
		"ephemeral_public_signature_key": 5,
		"ephemeral_private_signature_key": 6,
		"user_secret": 7,
		"public_encryption_key": 8,
		"private_encryption_key": 9,
		"public_signature_key": 10,
		"private_signature_key": 11,
	}
	return jsonOrder[a.Key()] < jsonOrder[b.Key()]
}

// Base64JsonEncode returns a base64-encoded, JSON marshalled representation
// of v, along with any error encountered in the process.
func Base64JsonEncode(v interface{}) (string, error) {
	// Note: []byte values are encoded as base64-encoded strings
	//       (see: https://golang.org/pkg/encoding/json/#Marshal)
	jsonToken, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	// Struct fields are marshalled in order of declaration, but we can't easily change the order
	// OrderedMap fields are always marshalled in order, so we bounce through it
	o := orderedmap.New()
	err = o.UnmarshalJSON(jsonToken)
	if err != nil {
		return "", err
	}
	o.Sort(jsonSort)
	orderedJson, err := json.Marshal(o)
	if err != nil {
		return "", err
	}

	b64Token := base64.StdEncoding.EncodeToString(orderedJson)
	return b64Token, nil
}

// Base64JsonDecode fills the underlying value of v with the JSON unmarshalled,
// base64-decoded value represented by b64, along with any error encountered in
// the process.
func Base64JsonDecode(b64 string, v interface{}) error {
	str, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	return json.Unmarshal(str, v)
}
