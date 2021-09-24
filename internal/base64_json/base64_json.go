package base64_json

import (
	"encoding/base64"
	"encoding/json"
	"github.com/iancoleman/orderedmap"
)

var (
	keyIndexes = map[string]int{
		"trustchain_id":                   1,
		"target":                          2,
		"value":                           3,
		"delegation_signature":            4,
		"ephemeral_public_signature_key":  5,
		"ephemeral_private_signature_key": 6,
		"user_secret":                     7,
		"public_encryption_key":           8,
		"private_encryption_key":          9,
		"public_signature_key":            10,
		"private_signature_key":           11,
	}
)

func keyOrder(p1, p2 *orderedmap.Pair) bool {
	return keyIndexes[p1.Key()] < keyIndexes[p2.Key()]
}

func Encode(v interface{}) (*string, error) {
	// Note: []byte values are encoded as base64-encoded strings
	//       (see: https://golang.org/pkg/encoding/json/#Marshal)
	buf, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Struct fields are marshalled in order of declaration, but we can't easily change the order
	// OrderedMap fields are always marshalled in order, so we bounce through it
	orderedMap := orderedmap.New()
	err = json.Unmarshal(buf, orderedMap)
	if err != nil {
		return nil, err
	}
	orderedMap.Sort(keyOrder)
	orderedJson, err := json.Marshal(orderedMap)
	if err != nil {
		return nil, err
	}

	b64Encoded := base64.StdEncoding.EncodeToString(orderedJson)
	return &b64Encoded, nil
}

func Decode(b64 string, v interface{}) error {
	buf, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}
