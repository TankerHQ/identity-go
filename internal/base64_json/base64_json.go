package base64_json

import (
	"encoding/base64"
	"encoding/json"
	"github.com/iancoleman/orderedmap"
	"sort"
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

func keySort(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		return keyIndexes[keys[i]] < keyIndexes[keys[j]]
	})
}

// Encode returns a pointer to the base64 representation of the result of
// marshalling v in JSON. If an error occurs in the process, it is returned.
// Under the hood, Encode transforms v into a *orderedmap.OrderedMap so
// the result will always wrap a key-sorted JSON representation. If v's
// underlying type is already *orderedmap.OrderedMap, v's wrapped value
// will be used as is.
func Encode(v interface{}) (string, error) {
	// Note: []byte values are encoded as base64-encoded strings
	//       (see: https://golang.org/pkg/encoding/json/#Marshal)
	buf, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	// Struct fields are marshalled in order of declaration, but we can't easily change the order
	// OrderedMap fields are always marshalled in order, so we bounce through it
	orderedMap := orderedmap.New()
	err = json.Unmarshal(buf, orderedMap)
	if err != nil {
		return "", err
	}
	orderedMap.SortKeys(keySort)
	orderedJson, err := json.Marshal(orderedMap)
	if err != nil {
		return "", err
	}

	b64Encoded := base64.StdEncoding.EncodeToString(orderedJson)
	return b64Encoded, nil
}

// Decode takes a value typically returned by Encode, that is,
// a base64-encoded JSON-marshalled value, and applies the reverse operation,
// first base64-decoding b64, then unmarshalling the resulting JSON
// representation into v. If an error occurs on the way, it is returned.
func Decode(b64 string, v interface{}) error {
	buf, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}
