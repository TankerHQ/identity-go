package base64_json_test

import (
	"github.com/TankerHQ/identity-go/v3/internal/base64_json"
	"github.com/iancoleman/orderedmap"
	"testing"
)

type benchStruct struct {
	PublicSignatureKey string `json:"public_signature_key"`
	PublicEncryptionKey string `json:"public_encryption_key"`
	PrivateEncryptionKey string `json:"private_encryption_key"`
}

var (
	benchStructValue = benchStruct{
		PublicSignatureKey:   "str",
		PublicEncryptionKey:  "str",
		PrivateEncryptionKey: "str",
	}

	benchMap = map[string]string{
		"public_signature_key": "str",
		"public_encryption_key": "str",
		"private_encryption_key": "str",
	}

	benchOrderedMap = func() *orderedmap.OrderedMap {
		ordered := orderedmap.New()
		for k, v := range benchMap {
			ordered.Set(k, v)
		}
		return ordered
	}()

	benchVecs = []struct{
		desc string
		data interface{}
	}{
		{
			desc: "Struct",
			data: benchStructValue,
		},
		{
			desc: "Map",
			data: benchMap,
		},
		{
			desc: "OrderedMap",
			data: benchOrderedMap,
		},
	}
)

func BenchmarkEncode(b *testing.B) {
	for _, vec := range benchVecs {
		b.Run(vec.desc, func(b *testing.B) {
			for i := 0 ; i < b.N ; i++ {
				base64_json.Encode(vec.data)
			}
		})
	}
}

func BenchmarkDecode(b *testing.B) {
	encoded, _ := base64_json.Encode(benchStructValue)
	into := make(map[string]interface{})
	for i := 0 ; i < b.N ; i++ {
		base64_json.Decode(encoded, &into)
	}
}