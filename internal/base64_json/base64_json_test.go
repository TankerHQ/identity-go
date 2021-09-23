package base64_json_test

import (
	"errors"
	"fmt"
	"github.com/TankerHQ/identity-go/v3/internal/base64_json"
	"github.com/iancoleman/orderedmap"
	"testing"
)

// should sort last
type embedded struct {
	PrivateSignatureKey string `json:"private_signature_key"`
}

// first field should sort first
// second should sort last
type embedded2 struct {
	TrustchainId        string `json:"trustchain_id"`
	PrivateSignatureKey string `json:"private_signature_key"`
}

// should sort reversed
type embedded3 struct {
	DelegationSignature string `json:"delegation_signature"`
	Value               string `json:"value"`
	Target              string `json:"target"`
}

var (
	order = map[string]int{
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

	testVectors = []struct {
		desc string
		data interface{}
	}{
		{
			desc: "SimpleMap",
			data: map[string]string{
				"public_encryption_key": "",
				"public_signature_key":  "",
			},
		},

		{
			desc: "PlainStruct",
			data: struct {
				PublicSignatureKey string `json:"public_signature_key"`
				UserSecret         string `json:"user_secret"`
				DelegationSignture string `json:"delegation_signture"`
			}{
				PublicSignatureKey: "",
				UserSecret:         "",
				DelegationSignture: "",
			},
		},

		{
			desc: "StructWithOneFieldEmbeddedStruct",
			data: struct {
				embedded
				PublicSignatureKey string `json:"public_signature_key"`
			}{
				embedded:           embedded{PrivateSignatureKey: ""},
				PublicSignatureKey: "",
			},
		},

		{
			desc: "StructWithTwoNonConsecutiveEmbeddedFields",
			data: struct {
				embedded2
				Value string `json:"value"`
			}{
				embedded2: embedded2{
					TrustchainId:        "",
					PrivateSignatureKey: "",
				},
				Value: "",
			},
		},

		{
			desc: "StructWithThreeReverseSortedFields",
			data: struct {
				embedded3
				TrustchainId string
				UserSecret   string
			}{
				embedded3: embedded3{
					DelegationSignature: "",
					Value:               "",
					Target:              "",
				},
				TrustchainId: "",
				UserSecret:   "",
			},
		},
	}
)

func TestEncodeDecode(t *testing.T) {
	for _, vec := range testVectors {
		t.Run(vec.desc, func(t *testing.T) {
			buf, err := base64_json.Encode(vec.data)
			if err != nil {
				t.Fatal(vec.desc, "encode failed")
			}

			ordered := orderedmap.New()
			err = base64_json.Decode(*buf, &ordered)
			if err != nil {
				t.Fatal(vec.desc, "decode failed")
			}

			var previousKey string
			for i, key := range ordered.Keys() {
				if i != 0 && order[key] < order[previousKey] {
					t.Fatal(fmt.Sprintf("%s should sort before %s", previousKey, key))
				}
				previousKey = key
			}
		})
	}
}

type errorMarshaller struct{}

func (errorMarshaller) MarshalJSON() ([]byte, error) {
	return nil, errors.New("something wrong")
}

type errorMarshallerToUnmarshal struct{}

func (errorMarshallerToUnmarshal) MarshalJSON() ([]byte, error) {
	// must be a valid json output
	return []byte("\"not good for unmarshal\""), nil
}

func TestEncode_Error(t *testing.T) {
	var (
		errorMa     errorMarshaller
		errorMaToUn errorMarshallerToUnmarshal
	)

	t.Run("Marshal", func(t *testing.T) {
		_, err := base64_json.Encode(errorMa)
		if err == nil {
			t.Fatal("no error on marshal error")
		}
	})

	t.Run("Unmarshal", func(t *testing.T) {
		_, err := base64_json.Encode(errorMaToUn)
		if err == nil {
			t.Fatal("no error on unmarshal error")
		}
	})
}

func TestDecode_Error(t *testing.T) {
	notBase64 := "that's a plain string"
	var i interface{}
	err := base64_json.Decode(notBase64, &i)
	if err == nil {
		t.Fatal("no error on decode with plain string")
	}
}
