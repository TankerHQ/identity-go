package identity

import (
	"encoding/hex"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"golang.org/x/crypto/blake2b"
)

var _ = Describe("Hash", func() {
	It("should match the RFC7693 BLAKE2b-512 test vector for \"abc\"", func() {
		// To check that the hash function is implemented correctly, we compute a test vector,
		// which is a known expected output for a given input, defined in the standard
		hexVector := "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923"
		vector, _ := hex.DecodeString(hexVector)
		input := []byte("abc")

		hash, err := blake2b.New512([]byte{})
		if err != nil {
			panic("hash failed: " + err.Error())
		}
		_, _ = hash.Write(input)
		output := hash.Sum([]byte{})
		Expect(output).To(Equal(vector))
	})
})
