package identity

import (
	"crypto/rand"

	"golang.org/x/crypto/ed25519"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func checkDelegationSignature(identity identity, trustchainPublicKey []byte) {
	signedData := append(
		identity.EphemeralPublicSignatureKey,
		identity.Value...)

	Expect(ed25519.Verify(
		trustchainPublicKey,
		signedData,
		identity.DelegationSignature,
	)).To(Equal(true))
}

var _ = Describe("generateIdentity", func() {
	var (
		trustchainPublicKey  []byte
		trustchainPrivateKey []byte
		trustchainID         []byte
		conf                 config
		userID               = "userID"
		obfuscatedUserID     []byte
		identity             identity
	)

	BeforeEach(func() {
		trustchainPublicKey, trustchainPrivateKey, _ = ed25519.GenerateKey(nil)
		trustchainID = make([]byte, 32)
		rand.Read(trustchainID)
		obfuscatedUserID = hashUserID(trustchainID, userID)
		conf = config{
			TrustchainID:         trustchainID,
			TrustchainPrivateKey: trustchainPrivateKey,
		}
		id, _ := generateIdentity(conf, userID)
		identity = *id
	})

	It("generateIdentity returns a valid tanker identity", func() {
		Expect(identity.TrustchainID).To(Equal(trustchainID))
		Expect(identity.Target).To(Equal("user"))
		Expect(identity.Value).To(Equal(obfuscatedUserID))
		checkDelegationSignature(identity, trustchainPublicKey)
	})
})
